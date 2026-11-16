// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"blackwall/internal/config"
)

var licenceReminderThresholds = [...]int{30, 14, 7, 2, 1}

const (
	licenceReminderBatchSize  = 32
	licenceReminderAttemptCap = 8
	licenceReminderLease      = 15 * time.Minute
)

type LicenceReminderService struct {
	db       *sql.DB
	mailer   MailSender
	enabled  bool
	appURL   string
	interval time.Duration
	now      func() time.Time
}

type LicenceReminderRun struct {
	Queued    int
	Delivered int
}

type LicenceReminderProjectStatus struct {
	Enabled            bool
	RecipientAvailable bool
	OrganisationName   string
	RecipientLabel     string
}

type LicenceReminderHistory struct {
	LicencePublicID string
	ThresholdDays   int
	Status          string
	Attempts        int
	SentAt          sql.NullTime
	CreatedAt       time.Time
}

type licenceReminderJob struct {
	id              int64
	licencePublicID string
	thresholdDays   int
	recipientUserID int64
	recipientEmail  string
	currentLabel    string
	attempts        int
	expiresAt       time.Time
	entityName      string
	projectName     string
	projectUUID     string
	organisation    string
	eligible        bool
}

func NewLicenceReminderService(db *sql.DB, cfg *config.Config, mailer MailSender) *LicenceReminderService {
	return &LicenceReminderService{
		db:       db,
		mailer:   mailer,
		enabled:  cfg.LicenceRemindersEnabled,
		appURL:   strings.TrimRight(cfg.AppURL, "/"),
		interval: time.Duration(cfg.LicenceReminderIntervalSeconds) * time.Second,
		now:      time.Now,
	}
}

func (s *LicenceReminderService) Enabled() bool { return s != nil && s.enabled && s.mailer != nil }

// Start runs one scan immediately and then at the configured interval. One
// goroutine performs both queueing and delivery, so a slow SMTP provider cannot
// cause overlapping scans inside a process. Database leases coordinate several
// Blackwall instances.
func (s *LicenceReminderService) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	go func() {
		s.runAndLog(ctx)
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runAndLog(ctx)
			}
		}
	}()
}

func (s *LicenceReminderService) runAndLog(ctx context.Context) {
	run, err := s.RunOnce(ctx)
	if err != nil {
		log.Printf("licence reminder worker failed: %v", err)
		return
	}
	if run.Queued > 0 || run.Delivered > 0 {
		log.Printf("licence reminder worker queued=%d processed=%d", run.Queued, run.Delivered)
	}
}

func (s *LicenceReminderService) RunOnce(ctx context.Context) (LicenceReminderRun, error) {
	if !s.Enabled() {
		return LicenceReminderRun{}, nil
	}
	now := s.now().UTC()
	queued, err := s.QueueDue(ctx, now)
	if err != nil {
		return LicenceReminderRun{}, fmt.Errorf("queue due reminders: %w", err)
	}
	processed, err := s.DeliverPending(ctx, now, licenceReminderBatchSize)
	if err != nil {
		return LicenceReminderRun{Queued: queued}, fmt.Errorf("deliver reminders: %w", err)
	}
	return LicenceReminderRun{Queued: queued, Delivered: processed}, nil
}

// QueueDue records each reminder before attempting SMTP. Countdown thresholds
// are UTC calendar days: a licence expiring on 15 September enters its 30-day
// reminder window throughout 16 August, irrespective of the worker's run time.
func (s *LicenceReminderService) QueueDue(ctx context.Context, now time.Time) (int, error) {
	queued := 0
	for _, threshold := range licenceReminderThresholds {
		windowStart, windowEnd := licenceReminderWindow(now, threshold)
		rows, err := s.db.QueryContext(ctx, `SELECT pl.id, o.admin_user_id, u.display_label
			FROM project_licences pl
			JOIN projects p ON p.id=pl.project_id AND p.status='active'
			JOIN organizations o ON o.id=p.organization_id AND o.status='active'
			JOIN users u ON u.id=o.admin_user_id AND u.status='active'
			WHERE pl.revoked_at IS NULL AND pl.expires_at>=? AND pl.expires_at<?`, windowStart, windowEnd)
		if err != nil {
			return queued, err
		}
		type candidate struct {
			licenceID int64
			userID    int64
			email     string
		}
		var candidates []candidate
		for rows.Next() {
			var c candidate
			var label string
			if err := rows.Scan(&c.licenceID, &c.userID, &label); err != nil {
				rows.Close()
				return queued, err
			}
			email, err := normaliseReminderMailbox(label)
			if err != nil {
				log.Printf("licence reminder skipped: organisation administrator user_id=%d has no valid email address", c.userID)
				continue
			}
			c.email = email
			candidates = append(candidates, c)
		}
		if err := rows.Close(); err != nil {
			return queued, err
		}
		if err := rows.Err(); err != nil {
			return queued, err
		}
		for _, c := range candidates {
			result, err := s.db.ExecContext(ctx, `INSERT INTO licence_renewal_reminders
				(licence_id, threshold_days, recipient_user_id, recipient_email, status, next_attempt_at)
				VALUES (?, ?, ?, ?, 'pending', ?)
				ON DUPLICATE KEY UPDATE recipient_email=IF(status='pending',VALUES(recipient_email),recipient_email)`,
				c.licenceID, threshold, c.userID, c.email, now.UTC())
			if err != nil {
				return queued, err
			}
			if affected, err := result.RowsAffected(); err == nil {
				if affected > 0 {
					queued++
				}
			}
		}
	}
	return queued, nil
}

func licenceReminderWindow(now time.Time, threshold int) (time.Time, time.Time) {
	utc := now.UTC()
	dayStart := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	windowStart := dayStart.AddDate(0, 0, threshold)
	return windowStart, windowStart.AddDate(0, 0, 1)
}

func (s *LicenceReminderService) DeliverPending(ctx context.Context, now time.Time, batchSize int) (int, error) {
	if batchSize < 1 || batchSize > 100 {
		batchSize = licenceReminderBatchSize
	}
	leaseExpiry := now.UTC().Add(-licenceReminderLease)
	if _, err := s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders
		SET status='pending', lock_token=NULL, locked_at=NULL, next_attempt_at=?
		WHERE status='sending' AND locked_at<?`, now.UTC(), leaseExpiry); err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders r
		JOIN project_licences pl ON pl.id=r.licence_id
		JOIN projects p ON p.id=pl.project_id
		JOIN organizations o ON o.id=p.organization_id
		LEFT JOIN users u ON u.id=r.recipient_user_id
		SET r.status='cancelled', r.lock_token=NULL, r.locked_at=NULL, r.last_error_code='no_longer_eligible'
		WHERE r.status='pending' AND (
			pl.revoked_at IS NOT NULL OR pl.expires_at<=? OR p.status<>'active' OR o.status<>'active'
			OR o.admin_user_id IS NULL OR o.admin_user_id<>r.recipient_user_id OR u.id IS NULL OR u.status<>'active'
		)`, now.UTC()); err != nil {
		return 0, err
	}

	lockToken := uuid.NewString()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM licence_renewal_reminders
		WHERE status='pending' AND next_attempt_at<=?
		ORDER BY next_attempt_at, id LIMIT ? FOR UPDATE SKIP LOCKED`, now.UTC(), batchSize)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			tx.Rollback()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := rows.Err(); err != nil {
		tx.Rollback()
		return 0, err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE licence_renewal_reminders
			SET status='sending', lock_token=?, locked_at=? WHERE id=? AND status='pending'`, lockToken, now.UTC(), id); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}

	jobs, err := s.claimedJobs(ctx, lockToken, now.UTC())
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, job := range jobs {
		if !job.eligible {
			_, _ = s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders
				SET status='cancelled', lock_token=NULL, locked_at=NULL, last_error_code='no_longer_eligible'
				WHERE id=? AND status='sending' AND lock_token=?`, job.id, lockToken)
			processed++
			continue
		}
		message := s.reminderMessage(job)
		deliveryCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		deliveryErr := s.mailer.Send(deliveryCtx, message)
		cancel()
		job.attempts++
		if deliveryErr == nil {
			_, err = s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders
				SET status='succeeded', attempts=?, sent_at=?, lock_token=NULL, locked_at=NULL, last_error_code=NULL
				WHERE id=? AND status='sending' AND lock_token=?`, job.attempts, s.now().UTC(), job.id, lockToken)
		} else {
			code, retryable := classifyMailDeliveryError(deliveryErr)
			if retryable && job.attempts < licenceReminderAttemptCap {
				nextAttempt := now.UTC().Add(licenceReminderRetryDelay(job.attempts))
				_, err = s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders
					SET status='pending', attempts=?, next_attempt_at=?, lock_token=NULL, locked_at=NULL, last_error_code=?
					WHERE id=? AND status='sending' AND lock_token=?`, job.attempts, nextAttempt, code, job.id, lockToken)
			} else {
				_, err = s.db.ExecContext(ctx, `UPDATE licence_renewal_reminders
					SET status='exhausted', attempts=?, lock_token=NULL, locked_at=NULL, last_error_code=?
					WHERE id=? AND status='sending' AND lock_token=?`, job.attempts, code, job.id, lockToken)
			}
		}
		if err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (s *LicenceReminderService) claimedJobs(ctx context.Context, lockToken string, now time.Time) ([]licenceReminderJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, pl.public_id, r.threshold_days,
		r.recipient_user_id, r.recipient_email, u.display_label, r.attempts, pl.expires_at,
		pl.entity_name, p.name, p.uuid, o.name,
		(pl.revoked_at IS NULL AND pl.expires_at>? AND p.status='active' AND o.status='active'
		 AND o.admin_user_id=r.recipient_user_id AND u.status='active') AS eligible
		FROM licence_renewal_reminders r
		JOIN project_licences pl ON pl.id=r.licence_id
		JOIN projects p ON p.id=pl.project_id
		JOIN organizations o ON o.id=p.organization_id
		JOIN users u ON u.id=r.recipient_user_id
		WHERE r.status='sending' AND r.lock_token=? ORDER BY r.id`, now, lockToken)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []licenceReminderJob
	for rows.Next() {
		var job licenceReminderJob
		if err := rows.Scan(&job.id, &job.licencePublicID, &job.thresholdDays,
			&job.recipientUserID, &job.recipientEmail, &job.currentLabel, &job.attempts, &job.expiresAt,
			&job.entityName, &job.projectName, &job.projectUUID, &job.organisation,
			&job.eligible); err != nil {
			return nil, err
		}
		currentEmail, emailErr := normaliseReminderMailbox(job.currentLabel)
		job.eligible = job.eligible && emailErr == nil && strings.EqualFold(currentEmail, job.recipientEmail)
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *LicenceReminderService) reminderMessage(job licenceReminderJob) OutboundEmail {
	dayWord := "days"
	if job.thresholdDays == 1 {
		dayWord = "day"
	}
	subject := fmt.Sprintf("Blackwall licence renewal reminder: %d %s remaining", job.thresholdDays, dayWord)
	body := fmt.Sprintf(`A project licence is approaching its renewal date.

Organisation: %s
Project: %s
Licensed entity: %s
Licence ID: %s
Expires: %s
Countdown: %d calendar %s remaining

Review or renew this licence in Blackwall:
%s/admin/projects/%s/licences

This automated message contains no licence token or signed entitlement details. If the licence has already been replaced or revoked, no further reminders for it will be sent.
`, safeReminderText(job.organisation), safeReminderText(job.projectName), safeReminderText(job.entityName), job.licencePublicID,
		job.expiresAt.UTC().Format("2 January 2006 at 15:04 UTC"), job.thresholdDays, dayWord, s.appURL, job.projectUUID)
	return OutboundEmail{
		To: job.recipientEmail, Subject: subject, Text: body,
		MessageKey: fmt.Sprintf("licence-reminder:%s:%d:%d", job.licencePublicID, job.thresholdDays, job.recipientUserID),
	}
}

func (s *LicenceReminderService) ProjectStatus(ctx context.Context, projectID int) (LicenceReminderProjectStatus, error) {
	status := LicenceReminderProjectStatus{Enabled: s.Enabled()}
	var label, userStatus string
	err := s.db.QueryRowContext(ctx, `SELECT o.name, COALESCE(u.display_label,''), COALESCE(u.status,'')
		FROM projects p JOIN organizations o ON o.id=p.organization_id
		LEFT JOIN users u ON u.id=o.admin_user_id WHERE p.id=?`, projectID).
		Scan(&status.OrganisationName, &label, &userStatus)
	if err != nil {
		return status, err
	}
	if userStatus == "active" {
		if email, err := normaliseReminderMailbox(label); err == nil {
			status.RecipientAvailable = true
			status.RecipientLabel = email
		}
	}
	return status, nil
}

func (s *LicenceReminderService) HistoryForProject(ctx context.Context, projectID, limit int) ([]LicenceReminderHistory, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT pl.public_id, r.threshold_days, r.status, r.attempts, r.sent_at, r.created_at
		FROM licence_renewal_reminders r JOIN project_licences pl ON pl.id=r.licence_id
		WHERE pl.project_id=? ORDER BY r.created_at DESC, r.id DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var history []LicenceReminderHistory
	for rows.Next() {
		var item LicenceReminderHistory
		if err := rows.Scan(&item.LicencePublicID, &item.ThresholdDays, &item.Status,
			&item.Attempts, &item.SentAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		history = append(history, item)
	}
	return history, rows.Err()
}

func classifyMailDeliveryError(err error) (string, bool) {
	var deliveryError *MailDeliveryError
	if errors.As(err, &deliveryError) {
		return deliveryError.Code, deliveryError.Retryable
	}
	return "delivery_failed", true
}

func licenceReminderRetryDelay(attempt int) time.Duration {
	delays := [...]time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	if attempt < 1 {
		return delays[0]
	}
	if attempt > len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt-1]
}

func safeReminderText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || (r < ' ' && r != ' ') {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}
