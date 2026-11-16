// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLicenceReminderThresholds(t *testing.T) {
	want := [...]int{30, 14, 7, 2, 1}
	if licenceReminderThresholds != want {
		t.Fatalf("thresholds = %v, want %v", licenceReminderThresholds, want)
	}
}

func TestLicenceReminderWindowUsesUTCCalendarDay(t *testing.T) {
	now := time.Date(2026, time.August, 16, 23, 45, 0, 0, time.FixedZone("BST", 3600))
	start, end := licenceReminderWindow(now, 30)
	if got, want := start.Format(time.RFC3339), "2026-09-15T00:00:00Z"; got != want {
		t.Fatalf("start = %s, want %s", got, want)
	}
	if got, want := end.Format(time.RFC3339), "2026-09-16T00:00:00Z"; got != want {
		t.Fatalf("end = %s, want %s", got, want)
	}
}

func TestReminderMessageContainsUsefulMetadataButNoEntitlements(t *testing.T) {
	service := &LicenceReminderService{appURL: "https://blackwall.cx"}
	message := service.reminderMessage(licenceReminderJob{
		licencePublicID: "38a46ec2-7f4d-4a77-99dc-2298b16acb08",
		thresholdDays:   1,
		recipientUserID: 42,
		recipientEmail:  "admin@example.com",
		expiresAt:       time.Date(2026, 8, 17, 12, 30, 0, 0, time.UTC),
		entityName:      "Example Limited\nInjected",
		projectName:     "Billing",
		projectUUID:     "aa88643b-889d-4ce7-a96d-4a562065c880",
		organisation:    "Example Organisation",
	})
	for _, value := range []string{"1 day remaining", "Example Limited Injected", "38a46ec2", "17 August 2026", "/admin/projects/aa88643b-889d-4ce7-a96d-4a562065c880/licences"} {
		if !strings.Contains(message.Subject+message.Text, value) {
			t.Errorf("message does not contain %q", value)
		}
	}
	for _, forbidden := range []string{"BWLIC1.", "hostnames", "features", "entity_reference"} {
		if strings.Contains(message.Text, forbidden) {
			t.Errorf("message leaked forbidden licence detail %q", forbidden)
		}
	}
	if message.MessageKey != "licence-reminder:38a46ec2-7f4d-4a77-99dc-2298b16acb08:1:42" {
		t.Fatalf("unexpected stable message key: %q", message.MessageKey)
	}
}

func TestNormaliseReminderMailbox(t *testing.T) {
	cases := map[string]string{
		"admin@example.com":                "admin@example.com",
		"Admin Person <Admin@example.com>": "Admin@example.com",
		"  root@localhost  ":               "root@localhost",
	}
	for input, want := range cases {
		got, err := normaliseReminderMailbox(input)
		if err != nil || got != want {
			t.Errorf("normaliseReminderMailbox(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "not-an-address", "a@example.com\r\nBcc: victim@example.com", "a@example.com, b@example.com"} {
		if _, err := normaliseReminderMailbox(input); err == nil {
			t.Errorf("normaliseReminderMailbox(%q) accepted invalid input", input)
		}
	}
}

func TestSMTPMessageHasStableSafeHeaders(t *testing.T) {
	mailer := &SMTPMailer{host: "smtp.example.com", fromAddress: "licences@example.com", fromName: "Blackwall"}
	message := OutboundEmail{
		To: "admin@example.com", Subject: "Licence renewal – 14 days", Text: "Line one\nLine two",
		MessageKey: "licence-reminder:abc:14:42",
	}
	first, err := mailer.buildMessage(message.To, message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mailer.buildMessage(message.To, message)
	if err != nil {
		t.Fatal(err)
	}
	firstID := headerLine(first, "Message-ID:")
	secondID := headerLine(second, "Message-ID:")
	if firstID == "" || firstID != secondID || !strings.HasSuffix(firstID, "@blackwall.invalid>") {
		t.Fatalf("Message-ID is not stable and safe: %q / %q", firstID, secondID)
	}
	for _, header := range []string{"Auto-Submitted: auto-generated", "X-Auto-Response-Suppress: All", "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: quoted-printable"} {
		if !strings.Contains(first, header+"\r\n") {
			t.Errorf("message is missing %q", header)
		}
	}
	if !strings.Contains(first, "Line one\r\nLine two") {
		t.Error("message body was not converted to CRLF")
	}
}

func TestSMTPMessageRejectsHeaderInjection(t *testing.T) {
	mailer := &SMTPMailer{fromAddress: "licences@example.com", fromName: "Blackwall\r\nBcc: victim@example.com"}
	if _, err := mailer.buildMessage("admin@example.com", OutboundEmail{Subject: "Reminder", Text: "Body"}); err == nil {
		t.Fatal("header injection was accepted")
	}
}

func TestMailErrorClassificationAndBackoff(t *testing.T) {
	code, retryable := classifyMailDeliveryError(&MailDeliveryError{Code: "tls_failed", Retryable: false, err: errors.New("private detail")})
	if code != "tls_failed" || retryable {
		t.Fatalf("classification = %q, %v", code, retryable)
	}
	if got := (&MailDeliveryError{Code: "safe_code", err: errors.New("secret provider response")}).Error(); got != "safe_code" {
		t.Fatalf("error leaked wrapped detail: %q", got)
	}
	if licenceReminderRetryDelay(1) != 5*time.Minute || licenceReminderRetryDelay(99) != 24*time.Hour {
		t.Fatal("unexpected retry schedule")
	}
}

func TestDisabledReminderServiceDoesNoWork(t *testing.T) {
	service := &LicenceReminderService{}
	run, err := service.RunOnce(context.Background())
	if err != nil || run != (LicenceReminderRun{}) {
		t.Fatalf("RunOnce() = %#v, %v", run, err)
	}
}

func headerLine(message, prefix string) string {
	for _, line := range strings.Split(message, "\r\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
