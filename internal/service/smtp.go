package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"

	"blackwall/internal/config"
)

// OutboundEmail is deliberately plain-text only. Licence reminders contain no
// licence token, hostname list, feature list, or customer reference, and a
// plain body avoids introducing an HTML-injection surface into an automated
// security notification.
type OutboundEmail struct {
	To      string
	Subject string
	Text    string
	// MessageKey is a stable, non-secret identifier used to derive Message-ID.
	// Retries retain the same value so a receiving mail system can suppress a
	// duplicate if SMTP succeeded immediately before Blackwall crashed.
	MessageKey string
}

// MailSender is the narrow delivery boundary used by the reminder worker. It
// also makes retry and message behaviour testable without real SMTP access.
type MailSender interface {
	Send(context.Context, OutboundEmail) error
}

// MailDeliveryError carries a stable, non-sensitive category. Callers persist
// only Code, never a provider response which could contain addresses or other
// deployment details.
type MailDeliveryError struct {
	Code      string
	Retryable bool
	err       error
}

func (e *MailDeliveryError) Error() string { return e.Code }
func (e *MailDeliveryError) Unwrap() error { return e.err }

type SMTPMailer struct {
	host        string
	port        int
	username    string
	password    string
	fromAddress string
	fromName    string
	tlsMode     string
	timeout     time.Duration
}

func NewSMTPMailer(cfg *config.Config) *SMTPMailer {
	return &SMTPMailer{
		host:        strings.TrimSpace(cfg.SMTPHost),
		port:        cfg.SMTPPort,
		username:    cfg.SMTPUsername,
		password:    cfg.SMTPPassword,
		fromAddress: strings.TrimSpace(cfg.SMTPFromAddress),
		fromName:    strings.TrimSpace(cfg.SMTPFromName),
		tlsMode:     cfg.SMTPTLSMode,
		timeout:     time.Duration(cfg.SMTPTimeoutSeconds) * time.Second,
	}
}

func (m *SMTPMailer) Send(ctx context.Context, message OutboundEmail) error {
	recipient, err := normaliseReminderMailbox(message.To)
	if err != nil {
		return &MailDeliveryError{Code: "invalid_recipient", err: err}
	}
	if message.Subject == "" || strings.ContainsAny(message.Subject, "\r\n") {
		return &MailDeliveryError{Code: "invalid_subject", err: errors.New("invalid subject")}
	}
	body, err := m.buildMessage(recipient, message)
	if err != nil {
		return &MailDeliveryError{Code: "invalid_message", err: err}
	}

	address := net.JoinHostPort(m.host, fmt.Sprintf("%d", m.port))
	dialer := &net.Dialer{Timeout: m.timeout, KeepAlive: -1}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return deliveryTransportError("connect_failed", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deliveryDeadline(ctx, m.timeout))

	// Closing the connection is the only reliable way to interrupt net/smtp if
	// the caller cancels while a command is blocked on a malicious or broken
	// server. The deadline remains the independent upper bound.
	rawConn := conn
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-done:
		}
	}()

	tlsConfig := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	if m.tlsMode == "implicit" {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return &MailDeliveryError{Code: "tls_failed", Retryable: isTemporaryError(err), err: err}
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return deliverySMTPError("smtp_greeting_failed", err)
	}
	defer client.Close()

	if m.tlsMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return &MailDeliveryError{Code: "starttls_unavailable", err: errors.New("SMTP server does not advertise STARTTLS")}
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return deliverySMTPError("tls_failed", err)
		}
	}
	if m.username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return &MailDeliveryError{Code: "smtp_auth_unavailable", err: errors.New("SMTP server does not advertise AUTH")}
		}
		if err := client.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
			return deliverySMTPError("smtp_auth_failed", err)
		}
	}
	if err := client.Mail(m.fromAddress); err != nil {
		return deliverySMTPError("sender_rejected", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return deliverySMTPError("recipient_rejected", err)
	}
	writer, err := client.Data()
	if err != nil {
		return deliverySMTPError("data_rejected", err)
	}
	if _, err := io.Copy(writer, strings.NewReader(body)); err != nil {
		_ = writer.Close()
		return deliveryTransportError("write_failed", err)
	}
	if err := writer.Close(); err != nil {
		return deliverySMTPError("message_rejected", err)
	}
	// DATA's final successful response means the server accepted ownership of
	// the message. A subsequent QUIT failure must not trigger a retry and risk a
	// duplicate notification.
	_ = client.Quit()
	return nil
}

func (m *SMTPMailer) buildMessage(recipient string, message OutboundEmail) (string, error) {
	if strings.ContainsAny(m.fromName+m.fromAddress+recipient, "\r\n") {
		return "", errors.New("mail header contains a line break")
	}
	from := (&mail.Address{Name: m.fromName, Address: m.fromAddress}).String()
	subject := mime.QEncoding.Encode("utf-8", message.Subject)
	text := strings.ReplaceAll(message.Text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	var encodedText bytes.Buffer
	encoder := quotedprintable.NewWriter(&encodedText)
	if _, err := encoder.Write([]byte(text)); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	messageID := uuid.NewString()
	if message.MessageKey != "" {
		digest := sha256.Sum256([]byte(message.MessageKey))
		messageID = "bwlr_" + hex.EncodeToString(digest[:16])
	}
	return strings.Join([]string{
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + messageID + "@blackwall.invalid>",
		"From: " + from,
		"To: " + recipient,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: quoted-printable",
		"Auto-Submitted: auto-generated",
		"X-Auto-Response-Suppress: All",
		"",
		encodedText.String(),
		"",
	}, "\r\n"), nil
}

func normaliseReminderMailbox(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 320 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("invalid mailbox")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address == "" || len(address.Address) > 254 {
		return "", errors.New("invalid mailbox")
	}
	// ParseAddress accepts display names, but the envelope and persisted queue
	// retain only the actual mailbox. This avoids header injection and prevents
	// a changed display name from generating a duplicate reminder.
	return address.Address, nil
}

func deliveryDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

func deliveryTransportError(code string, err error) error {
	return &MailDeliveryError{Code: code, Retryable: true, err: err}
}

func deliverySMTPError(code string, err error) error {
	retryable := isTemporaryError(err)
	var smtpError *textproto.Error
	if errors.As(err, &smtpError) {
		retryable = smtpError.Code >= 400 && smtpError.Code < 500
	}
	return &MailDeliveryError{Code: code, Retryable: retryable, err: err}
}

func isTemporaryError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}
