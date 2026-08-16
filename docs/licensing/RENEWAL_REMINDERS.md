# Project Licence Renewal Reminders

Blackwall can email the designated administrator of a project's organisation
when an active licence has 30, 14, 7, 2, and 1 UTC calendar days remaining.
The worker runs inside the Blackwall process and uses a durable MySQL queue, so
a restart or temporary mail-provider outage does not discard pending work.

## Recipient and countdown rules

- The recipient is the active user referenced by the organisation's
  `admin_user_id`. That user's display label must parse as one email address.
- The project and organisation must both be active. Revoked and expired
  licences are not eligible.
- Thresholds use UTC calendar dates. For example, a licence expiring at any
  time on 15 September enters its 30-day window on 16 August.
- Changing the designated administrator cancels an old administrator's queued
  reminder before delivery. The next scan can queue the current administrator
  while the threshold date is still current.
- Each licence, threshold, and administrator combination has a database unique
  constraint. Concurrent application instances cannot deliberately enqueue the
  same reminder twice.

The project licence page shows whether delivery and the designated recipient
are ready, plus the 25 most recent queued, sent, cancelled, or exhausted
reminders. Correct the organisation administrator's display label if the page
reports that a recipient is needed.

## Secure SMTP setup

Blackwall supports mandatory STARTTLS and implicit TLS. Plaintext SMTP is not
available. In production, supply the password through a deployment secret or
environment variable; do not put it in `config.yaml`, Git, an image layer, a
support bundle, or an audit event.

Example using authenticated submission on port 587:

```yaml
licence_reminders_enabled: true
licence_reminder_interval_seconds: 900
smtp_host: "smtp.example.com"
smtp_port: 587
smtp_username: "blackwall"
smtp_password: "" # set SMTP_PASSWORD through the deployment secret store
smtp_from_address: "licences@example.com"
smtp_from_name: "Blackwall"
smtp_tls_mode: "starttls"
smtp_timeout_seconds: 10
```

For an implicit-TLS provider, normally use port 465 and
`smtp_tls_mode: "implicit"`. Blackwall requires TLS 1.2 or newer and performs
normal certificate and hostname verification. It refuses to start with
reminders enabled if the SMTP host, port, sender, credential pair, TLS mode,
interval, or timeout is invalid. A relay which does not require authentication
may leave both `smtp_username` and `smtp_password` blank, but the connection
must still use verified TLS.

## Delivery and retry behaviour

Each message is plain text and includes only the organisation, project,
licensed entity, public licence ID, exact UTC expiry time, countdown, and an
authenticated admin link. It deliberately excludes the signed licence token,
hostnames, features, instance allowance, and customer reference.

The queue leases a reminder to one worker for 15 minutes and reclaims an
abandoned lease. Temporary transport and SMTP 4xx failures use bounded backoff:
5 minutes, 15 minutes, 1 hour, 3 hours, 6 hours, 12 hours, and 24 hours. The
eighth failed attempt is marked exhausted. Permanent SMTP 5xx, authentication,
certificate, configuration, sender, or recipient failures are exhausted
without futile retries.

SMTP cannot provide true exactly-once delivery across a process crash after a
mail server accepts `DATA` but before MySQL records success. Blackwall therefore
uses a stable, opaque Message-ID for every licence/threshold/recipient reminder,
allowing receiving systems to suppress that rare duplicate. The database
uniqueness constraint and row lease prevent duplicates during normal operation.

## Operational checks

1. Enable the service first in a non-production environment and confirm the
   sender passes SPF, DKIM, and DMARC alignment at the receiving domain.
2. Confirm the project licence page shows **ready** and the intended recipient.
3. Use a short-lived test licence whose expiry date enters a threshold window;
   do not edit production expiry timestamps merely to force a test.
4. Confirm the history row becomes **Sent** and the message links back to the
   correctly scoped project.
5. Alert on `exhausted` rows and repeated `smtp_auth_failed`, `tls_failed`, or
   `recipient_rejected` categories. Blackwall stores only the category, not the
   provider's potentially sensitive response.
6. Rotate SMTP credentials through the secret store, restart Blackwall, and
   confirm a test delivery. Rotation does not alter queued reminders.

Disabling `licence_reminders_enabled` stops both scans and delivery. Existing
queue history remains available and pending work resumes after the service is
configured and enabled again.
