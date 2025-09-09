# BlackWall Operational Runbook

## Daily Operations

### Monitor Health

```bash
# Check application health
curl https://blackwall.cx/health

# Check database connectivity
mysql -u blackwall -p blackwall -e "SELECT COUNT(*) FROM users;"

# Check disk space
df -h /home/andy/domains/blackwall.cx

# Check logs for errors
tail -100 /home/andy/domains/blackwall.cx/logs/*.log | grep -i error
```

### Review Audit Logs

Access admin panel: https://blackwall.cx/admin/audit

**Look for:**
- Multiple failed authentication attempts from same IP
- Unauthorized access attempts (invalid project_id, privilege escalation)
- Rate limit hits
- CSRF validation failures

**Alert thresholds:**
- 5+ failed WebAuthn authentications from same IP in 10 minutes
- 10+ oauth.authorize.fail events per hour
- Any security.csrf.fail events

### Backup

**Daily backup** (automate with cron):

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/home/andy/backups/blackwall"

mkdir -p $BACKUP_DIR

# Database backup
mysqldump -u blackwall -p***REMOVED*** blackwall | gzip > $BACKUP_DIR/blackwall_db_$DATE.sql.gz

# Environment config
cp /home/andy/domains/blackwall.cx/.env $BACKUP_DIR/env_$DATE

# Rotate old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

### Check Rate Limits

```bash
mysql -u blackwall -p blackwall << 'EOF'
SELECT identifier, action, attempts, blocked_until
FROM rate_limits
WHERE blocked_until IS NOT NULL AND blocked_until > NOW()
ORDER BY blocked_until DESC
LIMIT 20;
EOF
```

## Weekly Maintenance

### Review OAuth Client Activity

```sql
-- Active clients by project
SELECT p.name AS project, c.name AS client, c.status, COUNT(t.id) AS token_count
FROM oauth_clients c
JOIN projects p ON p.id = c.project_id
LEFT JOIN oauth_access_tokens t ON t.client_id = c.id AND t.created_at > NOW() - INTERVAL 7 DAY
GROUP BY c.id
ORDER BY token_count DESC;
```

### Clean Up Expired Tokens

```sql
-- Delete expired auth codes (older than 1 day)
DELETE FROM oauth_auth_codes WHERE created_at < NOW() - INTERVAL 1 DAY;

-- Delete expired access tokens (older than 7 days)
DELETE FROM oauth_access_tokens WHERE expires_at < NOW() - INTERVAL 7 DAY;

-- Delete expired refresh tokens (older than 30 days)
DELETE FROM oauth_refresh_tokens WHERE expires_at < NOW() - INTERVAL 30 DAY;

-- Clean up rate limit table
DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL 1 DAY;
```

### Review User Access

```sql
-- Users without any project assignments
SELECT u.uuid, u.display_label, u.created_at
FROM users u
LEFT JOIN user_project_roles r ON r.user_id = u.id
WHERE r.id IS NULL;

-- Disabled users with active sessions (check manually)
SELECT uuid, display_label, status FROM users WHERE status = 'disabled';
```

## Monthly Maintenance

### Rotate JWT Signing Keys

```bash
# Generate new RSA key pair
openssl genrsa -out /tmp/private_key.pem 2048
openssl rsa -in /tmp/private_key.pem -pubout -out /tmp/public_key.pem

# Get key ID
KID=$(openssl rand -hex 16)

# Insert new key
mysql -u blackwall -p blackwall << EOF
INSERT INTO jwt_signing_keys (kid, private_key, public_key, algorithm, is_active)
VALUES (
  '$KID',
  '$(cat /tmp/private_key.pem)',
  '$(cat /tmp/public_key.pem)',
  'RS256',
  1
);
EOF

# Clean up temp files
rm /tmp/private_key.pem /tmp/public_key.pem

# After 24 hours (allow JWKS cache refresh), deactivate old keys:
mysql -u blackwall -p blackwall << EOF
UPDATE jwt_signing_keys SET is_active = 0, rotated_at = NOW() WHERE kid != '$KID';
EOF
```

### Archive Old Audit Logs

```bash
# Export logs older than 90 days
mysql -u blackwall -p blackwall << 'EOF' > /home/andy/backups/blackwall/audit_archive_$(date +%Y%m%d).csv
SELECT * FROM audit_log WHERE created_at < NOW() - INTERVAL 90 DAY;
EOF

# Delete exported logs
mysql -u blackwall -p blackwall << 'EOF'
DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL 90 DAY;
EOF
```

### Review Privilege Escalations

```sql
-- Check for unusual privilege changes
SELECT 
  a.created_at,
  a.event_type,
  a.actor_user_uuid,
  a.target_id,
  a.metadata_json
FROM audit_log a
WHERE a.event_type LIKE 'admin.assignment.%'
  AND a.created_at > NOW() - INTERVAL 30 DAY
ORDER BY a.created_at DESC;
```

## Incident Response

### Scenario: Suspicious Login Activity

**Symptoms:** Multiple failed WebAuthn attempts from single IP

**Response:**

1. Identify affected IP:
   ```sql
   SELECT ip_address, COUNT(*) as attempts
   FROM audit_log
   WHERE event_type = 'webauthn.authentication.fail'
     AND created_at > NOW() - INTERVAL 1 HOUR
   GROUP BY ip_address
   HAVING attempts > 5
   ORDER BY attempts DESC;
   ```

2. Check if any succeeded:
   ```sql
   SELECT * FROM audit_log
   WHERE ip_address = 'SUSPICIOUS_IP'
     AND event_type = 'webauthn.authentication.success'
     AND created_at > NOW() - INTERVAL 24 HOUR;
   ```

3. If compromised, disable user:
   ```sql
   UPDATE users SET status = 'disabled' WHERE id = AFFECTED_USER_ID;
   ```

4. Revoke all tokens for user:
   ```sql
   UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE user_id = AFFECTED_USER_ID;
   UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE user_id = AFFECTED_USER_ID;
   ```

5. Force WebAuthn re-enrollment (delete old credentials):
   ```sql
   DELETE FROM webauthn_credentials WHERE user_id = AFFECTED_USER_ID;
   ```

### Scenario: Invalid Token Usage

**Symptoms:** Client using wrong project_id or expired tokens

**Response:**

1. Find problem client:
   ```sql
   SELECT oauth_client_public_id, COUNT(*) as fails
   FROM audit_log
   WHERE event_type LIKE 'oauth.%.fail'
     AND created_at > NOW() - INTERVAL 1 HOUR
   GROUP BY oauth_client_public_id
   ORDER BY fails DESC;
   ```

2. Review client configuration:
   ```sql
   SELECT c.*, p.name AS project_name
   FROM oauth_clients c
   JOIN projects p ON p.id = c.project_id
   WHERE c.client_id = 'PROBLEM_CLIENT_ID';
   ```

3. Disable client if necessary:
   ```sql
   UPDATE oauth_clients SET status = 'disabled' WHERE client_id = 'PROBLEM_CLIENT_ID';
   ```

4. Notify project owner.

### Scenario: Database Connection Failure

**Symptoms:** Application returns 500 errors, health check fails

**Response:**

1. Check MySQL status:
   ```bash
   systemctl status mysql
   ```

2. Check connections:
   ```bash
   mysql -u root -p -e "SHOW PROCESSLIST;"
   ```

3. Verify credentials:
   ```bash
   mysql -u blackwall -p***REMOVED*** -e "SELECT 1;"
   ```

4. Check disk space:
   ```bash
   df -h
   ```

5. Restart MySQL if needed:
   ```bash
   sudo systemctl restart mysql
   ```

### Scenario: CSRF Attack Detected

**Symptoms:** Multiple security.csrf.fail events in audit log

**Response:**

1. Identify source:
   ```sql
   SELECT ip_address, user_agent, COUNT(*) as attempts
   FROM audit_log
   WHERE event_type = 'security.csrf.fail'
     AND created_at > NOW() - INTERVAL 1 HOUR
   GROUP BY ip_address, user_agent
   ORDER BY attempts DESC;
   ```

2. Block IP at firewall level if widespread:
   ```bash
   sudo iptables -A INPUT -s ATTACKER_IP -j DROP
   ```

3. Verify CSRF_SECRET is properly set and not exposed.

4. Check for XSS vulnerabilities in custom templates.

## Recovery Procedures

### Restore from Backup

```bash
# Stop web server
sudo systemctl stop apache2

# Restore database
gunzip < /home/andy/backups/blackwall/blackwall_db_20260204.sql.gz | mysql -u blackwall -p blackwall

# Restore .env
cp /home/andy/backups/blackwall/env_20260204 /home/andy/domains/blackwall.cx/.env

# Start web server
sudo systemctl start apache2

# Verify
curl https://blackwall.cx/health
```

### Reset Admin Password (WebAuthn Credential Lost)

```bash
# 1. Delete bootstrap completion flag
mysql -u blackwall -p blackwall << 'EOF'
DELETE FROM system_config WHERE config_key = 'bootstrap_complete';
EOF

# 2. Run bootstrap again
php /home/andy/domains/blackwall.cx/bin/blackwall

# 3. Follow prompts to enroll new key
```

### Emergency Client Credential Reset

```bash
# Generate new client secret
NEW_SECRET=$(openssl rand -hex 32)
NEW_SECRET_HASH=$(php -r "echo password_hash('$NEW_SECRET', PASSWORD_ARGON2ID);")

mysql -u blackwall -p blackwall << EOF
UPDATE oauth_clients
SET client_secret_hash = '$NEW_SECRET_HASH'
WHERE client_id = 'AFFECTED_CLIENT_ID';
EOF

# Securely deliver new secret to client owner
echo "New client_secret: $NEW_SECRET"
```

## Performance Tuning

### Database Indexes

```sql
-- Check slow queries
SHOW VARIABLES LIKE 'slow_query%';

-- Analyze audit_log table
ANALYZE TABLE audit_log;

-- Add index if needed
-- Already created in migrations, but verify:
SHOW INDEX FROM audit_log;
```

### Cache JWKS

Clients should cache JWKS for 24 hours. Monitor `/oauth/jwks` access:

```bash
grep "GET /oauth/jwks" /home/andy/domains/blackwall.cx/logs/apache_access.log | wc -l
```

If excessive (>1000/day), advise clients to implement caching.

### Rate Limit Tuning

Adjust in code (Security/RateLimiter.php) or database:

```sql
-- View current limits
SELECT * FROM rate_limits ORDER BY attempts DESC LIMIT 20;

-- Clear specific limit
DELETE FROM rate_limits WHERE identifier = 'IP_ADDRESS' AND action = 'oauth.token';
```

## Monitoring & Alerts

### Key Metrics to Track

1. **Authentication success rate**: `webauthn.authentication.success` / total attempts
2. **Token issuance rate**: `oauth.token.issue` per hour
3. **Failed authorizations**: `oauth.authorize.fail` count
4. **Rate limit hits**: `security.ratelimit.hit` count
5. **Database query time**: Monitor slow_query_log
6. **Disk usage**: /home/andy/domains/blackwall.cx
7. **SSL certificate expiry**: Check monthly

### Recommended Alerts

- Failed auth rate > 10/min from single IP
- oauth.*.fail > 50/hour globally
- Disk usage > 80%
- SSL cert expiry < 30 days
- Database backup failure
- Health check failure

## Contacts

- **System Administrator**: admin@dixon.cx
- **Database Admin**: dba@dixon.cx
- **Security Team**: security@dixon.cx

## Version History

- v1.0 (2026-02-04): Initial deployment
