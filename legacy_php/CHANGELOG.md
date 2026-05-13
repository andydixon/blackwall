# BlackWall Changelog

## 2026-02-06 - User Management Enhancement

### Added

#### User Detail Page (`/admin/users/{id}`)
- **New Feature**: Comprehensive user detail page with full user information display
- Shows user UUID, display label, status, and timestamps
- Displays all enrolled WebAuthn credentials with metadata:
  - Credential label
  - Credential ID (truncated for readability)
  - Creation date
  - Last used timestamp
- Lists all project assignments for the user with privilege levels
- Quick actions sidebar for common operations:
  - View audit logs for specific user
  - Enable/disable user account

#### Enrollment Link Generation
- **New Feature**: Secure enrollment link system for WebAuthn credential enrollment
- Admins can generate time-limited enrollment links (24-hour expiry)
- Links contain only secure tokens - no user IDs exposed in URLs
- One-click copy button for easy sharing
- Success notification with full URL display

#### Public Enrollment Page (`/enroll?token=...`)
- **New Feature**: User-facing enrollment interface
- Clean, mobile-friendly design with instructions
- Uses WebAuthn API for secure credential registration  
- Automatic validation and error handling
- Redirects to portal login after successful enrollment

#### Credential Management
- **New Feature**: Delete credentials directly from user detail page
- CSRF protection on all credential operations
- Confirmation prompts before deletion
- Full audit logging of credential operations

#### Dashboard Enhancements
- **Enhancement**: IP addresses in recent activity are now clickable links
- Clicking an IP address filters the audit log by that IP
- Improved readability with code formatting for IP addresses
- Added IP Address column to recent activity table

### Technical Details

#### New Routes
```
POST /admin/users/{id}/enrollment-link
POST /admin/users/{id}/credentials/{credentialId}/delete
GET  /enroll?token=...
POST /enroll/complete
```

#### New Templates
- `/templates/admin/users/detail.php` - User detail page
- `/templates/enroll.php` - Public enrollment interface

#### Modified Files
- `/src/Controller/AdminController.php`
  - Added `userDetail()` method
  - Added `userUpdate()` method
  - Added `generateEnrollmentLink()` method
  - Added `deleteCredential()` method
- `/src/Controller/BootstrapController.php`
  - Added `showEnrollmentForm()` method
  - Added `enrollKey()` method
- `/templates/admin/dashboard.php`
  - Added IP Address column to recent activity
  - Made IP addresses clickable with audit log filter
- `/config/routes.php`
  - Added enrollment and credential management routes

#### Security Enhancements
- Enrollment tokens stored in database keyed by token (not user ID)
- Token expiry validation (24 hours)
- CSRF protection on all state-changing operations
- URL construction uses server variables (HTTPS detection)
- Audit logging for all user management operations

#### Database Schema
No schema changes required - uses existing:
- `system_config` table for enrollment token storage
- `webauthn_credentials` table for credential storage
- `audit_log` table for event logging

### Audit Events Added
- `admin.user.enrollment_link` - Enrollment link generated
- `admin.user.credential.delete` - Credential deleted by admin
- `admin.user.update` - User account updated
- `webauthn.registration.success` - Key enrolled via link
- `webauthn.registration.fail` - Enrollment failed

### Documentation Updates
- Updated `README.md` with user creation workflow
- Added enrollment link generation instructions
- Documented user detail page features
- Added IP address filtering documentation
- Updated audit logging section with clickable IP information

### Breaking Changes
None - All changes are additive and backward compatible.

### Migration Notes
No database migrations required. All functionality uses existing schema.

### Known Limitations
- Enrollment links expire after 24 hours (configurable in code)
- No bulk enrollment link generation
- No email notification system (links must be manually shared)

---

## Previous Changes

See git history for earlier modifications.
