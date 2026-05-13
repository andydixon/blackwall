# OAuth Implementation Fixes - February 2026

This document summarizes key fixes made to the BlackWall OAuth implementation.

## WebAuthn Signature Verification

### Issue
WebAuthn signatures were failing with "Invalid signature length" errors.

### Root Cause
- Browser sends ECDSA signatures in DER format (70-72 bytes)
- COSE library expects raw r||s format (64 bytes for ES256)

### Fix
Added DER-to-raw conversion in `WebAuthnService::verifyAssertion()`:
- Detects DER format (starts with 0x30)
- Extracts r and s components
- Removes DER padding
- Pads to 32 bytes each
- Concatenates to 64-byte raw format

## OAuth Client Storage

### Issue
Redirect URI validation failing with "Invalid redirect_uri".

### Root Cause
- Template form sent redirect URIs as newline-separated text
- Code stored as plain text string
- Repository tried to JSON decode, got null
- Validation failed

### Fix
1. Updated `AdminController::clientStore()` to parse and JSON encode redirect URIs
2. Updated `OAuthClientRepository::hydrate()` to handle null with `?? '[]'` fallback
3. Redirect URIs now stored as JSON array: `["https://example.com/callback"]`

## Project ID Handling  

### Issue
OAuth authorize endpoint required `project_id` parameter.

### Root Cause
- Original design required client to pass project_id
- Clients should only need client_id

### Fix
1. Removed `project_id` from required OAuth parameters
2. OAuth authorize derives project from `$client->projectId`  
3. Updated `authorizePost()` to use `findById()` instead of `findByUuid()`

## Dedicated OAuth Login

### Issue
OAuth flow redirected unauthenticated users to `/portal/login`, mixing concerns.

### Root Cause
- Single login page used for portal, admin, and OAuth
- Users saw portal branding when logging into external apps

### Fix
1. Created dedicated `/oauth/login` page showing application name
2. Separate WebAuthn challenge/verify endpoints for OAuth
3. After authentication, continues OAuth flow (not portal/admin)
4. Clean separation: portal login → portal, admin login → admin, OAuth login → back to client app

## Algorithm Lookup

### Issue
Token verification failed with "Unsupported algorithm".

### Root Cause
- Code looked up COSE algorithm at label `-1`
- Actual COSE spec uses label `3` for algorithm
- ES256 algorithm identifier is `-7`

### Fix
Changed `WebAuthnService::verifyAssertion()` to read `$publicKey->get(3)` which returns `-7`, then pass to algorithm manager.

## Client Secret Typo

### Issue
External app got "Invalid token response".

### Root Cause
- callback.php had typo: `grant_type=authorisation_code` (British spelling)
- Also: `Authorisation: Bearer` (British spelling)
- OAuth spec requires American spelling

### Fix
Updated external app callback:
- `grant_type=authorization_code`
- `Authorization: Bearer`

## Best Practices Learned

1. **Always use American spelling for OAuth spec**: `authorization` not `authorisation`
2. **Store redirect URIs as JSON arrays**: Enables proper array operations
3. **Derive context from relationships**: Don't require redundant parameters (project_id when we have client_id)
4. **Separate auth contexts**: OAuth, portal, and admin login should be distinct
5. **Handle COSE properly**: Use correct label numbers, convert DER signatures
6. **Bootstrap UI properly**: Use proper Bootstrap classes for professional appearance

## Testing Checklist

- [ ] Bootstrap process creates admin user and project
- [ ] Admin login with WebAuthn works
- [ ] Portal login with WebAuthn works
- [ ] OAuth client creation stores redirect URIs as JSON
- [ ] OAuth authorize redirects to dedicated OAuth login
- [ ] OAuth login shows application name
- [ ] WebAuthn authentication completes OAuth flow
- [ ] Token endpoint accepts authorization_code grant
- [ ] External app receives valid access_token
- [ ] UserInfo endpoint returns user data

## Files Modified

- `src/Service/WebAuthnService.php` - DER signature conversion, algorithm lookup
- `src/Controller/OAuthController.php` - Removed project_id requirement, added OAuth login methods
- `src/Controller/AdminController.php` - OAuth client CRUD with proper JSON storage
- `src/Controller/PortalController.php` - OAuth return URL handling
- `src/Repository/OAuthClientRepository.php` - Null-safe JSON decoding
- `templates/oauth/login.php` - New dedicated OAuth login page
- `templates/oauth/consent.php` - OAuth consent screen
- `templates/admin/clients/*.php` - Bootstrap-styled client management
- `config/routes.php` - Added OAuth login routes

## Documentation Updated

- README.md - Corrected OAuth flow, removed project_id requirement
- IMPLEMENTATION_PROMPT.md - Updated with correct parameter names
- This file (OAUTH_FIXES.md) - Complete fix summary
