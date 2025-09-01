# BlackWall User Portal Guide

## Overview

The BlackWall User Portal provides a self-service interface for users to manage their account, view project access, and manage security keys. The portal uses the same WebAuthn security as the admin panel.

## Accessing the Portal

Visit: **https://blackwall.dixon.cx/portal**

You will be prompted to authenticate using your WebAuthn security key or platform authenticator (e.g., YubiKey, Touch ID, Windows Hello).

## Features

### 1. Projects View

The portal displays all projects you have been granted access to by an administrator.

**For each project, you can see:**
- Project name and description
- Your privilege level (1-10)
  - **Level 1-2** (Blue): Administrative access
  - **Level 3-5** (Green): Standard user access
  - **Level 6-10** (Orange): Limited/read-only access
- Project status (active/inactive)

**Note:** You cannot create or modify projects through the portal. Contact your administrator to request access to additional projects.

### 2. Security Key Management

Manage all your WebAuthn credentials (security keys, passkeys, biometrics) from the portal.

#### Viewing Your Keys

The **Security Keys** section shows:
- Key label (custom name you assigned)
- Status (active/inactive)
- Creation date
- Last used timestamp
- Current session indicator (if you logged in with this key)

#### Adding a New Key

To add an additional security key:

1. Click the **"+ Add Key"** button
2. Enter a descriptive label (e.g., "YubiKey 5", "iPhone Touch ID", "Work Laptop")
3. Click **"Register Key"**
4. Follow your browser's prompts to touch/interact with your security device
5. The new key will appear in your list

**Why add multiple keys?**
- Backup in case you lose a key
- Different keys for different devices (laptop, phone, tablet)
- Separate work and personal keys

#### Removing a Key

To remove an unused security key:

1. Find the key in your list
2. Click the **"Delete"** button
3. Confirm the deletion

**Important restrictions:**
- ❌ You **cannot** delete the key you used to log in to the current session
- ❌ You must have at least one remaining key after deletion
- ⚠️ Deletion is permanent and cannot be undone

### 3. Account Information

View your account details:
- **User UUID**: Your unique identifier across all projects
- **Display Label**: Your human-readable username/email
- **Account Status**: Active/inactive
- **Account Created**: When your account was created

## Security Best Practices

### Managing Multiple Keys

**Recommended setup:**
- **Primary key**: Your main security key (YubiKey, etc.)
- **Backup key**: A second physical key stored securely
- **Platform authenticator**: Touch ID, Face ID, or Windows Hello as a convenience option

**Why multiple keys?**
- If you lose your primary key, you can still access your account
- Use different keys for different security contexts
- Maintain access if a key is damaged or lost

### Key Naming

Choose clear, descriptive names:
- ✅ Good: "YubiKey 5 NFC - Office", "iPhone 13 Touch ID", "Backup Key - Home Safe"
- ❌ Bad: "Key 1", "My Key", "Test"

Clear names help you identify which key to remove if compromised.

### When to Remove Keys

Remove keys if:
- You've lost or misplaced the physical key
- The device is no longer in your possession
- You suspect the key may be compromised
- You're replacing an old key with a new one

**Important:** Always ensure you have at least one working key before removing others.

## Frequently Asked Questions

### Can I manage OAuth clients from the portal?

No. OAuth client management is restricted to administrators through the admin panel. The portal is for managing your personal account and security keys only.

### Can I view other users or their projects?

No. The portal only shows your own projects and security keys. You cannot see information about other users.

### Can I change my privilege level in a project?

No. Privilege levels are set by project administrators. Contact your administrator to request a privilege level change.

### What happens if I delete all my keys by accident?

If you delete your last key, you will lose access to your account. Contact your system administrator to have them add a new key for you through the admin panel.

**Best practice:** Always maintain at least 2 keys (primary + backup).

### Can I use the same key across multiple accounts?

Yes. WebAuthn keys can be registered to multiple accounts across different services. You can use the same YubiKey for your BlackWall account and other services.

### What types of authenticators are supported?

BlackWall supports any **FIDO2/WebAuthn** compatible authenticator:
- **Hardware keys**: YubiKey, Titan Security Key, Feitian
- **Platform authenticators**: Touch ID (Mac/iOS), Face ID (iOS), Windows Hello, Android biometrics
- **Passkeys**: iCloud Keychain, Google Password Manager

**Requirements:**
- Must support resident keys/discoverable credentials
- Must support ES256 or RS256 algorithms

### Why can't I log in with my key?

Common issues:
1. **Browser not supported**: Use a modern browser (Chrome, Edge, Firefox, Safari)
2. **Not HTTPS**: WebAuthn requires a secure connection
3. **Key not registered**: Make sure you completed the bootstrap or registration process
4. **Wrong domain**: Keys are domain-specific; you must use https://blackwall.dixon.cx

### How do I log out?

Click the **"Logout"** button in the top-right corner of the portal. This will end your session and require re-authentication to access the portal again.

### Is my session shared with the admin panel?

No. Portal sessions and admin panel sessions are separate. Logging into the portal does not grant access to the admin panel, and vice versa.

## Audit Trail

All portal actions are logged:
- Login attempts (successful and failed)
- Security key additions
- Security key deletions
- Logout events

Administrators can view these events in the admin audit log. This provides accountability and helps investigate security incidents.

## Getting Help

If you:
- Cannot log in
- Have lost all your security keys
- Need access to a new project
- Need your privilege level changed
- Have other account issues

**Contact your system administrator** for assistance.

## Technical Details

### WebAuthn Security

BlackWall uses industry-standard **FIDO2/WebAuthn** with:
- ✅ Full COSE cryptographic signature verification
- ✅ Challenge-response authentication (prevents replay attacks)
- ✅ Origin binding (prevents phishing)
- ✅ Attestation verification
- ✅ Sign counter tracking (detects cloned keys)

Your private keys **never leave your security device**. Authentication is performed through cryptographic challenges, making it resistant to phishing, credential stuffing, and password database breaches.

### Privacy

The portal does not collect or display:
- Your browser fingerprint
- Detailed device information
- Location data
- Keystroke patterns

Only essential security information is logged:
- IP address (for security)
- User agent (for compatibility)
- Timestamp (for auditing)
- Action performed (for accountability)

---

**BlackWall User Portal** - Simple, secure account management
