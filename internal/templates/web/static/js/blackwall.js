// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

// BlackWall front-end utilities. Exposed as a single global so the inline
// scripts in admin/login, portal/login, bootstrap/enroll, oauth/login,
// portal/dashboard, and enroll templates have one well-known namespace
// rather than open-coding base64url translation in every page.
(function (global) {
    'use strict';

    // ── base64url ↔ raw bytes ─────────────────────────────────────────────
    // WebAuthn ferries challenges, credential IDs, signatures, etc. as
    // base64url-encoded strings (RFC 4648 §5, padding stripped). The browser
    // API itself uses ArrayBuffer / Uint8Array, so every login + enrolment
    // page needs to translate in both directions.

    // base64urlDecode(s) → Uint8Array
    // Accepts both base64url ("-_", no padding) and ordinary base64; we
    // normalise on entry so server output in either form just works.
    function base64urlDecode(input) {
        if (input == null) {
            throw new Error('base64urlDecode: input required');
        }
        var s = String(input).replace(/-/g, '+').replace(/_/g, '/');
        // Re-pad to a multiple of 4. atob() rejects unpadded input on some
        // older engines we still care about (older Safari, embedded
        // WebViews).
        var pad = s.length % 4;
        if (pad === 2) { s += '=='; }
        else if (pad === 3) { s += '='; }
        else if (pad === 1) {
            throw new Error('base64urlDecode: invalid input length');
        }

        var raw = atob(s);
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) {
            out[i] = raw.charCodeAt(i);
        }
        return out;
    }

    // base64urlEncode(buf) → string (no padding, URL-safe alphabet).
    // Accepts ArrayBuffer, Uint8Array, or anything iterable as bytes.
    function base64urlEncode(buffer) {
        var bytes;
        if (buffer instanceof ArrayBuffer) {
            bytes = new Uint8Array(buffer);
        } else if (ArrayBuffer.isView(buffer)) {
            bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        } else {
            bytes = new Uint8Array(buffer);
        }

        // btoa works on a binary string, not a byte array. Chunk so very
        // large payloads (signed clientDataJSON) don't blow the argument
        // limit on String.fromCharCode.
        var binary = '';
        var chunk = 0x8000;
        for (var i = 0; i < bytes.length; i += chunk) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }

        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    // ── small UI helpers ─────────────────────────────────────────────────

    // showError(target, message) — toggles a Bootstrap alert into the
    // matching slot. The templates use `<div id="error" class="alert"
    // style="display:none"></div>`; this is a tiny convenience wrapper so
    // the inline scripts don't reach for jQuery.
    function showError(target, message) {
        var el = typeof target === 'string' ? document.getElementById(target) : target;
        if (!el) { return; }
        el.textContent = message;
        el.style.display = '';
    }

    // hideError(target) — symmetric counterpart to showError.
    function hideError(target) {
        var el = typeof target === 'string' ? document.getElementById(target) : target;
        if (!el) { return; }
        el.textContent = '';
        el.style.display = 'none';
    }

    global.BlackWall = {
        base64urlDecode: base64urlDecode,
        base64urlEncode: base64urlEncode,
        showError: showError,
        hideError: hideError,
    };
})(typeof window !== 'undefined' ? window : this);
