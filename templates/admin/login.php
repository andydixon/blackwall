<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login — BlackWall</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg:           #0b0d12;
            --surface:      #13161e;
            --border:       rgba(255,255,255,0.08);
            --accent:       #3b82f6;
            --accent-glow:  rgba(59,130,246,0.3);
            --text:         #e5e7eb;
            --muted:        #6b7280;
            --danger:       #ef4444;
        }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            background-image: radial-gradient(ellipse 80% 60% at 50% 0%, rgba(59,130,246,0.07) 0%, transparent 70%);
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }

        .wrap {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 400px;
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2.5rem 2rem;
            box-shadow:
                0 0 0 1px rgba(255,255,255,0.03),
                0 20px 60px rgba(0,0,0,0.5),
                0 0 80px var(--accent-glow);
        }

        .logo-wrap {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo-wrap img {
            height: 52px;
            filter: brightness(0) invert(1);
            opacity: 0.9;
            margin-bottom: 0.75rem;
        }

        .logo-wrap .wordmark {
            font-size: 1rem;
            font-weight: 600;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--muted);
        }

        .divider {
            height: 1px;
            background: var(--border);
            margin: 0 -2rem 2rem;
        }

        .admin-label {
            text-align: center;
            margin-bottom: 1.75rem;
        }

        .admin-label h1 {
            font-size: 1.125rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }

        .admin-label p {
            font-size: 0.875rem;
            color: var(--muted);
        }

        .error-box {
            background: rgba(239,68,68,0.08);
            border: 1px solid rgba(239,68,68,0.25);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            font-size: 0.875rem;
            color: #fca5a5;
            margin-bottom: 1.25rem;
            display: none;
        }

        .btn-auth {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.625rem;
            width: 100%;
            padding: 0.875rem 1.5rem;
            background: var(--accent);
            color: #fff;
            font-size: 0.9375rem;
            font-weight: 600;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
            box-shadow: 0 4px 20px rgba(59,130,246,0.3);
        }

        .btn-auth:hover:not(:disabled) {
            background: #2563eb;
            box-shadow: 0 6px 28px rgba(59,130,246,0.45);
            transform: translateY(-1px);
        }

        .btn-auth:active:not(:disabled) { transform: translateY(0); }
        .btn-auth:disabled { opacity: 0.7; cursor: not-allowed; }

        .icon-fp {
            width: 22px; height: 22px; flex-shrink: 0;
        }

        .spinner {
            width: 18px; height: 18px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            flex-shrink: 0;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        .hint {
            text-align: center;
            margin-top: 1.25rem;
            font-size: 0.8125rem;
            color: var(--muted);
            line-height: 1.5;
        }

        .footer {
            text-align: center;
            margin-top: 1.5rem;
            font-size: 0.8rem;
            color: var(--muted);
        }

        .security-note {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.375rem;
            margin-top: 0.75rem;
            font-size: 0.75rem;
            color: var(--muted);
            opacity: 0.7;
        }

        .security-note svg { flex-shrink: 0; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            <div class="logo-wrap">
                <img src="/assets/blackwall.svg" alt="BlackWall">
                <div class="wordmark">BlackWall</div>
            </div>
            <div class="divider"></div>

            <div class="admin-label">
                <h1>Administrator Access</h1>
                <p>Authenticate with your security key to continue</p>
            </div>

            <div class="error-box" id="error-message"></div>

            <button class="btn-auth" id="webauthn-login">
                <svg class="icon-fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/>
                    <path d="M14 13.12c0 2.38 0 6.38-1 8.88"/>
                    <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/>
                    <path d="M2 12a10 10 0 0 1 18-6"/>
                    <path d="M2 16h.01"/>
                    <path d="M21.8 16c.2-2 .131-5.354 0-6"/>
                    <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/>
                    <path d="M8.65 22c.21-.66.45-1.32.57-2"/>
                    <path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>
                </svg>
                Sign in with Security Key
            </button>

            <p class="hint">Touch your security key or use biometric authentication when prompted.</p>
        </div>

        <div class="footer">
            <div>BlackWall Authentication Service</div>
            <div class="security-note">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                WebAuthn · No passwords
            </div>
        </div>
    </div>

    <script>
        const csrfToken = <?= json_encode($csrfToken) ?>;
        const loginBtn  = document.getElementById('webauthn-login');
        const errorEl   = document.getElementById('error-message');
        let requestedRpId = null;

        const fpIcon = `<svg class="icon-fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>`;

        function setLoading(label) {
            loginBtn.disabled = true;
            loginBtn.innerHTML = `<div class="spinner"></div>${label}`;
        }

        function resetBtn(label = 'Try Again') {
            loginBtn.disabled = false;
            loginBtn.innerHTML = `${fpIcon}${label}`;
        }

        function base64ToArrayBuffer(b64) {
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes.buffer;
        }

        function arrayBufferToBase64(buf) {
            const bytes = new Uint8Array(buf);
            let bin = '';
            for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
            return btoa(bin);
        }

        loginBtn.addEventListener('click', async () => {
            errorEl.style.display = 'none';
            setLoading('Preparing…');

            try {
                const challengeResp = await fetch('/admin/login/challenge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ csrf_token: csrfToken })
                });

                const challengeData = await challengeResp.json();
                requestedRpId = challengeData.rpId || null;

                setLoading('Touch your security key…');

                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: base64ToArrayBuffer(challengeData.challenge),
                        timeout: challengeData.timeout,
                        rpId: challengeData.rpId,
                        userVerification: challengeData.userVerification
                    }
                });

                setLoading('Verifying…');

                const verifyResp = await fetch('/admin/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        csrf_token: csrfToken,
                        id: credential.id,
                        rawId: arrayBufferToBase64(credential.rawId),
                        type: credential.type,
                        response: {
                            authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                            clientDataJSON:    arrayBufferToBase64(credential.response.clientDataJSON),
                            signature:         arrayBufferToBase64(credential.response.signature),
                            userHandle:        credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
                        }
                    })
                });

                const verifyData = await verifyResp.json();

                if (verifyData.success) {
                    setLoading('Redirecting…');
                    window.location.href = verifyData.redirect || '/admin/dashboard';
                } else {
                    throw new Error(verifyData.error || 'Authentication failed');
                }

            } catch (err) {
                console.error(err);
                if (err?.name === 'SecurityError') {
                    const rp = requestedRpId || 'unknown';
                    errorEl.textContent = `WebAuthn domain mismatch: page host is ${window.location.hostname}, rpId is ${rp}.`;
                } else {
                    errorEl.textContent = err.message || 'Authentication failed. Please try again.';
                }
                errorEl.style.display = 'block';
                resetBtn();
            }
        });
    </script>
</body>
</html>
