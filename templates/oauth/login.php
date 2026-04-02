<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to <?= htmlspecialchars($clientName) ?></title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg:        #0b0d12;
            --surface:   #13161e;
            --border:    rgba(255,255,255,0.08);
            --accent:    #3b82f6;
            --accent-glow: rgba(59,130,246,0.35);
            --text:      #e5e7eb;
            --muted:     #6b7280;
            --danger:    #ef4444;
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
            /* Subtle radial gradient spotlight */
            background-image:
                radial-gradient(ellipse 80% 60% at 50% 0%, rgba(59,130,246,0.07) 0%, transparent 70%);
        }

        /* Faint grid overlay */
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
            max-width: 420px;
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

        /* Logo */
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

        .logo-wrap .bw-wordmark {
            font-size: 1rem;
            font-weight: 600;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--muted);
        }

        /* Divider */
        .divider {
            height: 1px;
            background: var(--border);
            margin: 0 -2rem 2rem;
        }

        /* Request info */
        .request-info {
            text-align: center;
            margin-bottom: 2rem;
        }

        .org-logo {
            max-height: 40px;
            margin-bottom: 0.75rem;
        }

        .request-info h1 {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.375rem;
            color: var(--text);
        }

        .request-info p {
            font-size: 0.875rem;
            color: var(--muted);
        }

        .client-tag {
            display: inline-block;
            background: rgba(59,130,246,0.12);
            border: 1px solid rgba(59,130,246,0.25);
            color: var(--accent);
            font-size: 0.8125rem;
            font-weight: 500;
            padding: 0.2em 0.75em;
            border-radius: 999px;
            margin-top: 0.5rem;
        }

        /* Error */
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

        /* Button */
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

        .btn-auth:active:not(:disabled) {
            transform: translateY(0);
        }

        .btn-auth:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }

        /* Fingerprint icon */
        .icon-fp {
            width: 22px;
            height: 22px;
            flex-shrink: 0;
        }

        /* Spinner */
        .spinner {
            width: 18px;
            height: 18px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            flex-shrink: 0;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        /* Hint */
        .hint {
            text-align: center;
            margin-top: 1.25rem;
            font-size: 0.8125rem;
            color: var(--muted);
            line-height: 1.5;
        }

        /* Footer */
        .footer {
            text-align: center;
            margin-top: 1.5rem;
            font-size: 0.8rem;
            color: var(--muted);
        }

        .footer a {
            color: var(--muted);
            text-decoration: none;
            transition: color 0.15s;
        }

        .footer a:hover { color: var(--text); }

        .footer .sep { margin: 0 0.5em; opacity: 0.4; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            <!-- BlackWall branding -->
            <div class="logo-wrap">
                <img src="/assets/blackwall.svg" alt="BlackWall">
                <div class="bw-wordmark">BlackWall</div>
            </div>
            <div class="divider"></div>

            <!-- Request context -->
            <div class="request-info">
                <?php if (!empty($organization) && !empty($organization->logoUrl)): ?>
                    <img src="<?= htmlspecialchars($organization->logoUrl) ?>" alt="<?= htmlspecialchars($organization->name) ?>" class="org-logo">
                <?php endif; ?>
                <h1>Sign in to continue</h1>
                <p>Authenticate to access</p>
                <span class="client-tag"><?= htmlspecialchars($clientName) ?></span>
            </div>

            <!-- Error -->
            <div class="error-box" id="error"></div>

            <!-- Auth button -->
            <button class="btn-auth" id="loginBtn">
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
            <?php if (!empty($organization)): ?>
                <?= htmlspecialchars($organization->name) ?><span class="sep">·</span>
            <?php endif; ?>
            Secured by <strong>BlackWall</strong><span class="sep">·</span>
            <a href="<?= htmlspecialchars($returnUrl) ?>">Cancel</a>
        </div>
    </div>

    <script>
        const csrfToken = <?= json_encode($csrfToken ?? '') ?>;
        const loginBtn = document.getElementById('loginBtn');
        const errorDiv = document.getElementById('error');

        function setLoading(label) {
            loginBtn.disabled = true;
            loginBtn.innerHTML = `<div class="spinner"></div>${label}`;
        }

        function resetBtn() {
            loginBtn.disabled = false;
            loginBtn.innerHTML = `<svg class="icon-fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>Try Again`;
        }

        loginBtn.addEventListener('click', async () => {
            try {
                errorDiv.style.display = 'none';
                setLoading('Preparing…');

                const challengeResp = await fetch('/oauth/login/challenge', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ csrf_token: csrfToken })
                });

                if (!challengeResp.ok) throw new Error('Failed to get challenge');
                const challengeData = await challengeResp.json();

                setLoading('Touch your security key…');

                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: Uint8Array.from(atob(challengeData.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        timeout: 60000,
                        rpId: window.location.hostname,
                        userVerification: 'required'
                    }
                });

                setLoading('Verifying…');

                const verifyResp = await fetch('/oauth/login/verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        csrf_token: csrfToken,
                        id: credential.id,
                        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                        type: credential.type,
                        response: {
                            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                            userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                        }
                    })
                });

                const verifyData = await verifyResp.json();

                if (verifyData.success) {
                    setLoading('Redirecting…');
                    window.location.href = verifyData.redirect;
                } else {
                    throw new Error(verifyData.error || 'Authentication failed');
                }
            } catch (err) {
                console.error(err);
                errorDiv.textContent = err.message || 'Authentication failed. Please try again.';
                errorDiv.style.display = 'block';
                resetBtn();
            }
        });
    </script>
</body>
</html>
