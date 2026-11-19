# Security Architecture & Audit Controls (InSight / ان سايت)

## 1. Transport Layer Security & Authenticated Application Payload Encryption
- **HTTPS / TLS 1.2+ Mandatory in Production:** The application-layer encrypted channel (`ECDH P-256 + HKDF-SHA256 + AES-256-GCM`) is a **defense-in-depth layer only** and NEVER replaces HTTPS/TLS. In `NODE_ENV=production`, the Express server enforces HTTPS (`REQUIRE_HTTPS=true`), sets `Strict-Transport-Security` (HSTS), and rejects plain HTTP requests (`426 HTTPS_REQUIRED`).
- **Signed Handshake Identity:** `POST /api/security/handshake` signs the full ECDH handshake transcript (`channel_id|server_public_key|client_public_key|client_nonce|expires_at`) using an **ECDSA P-256** server signing key (`GET /api/security/public-key`). The browser verifies this signature via WebCrypto and binds all subsequent requests via `X-Sec-Channel` + AEAD AAD (`channelId:METHOD:pathname`).
- **Strict Security Headers:** Helmet enforces `Content-Security-Policy` (`default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'` in production), `frameguard: deny` in production, `Permissions-Policy: camera=(self), geolocation=(self), microphone=()`, and `Cache-Control: no-store` on all `/api/*` responses.

## 2. Key Management & Column-Level At-Rest Encryption
- **Production KMS Key Enforcement:** In `NODE_ENV=production`, `DATA_ENCRYPTION_KEY` (64-hex chars from KMS/Secret Manager) is **mandatory**. Sensitive columns in `data/attendance.db` (SQLite WAL with `0o600` file permissions) — including `system_secrets` (`auth_secret`, `kiosk_salt`, `ip_salt`, `signing_private_pem`), `users.mfa_secret_enc`, and `attendance_records.gps_meta_enc` (with plaintext `distance_m` kept `NULL`) — are encrypted via **AES-256-GCM** using `DATA_ENCRYPTION_KEY`.
- **Backup Isolation:** Admin encrypted backups (`POST /api/hr/security/backup`) encrypt database state with a separate admin-supplied passphrase (PBKDF2 + AES-256-GCM) and never export `DATA_ENCRYPTION_KEY` or `.master.key`.
- **Zero Default Credentials in Production:** Production startup fails closed against active default/demo passwords (`assertNoDefaultCredentialsInProduction`), and Vite tree-shakes all demo shortcuts behind `import.meta.env.DEV`.

## 3. Authentication, TOTP MFA, & Session Lifecycle Policy
- **RFC 6238 TOTP MFA:** HR Admin accounts support TOTP authenticator enrollment (`/api/hr/security/mfa/enroll` & `/activate`) with AES-256-GCM encrypted secret storage and replay protection (`last_used_totp_step`). When `REQUIRE_ADMIN_MFA=true` (default in production), sensitive HR endpoints enforce `aal = 'aal2'` and Step-Up verification.
- **Explicit Session Lifecycle:**
  - **Admin:** 15-minute server-side idle timeout, 2-hour absolute max lifetime, max **1** concurrent session.
  - **Employee:** 60-minute idle timeout, 8-hour absolute max lifetime, max **2** concurrent sessions.
  - **Kiosk:** 12-hour lifetime, max **1** concurrent session.
- **Immediate Revocation:** Logout, password change, account deactivation, concurrent eviction, and HR emergency lockdown revoke active `jti` entries in `db.active_sessions` and increment `token_version`.
- **UA Binding & Step-Up Auto-Lock:** Session JWTs, `X-Sec-Channel`, and 15-minute `X-Admin-StepUp` tokens are bound to `User-Agent` hash; HR Console locks after 5 minutes of client idle inactivity.

## 4. Network, Rate Limiting, & WAF Controls
- **Trusted Proxy Configuration:** Express `trust proxy` uses `TRUST_PROXY` env configuration (defaulting to `false` in production unless configured) and `req.ip` rather than trusting arbitrary `X-Forwarded-For` headers.
- **Distributed Rate Limiting:** Supports Redis REST (`REDIS_REST_URL` + `REDIS_REST_TOKEN`) for multi-instance deployments (with `REQUIRE_DISTRIBUTED_RATE_LIMIT=true` fail-closed mode), bounded in-memory sliding windows, and per-endpoint limits (including 15/hour export limit).
- **Resource & Export Caps:** `64kb` JSON limit, `15s` request timeout, `366`-day max date window, `50,000`-row export cap, CSV formula injection neutralization, SQLi/XSS WAF inspection, Zod `.strict()`, and generic error responses with correlation `X-Request-Id`.

## 5. Immutable Audit Logging, Alerting, Privacy, & Anti-Fraud
- **Append-Only Audit Trails:** Production Express logging records `security_logs` and `security_alerts` with 90-day retention pruning and raw GPS scrubbing. The archived PostgreSQL/Supabase SQL reference (`examples/optional-supabase-mode/migrations/202611170006_production_hardening.sql`) additionally defines `public.is_aal2_mfa()`, immutable `admin_access_audit` triggers, and `security_audit_archive`.
- **Real-Time Alerting:** Brute-force lockouts, Step-Up failures, WAF SQLi/XSS blocks, attendance anomalies (e.g., multiple employees checking in from the same IP/UA within 120s), and global revocations emit structured alerts and optional webhooks (`ALERT_WEBHOOK_URL`).
- **Privacy & GPS Limitation:** Geolocation is sampled solely at check-in/out with explicit user notice and scrubbed after 90 days. Browser GPS alone cannot prevent spoofing on compromised devices; combine with physical/network controls and HR anomaly review.

## 6. Supported Architecture & Security Parity Matrix (ADR-001)
Per [`docs/DECISIONS.md`](DECISIONS.md), the **Self-Hosted Express Server (`server.ts`)** is the **single official runtime backend** wired to the frontend. The legacy `supabase/` artifacts remain archived in `examples/optional-supabase-mode/` as a non-equivalent reference only:

| Security / Functional Control | Official Express Backend (`server.ts`) | Archived Supabase Reference (`examples/optional-supabase-mode/`) |
| --- | :---: | :---: |
| Mandatory HTTPS / HSTS in Production | Supported (`REQUIRE_HTTPS=true`) | Managed at Supabase Edge |
| Application-Layer E2EE (`ECDH P-256 + ECDSA + AES-256-GCM`) | Supported & enforced on `/api/*` | Not implemented |
| Data-at-Rest AES-256-GCM + `DATA_ENCRYPTION_KEY` | Supported (SQLite WAL `attendance.db` + encrypted secrets, TOTP & GPS columns) | Managed Postgres disk encryption |
| HR Admin Step-Up + TOTP MFA (`AAL2`) | Supported & enforced | SQL helper only (not wired to UI) |
| Granular DB RBAC (`super_admin`, `hr_manager`, etc.) | Supported & editable in HR Console | Schema migration `0007` only |
| Multi-Kiosk Devices & Scheduled QR Capture Window | Supported in API & UI | SQL helper only |
| Cloudflare WAF (`CF-IPCountry`, `CF-Threat-Score`) & Turnstile | Supported | Not supported |
| SQLi/XSS/HPP/Method-Override & Strict Proxy-Aware CORS | Supported | Partial (Edge Functions only) |

## 7. Automated DevSecOps Pipeline Gates (`.github/workflows/ci.yml`)
- **Blocking Dependency Audit:** Every PR and push runs `npm audit --audit-level=high` against `package-lock.json`.
- **Automated Dependency & Security PRs:** `.github/dependabot.yml` checks `npm` and `github-actions` weekly for security patches.
- **Secret Scanning & SAST:** Dedicated CI jobs run **Gitleaks** (`.gitleaks.toml`) on full commit history and **CodeQL** (`.github/codeql/codeql-config.yml`, `security-extended` + `security-and-quality`) covering `server.ts`, `server/`, `src/`, `scripts/`, and archived Edge Functions.
- **Supply Chain & Build Hygiene:** Every `main` build publishes a **CycloneDX SBOM** artifact, verifies SPDX license compliance (`scripts/check-licenses.ts`), and scans compiled `dist/` bundles (`scripts/check-bundle-secrets.ts`) to ensure zero secret or demo-credential leakage.

