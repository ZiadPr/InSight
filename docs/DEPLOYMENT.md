# Deployment & Operations Runbook (InSight / ان سايت)

> For Netlify hosting, follow [the Netlify deployment guide](NETLIFY.md). The local SQLite storage and persistent-volume requirements below apply to self-hosted deployments.

## 1. Prerequisites & Single-Node Scaling Boundary
- **Single-Node Deployment Model (Instance واحد فقط):** Per [`docs/DECISIONS.md`](DECISIONS.md) (`ADR-001` & `ADR-002`), the official `server.ts` runtime stores data in an embedded **SQLite WAL** database (`data/attendance.db`) with column-level AES-256-GCM encryption and maintains ephemeral ECDH transport channels in process memory. Deploy **strictly 1 active instance** (`replicas = 1` / `max-instances = 1`) backed by a persistent local SSD volume mounted at `/app/data`.
- Multi-instance horizontal scaling is **not supported** with local SQLite; organizations requiring multi-node active-active clusters must adopt a shared external PostgreSQL database + distributed Redis store (`examples/optional-supabase-mode/` reference).
- Hardened Node.js 22+ container/host running `server.ts` behind an HTTPS reverse proxy / load balancer (TLS 1.2/1.3).
- Secret Manager / KMS injecting runtime environment variables (never store secrets in Git or `.master.key` alongside DB backups).

## 2. Production Environment Checklist
Configure all secrets before setting `NODE_ENV=production`:
1. `DATA_ENCRYPTION_KEY`: `openssl rand -hex 32` (64 hex chars). Mandatory in production (keys column-level AES-256-GCM secrets, TOTP secrets, and GPS metadata).
2. `ADMIN_BOOTSTRAP_EMAIL` & `ADMIN_BOOTSTRAP_PASSWORD` (strong password >= 12 chars) for initial database creation.
3. `KIOSK_BOOTSTRAP_SECRET` (high-entropy secret >= 16 chars).
4. `REQUIRE_ADMIN_MFA="true"` (default in production).
5. `TRUST_PROXY`: Set strictly to your reverse proxy CIDR or hop count (e.g., `loopback` or `10.0.0.0/8`). Test that direct spoofed `X-Forwarded-For` headers are ignored.
6. `ALLOWED_ORIGINS`: Exact HTTPS frontend origin(s).
7. `REDIS_REST_URL` & `REDIS_REST_TOKEN` (optional persistent rate-limit store).
8. `ALERT_WEBHOOK_URL`: SIEM / Slack / PagerDuty webhook for real-time security alerts.

## 3. Upgrading Legacy Encrypted JSON (`attendance-db.enc`) & Archived Reference Note (ADR-001)
- **Upgrading from pre-Task-02 versions:** Run `npm run migrate:sqlite` before starting the new server (or let `server.ts` auto-migrate on first boot) — this creates an automatic `.bak-<timestamp>` copy of `data/attendance-db.enc` and writes `data/attendance.db`. See [`docs/DATABASE.md`](DATABASE.md) for schema and benchmark details.
- **Archived Supabase Reference:** Per [`docs/DECISIONS.md`](DECISIONS.md), `examples/optional-supabase-mode/` contains archived PostgreSQL migrations (`0001`–`0007`) as a non-wired architectural reference only.

## 4. Automated Vulnerability, Supply Chain & CI Verification (DevSecOps)
All release verification checks below run **automatically as blocking gates** on every Pull Request and `main` push via [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (with weekly automated security dependency PRs managed via [`.github/dependabot.yml`](../.github/dependabot.yml)):

1. **Dependency Vulnerability Gate:** `npm ci && npm audit --audit-level=high` (fails automatically on any high or critical CVE).
2. **License Compliance Check:** `npm run check:licenses` verifies third-party dependencies comply with permissive MIT-compatible licensing.
3. **Secret Scanning (Gitleaks):** Separate `secret-scan` job scans full commit history using `.gitleaks.toml` (allowing empty `.env.example` templates only).
4. **SAST Static Security Analysis (CodeQL):** Separate `codeql-sast` job analyzes JavaScript/TypeScript security logic (`server.ts`, `server/`, `src/`, `scripts/`, and archived Edge Functions via `.github/codeql/codeql-config.yml`).
5. **Type Check, Production Build & Bundle Secret Guard:** Runs `npm run lint`, `npm run build`, `npm run check:bundle` (confirms zero demo credentials or server secret identifiers inside `dist/`), and `node --check server.ts`.
6. **Automated Tests & CycloneDX SBOM Artifact:** Executes `npm test` and generates `sbom.cdx.json` via `npm run sbom`, uploading the CycloneDX SBOM as a workflow artifact (`retention-days: 90`) on every `main` run.

For local pre-push verification before opening a PR, run:
```bash
npm ci
npm run audit:ci
npm run check:licenses
npm run lint
npm run build
npm run check:bundle
npm test
```

## 5. Encrypted Backup & Restore Verification (RPO / RTO)
- **Backup:** Use **HR Console > Security > Export Encrypted Backup** (`POST /api/hr/security/backup`) with a separate offline backup passphrase. Store backup files in separate immutable object storage from `DATA_ENCRYPTION_KEY`.
- **Restore Drill (Quarterly):** Verify restore into an isolated staging environment and record measured RPO (target <= 24h) and RTO (target <= 1h).

## 6. Nightly Cleanup & Audit Archiving
Migration `0006` upgrades `public.cleanup_security_and_expired_data(90)` to archive aged `security_logs` and `admin_access_audit` rows into `public.security_audit_archive` prior to pruning, purge expired `user_sessions`, and scrub raw GPS coordinates older than 90 days.
