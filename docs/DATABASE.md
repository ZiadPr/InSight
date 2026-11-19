# Database Design, Retention Policy & Benchmarks (InSight / ان سايت)

> **Official Runtime Storage (`ADR-001` / `ADR-002`):** The official Express runtime (`server.ts`) uses **embedded SQLite via `better-sqlite3`** (`data/attendance.db`) in **WAL mode (`PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`)** with **`0o600` POSIX permissions** and **column-level AES-256-GCM encryption** keyed by `DATA_ENCRYPTION_KEY`.
>
> Every check-in/check-out (`/api/attendance/scan`) executes inside a single atomic SQLite transaction updating **only** the consumed QR token, inserting/updating **only** the single affected `attendance_records` row, and appending **one** audit row — eliminating full-database serialization and rewrite overhead.

---

## 1. Official Express SQLite Schema (`server/sqliteStore.ts`)

| Table | Purpose & Key Constraints | Sensitive Encrypted Columns (`AES-256-GCM`) |
| --- | --- | --- |
| `system_secrets` | Cryptographic keys & HMAC/salt secrets (`auth_secret`, `kiosk_salt`, `ip_salt`, `signing_private_pem`) + public SPKI key | `value` (`is_encrypted = 1` for all secrets) |
| `company_settings` | Geofence center, radius, QR TTL, work hours, grace period, and QR capture schedule (`qr_window_start`, `qr_cutoff_time`, `qr_reappear_time`, `qr_window_end`) | — |
| `security_policy` | Cloudflare Free WAF (`cloudflare_enabled`, `allowed_countries_json`, `max_cf_threat_score`), Turnstile site key, strict IP binding, HTTP guards | — |
| `rbac_roles` | Persistent DB role definitions (`super_admin`, `hr_manager`, `attendance_supervisor`, `security_auditor`) | — |
| `users` | Employees, HR admins, and Kiosk auth principals (`email UNIQUE COLLATE NOCASE`, `employee_number UNIQUE`, `token_version`) | `mfa_secret_enc` (TOTP RFC 6238 secret encrypted at rest) |
| `kiosk_devices` | Multiple authorized reception terminals (`auth_user_id UNIQUE`, `secret_hash`, `revoked_before`, `last_seen_at`) | `secret_hash` (salted SHA-256) |
| `qr_tokens` | Ephemeral QR & 8-char manual fallback tokens (`token_hash UNIQUE`, `status` `active\|consumed\|expired\|revoked`) | Only `token_hash` & `manual_code_hash` stored |
| `attendance_records` | Daily attendance ledger enforcing **1 row per employee per day** (`UNIQUE (employee_id, attendance_date)`) & `qr_token_id UNIQUE` | `gps_meta_enc` (encrypted distance metadata; plaintext `distance_m` stored as `NULL`) |
| `active_sessions` | Active session ledger (`jti PRIMARY KEY`, `aal`, `ua_hash`, idle & absolute expiry) | HMAC-bound `ua_hash` & `ip_hash` |
| `revoked_jtis` | Immediate JTI revocation denylist until token expiry | — |
| `security_logs` | Security & attendance audit trail (with `created_at` & `(event_type, ip_hash, created_at)` indexes) | Salted HMAC `ip_hash` only |
| `security_alerts` | Structured high/critical SIEM alerts | Salted HMAC `ip_hash` only |

### Critical Performance Indexes
- `idx_attendance_emp_date` (`UNIQUE` on `attendance_records(employee_id, attendance_date)`) — accelerates per-employee history (`GET /api/attendance/me`) and scan conflict detection.
- `idx_attendance_date` (`attendance_records(attendance_date)`) — accelerates daily HR dashboard aggregates (`getTodayStats`) and date-range CSV exports (`/api/hr/export`).
- `idx_attendance_emp_idempotency` (`attendance_records(employee_id, idempotency_key)`) — O(log N) duplicate scan suppression.
- `idx_qr_tokens_kiosk_status` (`qr_tokens(kiosk_device_id, status)`), `idx_qr_tokens_manual` (`qr_tokens(manual_code_hash)`), `idx_qr_tokens_issued` (`qr_tokens(issued_at)`).
- `idx_security_logs_created` & `idx_security_logs_anomaly` (`security_logs(event_type, ip_hash, created_at)`).

---

## 2. Micro-Benchmark Results (Task 02)

Measured via `npm test` (`tests/storage/sqlite-storage.test.ts` — `better-sqlite3` WAL + synchronous per-record AES-256-GCM encryption on `gps_meta_enc`):

| Workload | Measured Result | Notes |
| --- | --- | --- |
| **10,000 sequential individual `attendance_records` writes** (100 employees × 100 days, each encrypted + WAL committed) | **1,006.1 ms** (~9,940 writes/sec) | Sub-millisecond per scan (~0.10 ms/write average) |
| **First 1,000 writes latency (`0 → 1,000` rows)** | **144.9 ms** | Cold cache baseline |
| **Final 1,000 writes latency (`9,000 → 10,000` rows)** | **90.6 ms** | **Zero linear degradation** as DB grows |
| **Indexed point lookup + `getTodayStats` across 10,000+ rows** | **0.88 ms** | Uses `idx_attendance_emp_date` & `idx_attendance_date` |

---

## 3. Legacy Encrypted JSON → SQLite Migration

Upgrading an existing deployment from legacy `data/attendance-db.enc` to `data/attendance.db`:
1. **Automatic on Startup:** If `data/attendance.db` does not exist on boot while `data/attendance-db.enc` is present, `server.ts` automatically creates a timestamped `data/attendance-db.enc.bak-<timestamp>` backup and imports all users, settings, kiosks, records, and logs atomically into SQLite.
2. **Manual CLI Tool:** Run before cutover (or in maintenance windows) with automatic pre-migration backup:
   ```bash
   npm run migrate:sqlite
   # Optional explicit paths:
   tsx scripts/migrate-json-db-to-sqlite.ts --input data/attendance-db.enc --output data/attendance.db
   ```

---

## 4. Automated Retention Cleanup
`store.cleanupExpiredAndAgedData()` runs on startup and every 6 hours inside a single transaction:
- Deletes expired `revoked_jtis` and expired `active_sessions`.
- Marks overdue `active` `qr_tokens` as `expired` and deletes tokens older than **7 days**.
- Deletes `security_logs` and `security_alerts` older than **90 days**.
- Scrubs `gps_meta_enc = NULL` and `distance_m = NULL` on `attendance_records` older than **90 days** while preserving attendance dates and status.

---

## 5. Archived Reference Schema Overview (`examples/optional-supabase-mode/`)

> Reference only (`ADR-001`). Not connected to the official Express runtime or frontend.

1. **`public.profiles`**, **`public.campus_settings`**, **`public.kiosk_devices`**, **`public.study_calendar`**, **`public.qr_tokens`**, **`public.attendance_records`**, **`public.security_logs`**, **`public.rate_limits`**, **`public.rbac_roles`**, **`public.user_permissions`** (migrations `0001`–`0007`).
