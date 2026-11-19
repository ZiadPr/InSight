# Deploying InSight on Netlify

The Vite frontend is published from `dist`. Netlify Server runs the same Express application for `/api/*` through `netlify/server/index.mjs`; uploading the frontend alone does not provide login or attendance endpoints. Node.js 24 is selected by `.node-version`.

On Netlify, employee accounts, attendance, kiosks, security settings, sessions, revocations, and login lockouts live in Netlify Database. Local development and self-hosted installations retain the existing SQLite implementation. No local database file is used as storage on Netlify.

## Initial configuration

Configure these server environment variables in production and deploy previews before the first server startup:

- `ADMIN_BOOTSTRAP_EMAIL`: a valid email address for the initial administrator.
- `ADMIN_BOOTSTRAP_PASSWORD`: 12–128 characters, including Latin letters and numbers. Keep it secret.

Bootstrap account values initialize an empty database. The bootstrap password also provides stable server-only encryption key material through scrypt when no dedicated encryption key is configured. Keep this environment secret unchanged after initialization; change account passwords through the application instead. Changing the bootstrap password later does not reset the administrator's password and would prevent decryption of existing records.

Before first initialization, deployments may alternatively configure `DATA_ENCRYPTION_KEY` with a securely generated 64-character hexadecimal key. When present, this dedicated key takes precedence and must remain stable. Do not add, remove, or replace it after initialization without re-encrypting existing data. Preview databases copied from production require the same key material. No development demo account is enabled in production. Create or rotate reception terminal accounts and secrets from the HR dashboard.

The schema is defined in `db/schema.ts`; versioned migrations live in `netlify/database/migrations`. Netlify applies the migrations during deployment. Repository transactions use a PostgreSQL advisory lock to retain the original single-writer behavior, and check-in transactions commit the consumed token, attendance record, and audit event together.

## After deployment

Open `/login` and sign in with the configured administrator account. Enroll administrator MFA when prompted. Configure the workplace location, timezone, and reception terminal in the HR dashboard, then enable attendance. Attendance starts disabled because the default office coordinates must be reviewed first.

`GET /api/health` should return JSON with `ok: true` and `storage_engine: "netlify-postgres"`. `/login`, `/employee`, `/employee/scan`, `/hr`, and `/kiosk` should load directly and survive browser refreshes. The frontend rewrite rules are deliberately limited to page routes so `/api/*` reaches the server.

The supplementary encrypted transport performs a new handshake after a server restart. Its temporary channels and pending MFA enrollment challenges can expire; completed enrollments and login sessions are persisted in PostgreSQL. Scheduled maintenance is not implemented with background timers; expired data is cleaned when the server starts and relevant expiry checks remain enforced on requests.

## Verification

Run `npm test`, `npm run lint`, and `npm run check:licenses`. The PostgreSQL integration test uses an isolated embedded PostgreSQL instance, applies the migration files there, and verifies encrypted data, atomic QR consumption and rollback, session revocation, and durable login lockouts. It never changes the hosted database.
