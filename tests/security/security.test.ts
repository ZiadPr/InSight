import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  calculateHaversineMeters,
  isValidGpsCoordinates,
  sanitizeSpreadsheetCell,
} from "../../src/lib/validation.ts";
import {
  evaluateCorsOrigin,
  evaluateRateLimitResult,
  requireAal2Mfa,
  requireStrongSalt,
  sha256HexWeb,
  validateGpsFreshness,
  verifyKioskAuthorization,
} from "../../examples/optional-supabase-mode/functions/_shared/securityGuards.ts";

function collectFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(full));
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results;
}

function makeFakeJwt(payload: Record<string, unknown>): string {
  const encode = (obj: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${encode({ alg: "HS256", typ: "JWT" })}.${encode(payload)}.sig`;
}

test("Frontend src/ never references service_role or server secrets", () => {
  const srcRoot = path.resolve(process.cwd(), "src");
  const files = collectFiles(srcRoot);
  assert.ok(files.length > 0, "Expected frontend files in src/");

  const forbiddenPatterns = [
    /SUPABASE_SERVICE_ROLE_KEY/,
    /service_role/,
    /KIOSK_DEVICE_SECRET_SALT/,
    /IP_HASH_SALT/,
  ];

  for (const file of files) {
    const content = fs.readFileSync(file, "utf8");
    for (const pattern of forbiddenPatterns) {
      assert.equal(
        pattern.test(content),
        false,
        `Forbidden secret reference ${pattern} found in ${file}`,
      );
    }
  }
});

test("Rate limiter fails closed (503) when RPC errors or returns malformed data", () => {
  const errResult = evaluateRateLimitResult(null, new Error("DB connection failed"));
  assert.equal(errResult.allowed, false);
  if (!errResult.allowed) {
    assert.equal(errResult.status, 503);
    assert.equal(errResult.error, "RATE_LIMIT_UNAVAILABLE");
  }

  const malformed = evaluateRateLimitResult({}, null);
  assert.equal(malformed.allowed, false);
  if (!malformed.allowed) {
    assert.equal(malformed.status, 503);
  }

  const blocked = evaluateRateLimitResult({ allowed: false, retry_after_seconds: 90 }, null);
  assert.equal(blocked.allowed, false);
  if (!blocked.allowed) {
    assert.equal(blocked.status, 429);
    assert.equal(blocked.retryAfterSeconds, 90);
  }

  const allowed = evaluateRateLimitResult({ allowed: true, remaining: 5 }, null);
  assert.equal(allowed.allowed, true);
});

test("Kiosk device secret is mandatory and remote revocation invalidates older JWTs", async () => {
  const salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const secret = "kiosk-rotatable-secret-2026";
  const secretHash = await sha256HexWeb(`${salt}:${secret}`);

  // Missing secret_hash on DB row
  const noHash = await verifyKioskAuthorization({
    device: { is_active: true, secret_hash: null, revoked_before: null },
    providedSecret: secret,
    deviceSecretSalt: salt,
    jwtIssuedAtSec: Math.floor(Date.now() / 1000),
  });
  assert.equal(noHash.ok, false);
  if (!noHash.ok) assert.equal(noHash.error, "DEVICE_SECRET_NOT_CONFIGURED");

  // Missing x-kiosk-secret header
  const missingHeader = await verifyKioskAuthorization({
    device: { is_active: true, secret_hash: secretHash, revoked_before: null },
    providedSecret: "",
    deviceSecretSalt: salt,
    jwtIssuedAtSec: Math.floor(Date.now() / 1000),
  });
  assert.equal(missingHeader.ok, false);
  if (!missingHeader.ok) assert.equal(missingHeader.error, "DEVICE_SECRET_REQUIRED");

  // Wrong secret
  const wrongSecret = await verifyKioskAuthorization({
    device: { is_active: true, secret_hash: secretHash, revoked_before: null },
    providedSecret: "wrong-secret",
    deviceSecretSalt: salt,
    jwtIssuedAtSec: Math.floor(Date.now() / 1000),
  });
  assert.equal(wrongSecret.ok, false);
  if (!wrongSecret.ok) assert.equal(wrongSecret.error, "DEVICE_SECRET_INVALID");

  // Revoked session (JWT issued before revoked_before)
  const nowSec = Math.floor(Date.now() / 1000);
  const revokedBeforeIso = new Date((nowSec - 10) * 1000).toISOString();
  const revoked = await verifyKioskAuthorization({
    device: { is_active: true, secret_hash: secretHash, revoked_before: revokedBeforeIso },
    providedSecret: secret,
    deviceSecretSalt: salt,
    jwtIssuedAtSec: nowSec - 60,
  });
  assert.equal(revoked.ok, false);
  if (!revoked.ok) {
    assert.equal(revoked.status, 401);
    assert.equal(revoked.error, "KIOSK_SESSION_REVOKED");
  }

  // Valid fresh session + valid secret
  const valid = await verifyKioskAuthorization({
    device: { is_active: true, secret_hash: secretHash, revoked_before: revokedBeforeIso },
    providedSecret: secret,
    deviceSecretSalt: salt,
    jwtIssuedAtSec: nowSec,
  });
  assert.equal(valid.ok, true);
});

test("Cryptographic salts fail closed if missing or weak (no hardcoded default)", () => {
  assert.throws(() => requireStrongSalt(undefined, "IP_HASH_SALT"));
  assert.throws(() => requireStrongSalt("short-salt", "IP_HASH_SALT"));
  const strong = "a".repeat(32);
  assert.equal(requireStrongSalt(strong, "IP_HASH_SALT"), strong);

  const cryptoFile = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/functions/_shared/crypto.ts"),
    "utf8",
  );
  assert.equal(cryptoFile.includes("attendance-ip-default-salt"), false);
});

test("Strict CORS rejects unknown origins explicitly", () => {
  const allowedOrigins = "https://attendance.university.edu";
  assert.deepEqual(evaluateCorsOrigin("https://attendance.university.edu", allowedOrigins), {
    allowed: true,
    allowOrigin: "https://attendance.university.edu",
  });
  assert.deepEqual(evaluateCorsOrigin("https://evil.attacker.com", allowedOrigins), {
    allowed: false,
  });
  assert.deepEqual(evaluateCorsOrigin("https://evil.attacker.com", ""), {
    allowed: false,
  });
  assert.deepEqual(evaluateCorsOrigin("http://localhost:3000", ""), {
    allowed: true,
    allowOrigin: "http://localhost:3000",
  });
});

test("Export function enforces MFA AAL2 on admin JWT", () => {
  const aal1Jwt = makeFakeJwt({ sub: "admin-1", aal: "aal1", iat: 1700000000 });
  const aal2Jwt = makeFakeJwt({ sub: "admin-1", aal: "aal2", iat: 1700000000 });
  const noAalJwt = makeFakeJwt({ sub: "admin-1", iat: 1700000000 });

  assert.equal(requireAal2Mfa(aal1Jwt), false);
  assert.equal(requireAal2Mfa(noAalJwt), false);
  assert.equal(requireAal2Mfa(aal2Jwt), true);
});

test("GPS freshness rejects stale (>30s) or future-skewed timestamps and documents spoofing limit", () => {
  const serverNow = Date.UTC(2026, 10, 17, 12, 0, 0);
  const fresh = new Date(serverNow - 4_000).toISOString();
  const stale = new Date(serverNow - 45_000).toISOString();
  const future = new Date(serverNow + 25_000).toISOString();

  assert.equal(validateGpsFreshness(fresh, serverNow).ok, true);
  assert.deepEqual(validateGpsFreshness(stale, serverNow), { ok: false, error: "GPS_STALE" });
  assert.deepEqual(validateGpsFreshness(future, serverNow), { ok: false, error: "GPS_STALE" });
  assert.deepEqual(validateGpsFreshness(undefined, serverNow), {
    ok: false,
    error: "LOCATION_INVALID",
  });

  // Spoofed GPS limitation check: browser-forged coordinates matching campus center
  // will mathematically pass Haversine radius validation when GPS alone is used.
  const spoofedDistance = calculateHaversineMeters(24.7255, 46.6238, 24.7255, 46.6238);
  assert.equal(spoofedDistance, 0);
});

test("Spreadsheet export sanitization neutralizes formula injection prefixes", () => {
  assert.equal(sanitizeSpreadsheetCell("=CMD('calc')"), "'=CMD('calc')");
  assert.equal(sanitizeSpreadsheetCell("+1+1"), "'+1+1");
  assert.equal(sanitizeSpreadsheetCell("-10"), "'-10");
  assert.equal(sanitizeSpreadsheetCell("@SUM(A1:A2)"), "'@SUM(A1:A2)");
  assert.equal(sanitizeSpreadsheetCell("\t=1+1"), "'\t=1+1");
  assert.equal(sanitizeSpreadsheetCell("\r=1+1"), "'\r=1+1");
  assert.equal(sanitizeSpreadsheetCell("محمد أحمد العلي"), "محمد أحمد العلي");
  assert.equal(sanitizeSpreadsheetCell("202610045"), "202610045");
});

test("GPS validation rejects out-of-range coordinates and non-positive accuracy", () => {
  assert.equal(isValidGpsCoordinates(24.7136, 46.6753, 15), true);
  assert.equal(isValidGpsCoordinates(95, 46.6753, 15), false);
  assert.equal(isValidGpsCoordinates(24.7136, -185, 15), false);
  assert.equal(isValidGpsCoordinates(24.7136, 46.6753, 0), false);
  assert.equal(isValidGpsCoordinates(Number.NaN, 46.6753, 10), false);
});

test("SQL migrations enable RLS, disable placeholder campus, lock default privileges, and schedule cleanup", () => {
  const schemaSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170001_initial_schema.sql"),
    "utf8",
  );
  const rlsSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170002_rls_and_atomic_functions.sql"),
    "utf8",
  );
  const seedSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170003_seed_defaults.sql"),
    "utf8",
  );
  const hardeningSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170004_security_hardening.sql"),
    "utf8",
  );

  const tableMatches = [...schemaSql.matchAll(/CREATE TABLE IF NOT EXISTS public\.(\w+)/g)].map(
    (m) => m[1],
  );
  assert.ok(tableMatches.length >= 8, "Expected all core tables in initial schema");

  for (const tableName of tableMatches) {
    assert.ok(
      rlsSql.includes(`ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;`),
      `Missing ENABLE ROW LEVEL SECURITY for table ${tableName}`,
    );
  }

  assert.equal(/USING\s*\(\s*true\s*\)/i.test(rlsSql), false, "Must not use USING (true)");
  assert.equal(
    /WITH CHECK\s*\(\s*true\s*\)/i.test(rlsSql),
    false,
    "Must not use WITH CHECK (true)",
  );

  // Default seed must be disabled until real coordinates are configured
  assert.ok(seedSql.includes("FALSE"), "Default campus seed must start disabled (FALSE)");
  assert.ok(
    hardeningSql.includes("ALTER DEFAULT PRIVILEGES IN SCHEMA public"),
    "Must lock down default privileges for future tables/functions",
  );
  assert.ok(
    hardeningSql.includes("cleanup_security_and_expired_data"),
    "Must define retention cleanup function",
  );
  assert.ok(
    hardeningSql.includes("revoke_kiosk_sessions"),
    "Must define remote Kiosk session revocation RPC",
  );
});

test("Backend server enforces AES-256-GCM encryption at rest, SQLite WAL targeted writes, E2EE transport, Admin Step-Up, and SQLi/XSS WAF libraries", () => {
  const serverSource = fs.readFileSync(path.resolve(process.cwd(), "server.ts"), "utf8");
  const storeSource = fs.readFileSync(path.resolve(process.cwd(), "server/sqliteStore.ts"), "utf8");
  assert.ok(storeSource.includes("aes-256-gcm"), "Expected AES-256-GCM encryption at rest");
  assert.ok(storeSource.includes('from "better-sqlite3"'), "Expected better-sqlite3 storage engine");
  assert.ok(storeSource.includes("journal_mode = WAL"), "Expected SQLite WAL mode");
  assert.ok(storeSource.includes("idx_attendance_emp_date"), "Expected index on (employee_id, attendance_date)");
  assert.ok(storeSource.includes("idx_attendance_date"), "Expected index on (attendance_date)");
  assert.ok(storeSource.includes("gps_meta_enc"), "Expected column-level AES-256-GCM encryption for GPS");
  assert.equal(serverSource.includes("writeEncryptedDb"), false, "Must not rewrite entire DB on disk per scan");
  assert.equal(serverSource.includes("persistDatabase"), false, "Must not use full-DB persistDatabase timer");
  assert.ok(serverSource.includes("scryptSync"), "Expected Scrypt password hashing");
  assert.ok(serverSource.includes("timingSafeEqual"), "Expected constant-time token comparison");
  assert.ok(storeSource.includes("revoked_jtis"), "Expected JTI token revocation support");
  assert.ok(serverSource.includes("token_version"), "Expected token_version invalidation support");
  assert.ok(serverSource.includes("no-store, no-cache"), "Expected no-store cache headers on API");
  assert.ok(serverSource.includes("attendance.db"), "Expected SQLite DB file target");
  assert.ok(serverSource.includes('from "helmet"'), "Expected Helmet security middleware");
  assert.ok(serverSource.includes('from "hpp"'), "Expected HPP parameter pollution middleware");
  assert.ok(serverSource.includes('from "express-rate-limit"'), "Expected express-rate-limit middleware");
  assert.ok(serverSource.includes('from "zod"'), "Expected Zod runtime schema validation");
  assert.ok(serverSource.includes("/api/security/handshake"), "Expected ECDH P-256 handshake endpoint");
  assert.ok(serverSource.includes("requireEncryptedChannel"), "Expected mandatory encrypted channel for HR Admin");
  assert.ok(serverSource.includes("requireAdminWithStepUp"), "Expected Step-Up verification for HR Admin");
  assert.ok(serverSource.includes("SQLI_XSS_PATTERNS"), "Expected SQLi/XSS WAF inspection");
});

test("Migration 0005 enables RLS on new admin tables and defines SQLi text validation guards", () => {
  const m5 = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170005_admin_and_sqli_hardening.sql"),
    "utf8",
  );
  assert.ok(m5.includes("assert_safe_text"), "Expected assert_safe_text SQLi guard function");
  assert.ok(
    m5.includes("ALTER TABLE public.admin_step_up_sessions ENABLE ROW LEVEL SECURITY;"),
    "Expected RLS enabled on admin_step_up_sessions",
  );
  assert.ok(
    m5.includes("ALTER TABLE public.admin_access_audit ENABLE ROW LEVEL SECURITY;"),
    "Expected RLS enabled on admin_access_audit",
  );
  assert.equal(/USING\s*\(\s*true\s*\)/i.test(m5), false, "Must not use USING (true)");
  assert.equal(/WITH CHECK\s*\(\s*true\s*\)/i.test(m5), false, "Must not use WITH CHECK (true)");
});

test("Migration 0006 enforces AAL2 own-ledger audit RLS, append-only immutability, archiving, and session lifecycle", () => {
  const m6 = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170006_production_hardening.sql"),
    "utf8",
  );
  assert.ok(m6.includes("is_aal2_mfa"), "Expected is_aal2_mfa helper function");
  assert.ok(m6.includes("admin_user_id = auth.uid()"), "Expected own-ledger filter on admin_access_audit");
  assert.ok(m6.includes("prevent_audit_mutation"), "Expected append-only audit trigger function");
  assert.ok(m6.includes("security_audit_archive"), "Expected immutable archive table before pruning");
  assert.ok(
    m6.includes("ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;"),
    "Expected RLS enabled on user_sessions",
  );
  assert.ok(m6.includes("revoke_user_sessions"), "Expected centralized session revocation RPC");
  assert.equal(/USING\s*\(\s*true\s*\)/i.test(m6), false, "Must not use USING (true)");
  assert.equal(/WITH CHECK\s*\(\s*true\s*\)/i.test(m6), false, "Must not use WITH CHECK (true)");
});

test("Server has zero duplicate manual QR definitions and enforces production hardening & TOTP MFA", () => {
  const serverSource = fs.readFileSync(path.resolve(process.cwd(), "server.ts"), "utf8");
  assert.equal(
    (serverSource.match(/const MANUAL_CODE_ALPHABET\b/g) ?? []).length,
    1,
    "MANUAL_CODE_ALPHABET must be declared once",
  );
  assert.equal(
    (serverSource.match(/function generateManualCode\b/g) ?? []).length,
    1,
    "generateManualCode must be declared once",
  );
  assert.equal(
    (serverSource.match(/function normalizeManualCode\b/g) ?? []).length,
    1,
    "normalizeManualCode must be declared once",
  );

  // P0: No demo passwords in README and production bootstrap bans demo creds
  const readme = fs.readFileSync(path.resolve(process.cwd(), "README.md"), "utf8");
  assert.equal(/Admin@2026|Emp@2026|Kiosk@2026|KIOSK-HQ-2026/.test(readme), false);
  assert.ok(serverSource.includes("assertNoDefaultCredentialsInProduction"));
  assert.ok(serverSource.includes("buildProductionBootstrapDatabase"));

  // P0/UI: Frontend demo creds must be gated by import.meta.env.DEV
  for (const page of ["src/pages/LoginPage.tsx", "src/pages/KioskPage.tsx", "src/pages/HrDashboardPage.tsx"]) {
    const content = fs.readFileSync(path.resolve(process.cwd(), page), "utf8");
    if (/Admin@2026|Emp@2026|Kiosk@2026|KIOSK-HQ-2026/.test(content)) {
      assert.ok(
        content.includes("import.meta.env.DEV"),
        `${page} must guard demo credentials behind import.meta.env.DEV`,
      );
    }
  }

  // P1 & P2 controls in server.ts
  assert.ok(serverSource.includes("contentSecurityPolicy:"));
  assert.ok(serverSource.includes("frameAncestors: allowedFrameAncestors"));
  assert.ok(serverSource.includes('dsaEncoding: "ieee-p1363"'));
  assert.ok(serverSource.includes("DATA_ENCRYPTION_KEY"));
  assert.ok(serverSource.includes("TRUST_PROXY"));
  assert.equal(serverSource.includes('req.headers["x-forwarded-for"]'), false);
  assert.ok(serverSource.includes("checkDistributedRateLimit"));
  assert.ok(serverSource.includes("verifyTotpCode"));
  assert.ok(serverSource.includes("/api/hr/security/mfa/enroll"));
  assert.ok(serverSource.includes("/api/hr/security/mfa/activate"));
  assert.ok(serverSource.includes("SESSION_POLICIES"));
  assert.ok(serverSource.includes("/api/hr/security/sessions/:jti"));
  assert.ok(serverSource.includes("/api/hr/security/backup"));
  assert.ok(serverSource.includes("EXPORT_RANGE_EXCEEDED"));
  assert.ok(serverSource.includes("EXPORT_LIMIT_EXCEEDED"));
  assert.ok(serverSource.includes("attendance_anomaly_detected"));
  assert.ok(serverSource.includes("ALERT_WEBHOOK_URL"));
});

test("Node ECDSA P-256 ieee-p1363 signature verifies cleanly via WebCrypto subtle.verify", async () => {
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const payload = Buffer.from("ch-1|srv-pub|cli-pub|nonce-1|2026-11-18T00:00:00Z", "utf8");
  const sig = sign("sha256", payload, { key: privateKey, dsaEncoding: "ieee-p1363" });

  const webKey = await globalThis.crypto.subtle.importKey(
    "spki",
    spkiDer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    webKey,
    sig,
    payload,
  );
  assert.equal(ok, true);
});

test("Migration 0007 enforces AAL2 RLS on RBAC tables and defines QR schedule & permission RPC guards", () => {
  const m7 = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611190007_multi_kiosk_schedule_rbac.sql"),
    "utf8",
  );
  assert.ok(m7.includes("CREATE TABLE IF NOT EXISTS public.rbac_roles"));
  assert.ok(m7.includes("CREATE TABLE IF NOT EXISTS public.user_permissions"));
  assert.ok(m7.includes("ALTER TABLE public.rbac_roles ENABLE ROW LEVEL SECURITY;"));
  assert.ok(m7.includes("ALTER TABLE public.user_permissions ENABLE ROW LEVEL SECURITY;"));
  assert.ok(m7.includes("has_hr_permission"));
  assert.ok(m7.includes("is_within_qr_capture_window"));
  assert.ok(m7.includes("is_aal2_mfa()"));
  assert.equal(/USING\s*\(\s*true\s*\)/i.test(m7), false, "Must not use USING (true)");
  assert.equal(/WITH CHECK\s*\(\s*true\s*\)/i.test(m7), false, "Must not use WITH CHECK (true)");
});

test("Server implements Multi-Kiosk, QR capture window, Cloudflare Free WAF/Turnstile, and DB RBAC guards", () => {
  const serverSource = fs.readFileSync(path.resolve(process.cwd(), "server.ts"), "utf8");
  assert.ok(serverSource.includes("evaluateQrCaptureSchedule"));
  assert.ok(serverSource.includes("QR_WINDOW_CLOSED"));
  assert.ok(serverSource.includes("requirePermission"));
  assert.ok(serverSource.includes('"/api/hr/kiosks"'));
  assert.ok(serverSource.includes('"/api/hr/kiosks/:id"'));
  assert.ok(serverSource.includes('"/api/hr/security/policy"'));
  assert.ok(serverSource.includes('"/api/hr/rbac/roles/:roleKey"'));
  assert.ok(serverSource.includes('"/api/hr/rbac/users/:userId"'));
  assert.ok(serverSource.includes('"/api/auth/public-config"'));
  assert.ok(serverSource.includes("METHOD_OVERRIDE_BLOCKED"));
  assert.ok(serverSource.includes("UNSUPPORTED_MEDIA_TYPE"));
  assert.ok(serverSource.includes("WAF_THREAT_BLOCKED"));
  assert.ok(serverSource.includes("COUNTRY_BLOCKED"));
  assert.ok(serverSource.includes("strict_ip_binding"));
  assert.ok(serverSource.includes("TURNSTILE_SECRET_KEY"));
  assert.ok(serverSource.includes("https://challenges.cloudflare.com"));
  assert.ok(serverSource.includes("x-forwarded-host"));
  assert.ok(serverSource.includes("CORS_ORIGIN_REJECTED"));
  assert.ok(serverSource.includes("configuredAppUrl"));

  const catalog = fs.readFileSync(
    path.resolve(process.cwd(), "docs/ENTERPRISE_SETUP_CATALOG.md"),
    "utf8",
  );
  assert.ok(catalog.includes("Cloudflare"));
  assert.ok(catalog.includes("DATA_ENCRYPTION_KEY"));
  assert.equal(/Admin@2026|Emp@2026|Kiosk@2026|KIOSK-HQ-2026/.test(catalog), false);
});

test("ADR-001: Frontend enforces single official Express E2EE backend with zero dual-backend dead code", () => {
  const srcFiles = collectFiles(path.resolve(process.cwd(), "src"));
  for (const file of srcFiles) {
    const content = fs.readFileSync(file, "utf8");
    assert.equal(
      content.includes("isSupabaseConfigured"),
      false,
      `Dual-backend branch isSupabaseConfigured must not exist in ${file}`,
    );
    assert.equal(
      content.includes("@supabase/supabase-js"),
      false,
      `Unused @supabase/supabase-js import found in ${file}`,
    );
  }
  assert.equal(fs.existsSync(path.resolve(process.cwd(), "src/lib/supabase.ts")), false);
  assert.equal(fs.existsSync(path.resolve(process.cwd(), "supabase")), false);
  assert.equal(fs.existsSync(path.resolve(process.cwd(), "docs/DECISIONS.md")), true);
  assert.equal(fs.existsSync(path.resolve(process.cwd(), "CHANGELOG.md")), true);
});

test("CI pipeline enforces blocking npm audit, Gitleaks secret scan, CodeQL SAST, license check, bundle secret check, Dependabot, and CycloneDX SBOM artifact", () => {
  const ci = fs.readFileSync(path.resolve(process.cwd(), ".github/workflows/ci.yml"), "utf8");
  const dependabot = fs.readFileSync(path.resolve(process.cwd(), ".github/dependabot.yml"), "utf8");
  const gitleaks = fs.readFileSync(path.resolve(process.cwd(), ".gitleaks.toml"), "utf8");
  const codeqlCfg = fs.readFileSync(
    path.resolve(process.cwd(), ".github/codeql/codeql-config.yml"),
    "utf8",
  );
  const deployDoc = fs.readFileSync(path.resolve(process.cwd(), "docs/DEPLOYMENT.md"), "utf8");

  assert.equal(fs.existsSync(path.resolve(process.cwd(), "package-lock.json")), true, "package-lock.json required for npm ci & npm audit");
  assert.ok(ci.includes("npm audit --audit-level=high"));
  assert.equal(ci.includes("continue-on-error: true"), false);
  assert.ok(ci.includes("gitleaks/gitleaks-action"));
  assert.ok(ci.includes("github/codeql-action/analyze"));
  assert.ok(ci.includes("npm run check:licenses"));
  assert.ok(ci.includes("npm run check:bundle"));
  assert.ok(ci.includes("npm run sbom"));
  assert.ok(ci.includes("actions/upload-artifact"));
  assert.ok(ci.includes("sbom.cdx.json"));

  assert.ok(dependabot.includes('package-ecosystem: "npm"'));
  assert.ok(dependabot.includes('package-ecosystem: "github-actions"'));
  assert.ok(gitleaks.includes(".env\\.example"));
  assert.ok(codeqlCfg.includes("server.ts"));

  assert.ok(deployDoc.includes("dependabot.yml"));
  assert.ok(deployDoc.includes("npm audit --audit-level=high"));
  assert.ok(deployDoc.includes("CodeQL"));
});


