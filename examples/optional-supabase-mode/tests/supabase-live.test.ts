import test from "node:test";
import assert from "node:assert/strict";

const SUPABASE_URL = process.env.TEST_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.TEST_SUPABASE_ANON_KEY;
const STUDENT_JWT = process.env.TEST_STUDENT_JWT;
const OTHER_STUDENT_ID = process.env.TEST_OTHER_STUDENT_ID;
const KIOSK_JWT = process.env.TEST_KIOSK_JWT;
const KIOSK_SECRET = process.env.TEST_KIOSK_SECRET;
const ADMIN_AAL1_JWT = process.env.TEST_ADMIN_AAL1_JWT;
const CAMPUS_LAT = Number(process.env.TEST_CAMPUS_LAT ?? "24.7136");
const CAMPUS_LON = Number(process.env.TEST_CAMPUS_LON ?? "46.6753");

const hasLiveEnv = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);

test(
  "Live RLS: anonymous requests cannot read sensitive tables",
  {
    skip: !hasLiveEnv
      ? "Set TEST_SUPABASE_URL and TEST_SUPABASE_ANON_KEY to run live RLS E2E tests"
      : false,
  },
  async () => {
    const tables = [
      "profiles",
      "attendance_records",
      "qr_tokens",
      "security_logs",
      "kiosk_devices",
      "rate_limits",
    ];
    for (const table of tables) {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?select=*`, {
        headers: {
          apikey: SUPABASE_ANON_KEY!,
          Authorization: `Bearer ${SUPABASE_ANON_KEY!}`,
        },
      });
      const body = await res.json().catch(() => []);
      if (res.ok) {
        assert.deepEqual(body, [], `Anonymous read on ${table} returned rows`);
      } else {
        assert.ok(res.status === 401 || res.status === 403);
      }
    }
  },
);

test(
  "Live RLS: student cannot read another student's profile/records or write attendance directly via REST API",
  {
    skip:
      !hasLiveEnv || !STUDENT_JWT || !OTHER_STUDENT_ID
        ? "Set TEST_SUPABASE_URL, TEST_SUPABASE_ANON_KEY, TEST_STUDENT_JWT, and TEST_OTHER_STUDENT_ID"
        : false,
  },
  async () => {
    const otherProfileRes = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?id=eq.${OTHER_STUDENT_ID}&select=*`,
      {
        headers: {
          apikey: SUPABASE_ANON_KEY!,
          Authorization: `Bearer ${STUDENT_JWT!}`,
        },
      },
    );
    const otherProfiles = await otherProfileRes.json().catch(() => []);
    assert.deepEqual(otherProfiles, []);

    const otherAttendanceRes = await fetch(
      `${SUPABASE_URL}/rest/v1/attendance_records?student_id=eq.${OTHER_STUDENT_ID}&select=*`,
      {
        headers: {
          apikey: SUPABASE_ANON_KEY!,
          Authorization: `Bearer ${STUDENT_JWT!}`,
        },
      },
    );
    const otherAttendance = await otherAttendanceRes.json().catch(() => []);
    assert.deepEqual(otherAttendance, []);

    const directInsertRes = await fetch(`${SUPABASE_URL}/rest/v1/attendance_records`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_ANON_KEY!,
        Authorization: `Bearer ${STUDENT_JWT!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        student_id: OTHER_STUDENT_ID,
        attendance_date: "2026-11-17",
        status: "present",
      }),
    });
    assert.ok(directInsertRes.status === 401 || directInsertRes.status === 403);
  },
);

test(
  "Live E2E: student cannot invoke export-attendance or kiosk-issue-token; AAL1 admin denied MFA export",
  {
    skip:
      !hasLiveEnv || !STUDENT_JWT
        ? "Set TEST_SUPABASE_URL, TEST_SUPABASE_ANON_KEY, and TEST_STUDENT_JWT"
        : false,
  },
  async () => {
    const exportRes = await fetch(`${SUPABASE_URL}/functions/v1/export-attendance`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_ANON_KEY!,
        Authorization: `Bearer ${STUDENT_JWT!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from_date: "2026-11-01", to_date: "2026-11-30" }),
    });
    assert.equal(exportRes.status, 403);

    if (ADMIN_AAL1_JWT) {
      const aal1ExportRes = await fetch(`${SUPABASE_URL}/functions/v1/export-attendance`, {
        method: "POST",
        headers: {
          apikey: SUPABASE_ANON_KEY!,
          Authorization: `Bearer ${ADMIN_AAL1_JWT}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ from_date: "2026-11-01", to_date: "2026-11-30" }),
      });
      assert.equal(aal1ExportRes.status, 403);
    }

    const kioskRes = await fetch(`${SUPABASE_URL}/functions/v1/kiosk-issue-token`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_ANON_KEY!,
        Authorization: `Bearer ${STUDENT_JWT!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    assert.equal(kioskRes.status, 403);
  },
);

test(
  "Live E2E: kiosk requires mandatory x-kiosk-secret and concurrent check-in requests allow at most one success",
  {
    skip:
      !hasLiveEnv || !KIOSK_JWT || !KIOSK_SECRET || !STUDENT_JWT
        ? "Set TEST_SUPABASE_URL, TEST_SUPABASE_ANON_KEY, TEST_KIOSK_JWT, TEST_KIOSK_SECRET, and TEST_STUDENT_JWT"
        : false,
  },
  async () => {
    // Missing secret must be rejected
    const unauthKiosk = await fetch(`${SUPABASE_URL}/functions/v1/kiosk-issue-token`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_ANON_KEY!,
        Authorization: `Bearer ${KIOSK_JWT!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    assert.equal(unauthKiosk.status, 403);

    // Valid secret issues token
    const issued = await fetch(`${SUPABASE_URL}/functions/v1/kiosk-issue-token`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_ANON_KEY!,
        Authorization: `Bearer ${KIOSK_JWT!}`,
        "x-kiosk-secret": KIOSK_SECRET!,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    assert.equal(issued.status, 200);
    const { token } = (await issued.json()) as { ok: boolean; token: string };
    assert.ok(token.length >= 20);

    // Concurrent race on same QR token
    const nowIso = new Date().toISOString();
    const attempt = (key: string) =>
      fetch(`${SUPABASE_URL}/functions/v1/attendance-check-in`, {
        method: "POST",
        headers: {
          apikey: SUPABASE_ANON_KEY!,
          Authorization: `Bearer ${STUDENT_JWT!}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          qr_token: token,
          latitude: CAMPUS_LAT,
          longitude: CAMPUS_LON,
          accuracy: 15,
          client_captured_at: nowIso,
          idempotency_key: key,
        }),
      });

    const [r1, r2] = await Promise.all([attempt("race-1"), attempt("race-2")]);
    const successes = [r1, r2].filter((r) => r.status === 200).length;
    assert.ok(successes <= 1, `Concurrent race allowed ${successes} successes`);
  },
);
