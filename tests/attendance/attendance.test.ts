import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  isValidEmail,
  isValidQrOrManualInput,
  isValidQrTokenFormat,
} from "../../src/lib/validation.ts";
import {
  buildAttendanceSummaryRows,
  type ExportAttendanceRow,
  type ExportStudentRow,
} from "../../examples/optional-supabase-mode/functions/_shared/securityGuards.ts";

test("QR token format validator accepts cryptographic base64url tokens and rejects unsafe payloads", () => {
  const validToken = "aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA";
  assert.equal(isValidQrTokenFormat(validToken), true);

  assert.equal(isValidQrTokenFormat("short"), false);
  assert.equal(isValidQrTokenFormat("<script>alert(1)</script>123456789"), false);
  assert.equal(isValidQrTokenFormat("token with spaces 1234567890"), false);
  assert.equal(isValidQrTokenFormat(""), false);
});

test("Manual fallback attendance input validator accepts 8-char manual codes and full QR tokens", () => {
  assert.equal(isValidQrOrManualInput("7K4M-9P2R"), true);
  assert.equal(isValidQrOrManualInput("7k4m9p2r"), true);
  assert.equal(isValidQrOrManualInput("7K4M 9P2R"), true);
  assert.equal(isValidQrOrManualInput("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA"), true);

  assert.equal(isValidQrOrManualInput("short"), false);
  assert.equal(isValidQrOrManualInput("<script>"), false);
  assert.equal(isValidQrOrManualInput("ABCD-123"), false);
  assert.equal(isValidQrOrManualInput(""), false);
});

test("Email format validator handles valid and malformed inputs", () => {
  assert.equal(isValidEmail("student1@university.edu"), true);
  assert.equal(isValidEmail("invalid-email"), false);
  assert.equal(isValidEmail("student@"), false);
});

test("Export summary accurately separates present, excused, and absent days even with >1000 records", () => {
  const students: ExportStudentRow[] = Array.from({ length: 1200 }, (_, i) => ({
    id: `stu-${i + 1}`,
    full_name: `طالب ${i + 1}`,
    student_number: `2026${String(i + 1).padStart(4, "0")}`,
  }));

  // 10 official study days; student 1 has 6 present + 2 excused -> 2 absent; student 2 has 0 present + 3 excused -> 7 absent
  const records: ExportAttendanceRow[] = [
    ...Array.from({ length: 6 }, (_, d) => ({
      student_id: "stu-1",
      attendance_date: `2026-11-0${d + 1}`,
      checked_in_at: `2026-11-0${d + 1}T08:00:00Z`,
      status: "present" as const,
    })),
    {
      student_id: "stu-1",
      attendance_date: "2026-11-07",
      checked_in_at: "2026-11-07T08:00:00Z",
      status: "excused",
    },
    {
      student_id: "stu-1",
      attendance_date: "2026-11-08",
      checked_in_at: "2026-11-08T08:00:00Z",
      status: "excused",
    },
    ...Array.from({ length: 3 }, (_, d) => ({
      student_id: "stu-2",
      attendance_date: `2026-11-0${d + 1}`,
      checked_in_at: `2026-11-0${d + 1}T08:00:00Z`,
      status: "excused" as const,
    })),
    // Add >1,200 extra records across other students to validate scaling past 1,000 rows
    ...students.slice(2).map((s) => ({
      student_id: s.id,
      attendance_date: "2026-11-01",
      checked_in_at: "2026-11-01T08:00:00Z",
      status: "present" as const,
    })),
  ];

  const summary = buildAttendanceSummaryRows(students, records, 10);
  assert.equal(summary.length, 1200);

  const s1 = summary[0];
  assert.equal(s1.present_days, 6);
  assert.equal(s1.excused_days, 2);
  assert.equal(s1.absent_days, 2);
  assert.equal(s1.attendance_rate, 60);

  const s2 = summary[1];
  assert.equal(s2.present_days, 0);
  assert.equal(s2.excused_days, 3);
  assert.equal(s2.absent_days, 7);
  assert.equal(s2.attendance_rate, 0);
});

test("Database schema enforces single-use QR, one attendance per day, and row-level locking", () => {
  const schemaSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170001_initial_schema.sql"),
    "utf8",
  );
  const rpcSql = fs.readFileSync(
    path.resolve(process.cwd(), "examples/optional-supabase-mode/migrations/202611170002_rls_and_atomic_functions.sql"),
    "utf8",
  );

  assert.ok(
    schemaSql.includes("CONSTRAINT one_attendance_per_student_per_day UNIQUE (student_id, attendance_date)"),
    "Missing unique constraint one_attendance_per_student_per_day",
  );
  assert.ok(
    schemaSql.includes("CREATE UNIQUE INDEX IF NOT EXISTS one_active_qr_per_kiosk"),
    "Missing partial unique index one_active_qr_per_kiosk",
  );
  assert.ok(
    rpcSql.includes("FOR UPDATE"),
    "Atomic check-in RPC must lock QR row with SELECT ... FOR UPDATE",
  );
  assert.ok(
    rpcSql.includes("AT TIME ZONE v_campus.timezone"),
    "Attendance date must be computed server-side using university timezone",
  );
});
