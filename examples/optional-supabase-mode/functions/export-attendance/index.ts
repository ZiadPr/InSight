import ExcelJS from "npm:exceljs@4.4.0";
import { enforceCors, getCorsHeaders, jsonResponse } from "../_shared/cors.ts";
import { sanitizeExcelCell } from "../_shared/crypto.ts";
import {
  buildAttendanceSummaryRows,
  requireAal2Mfa,
  type ExportAttendanceRow,
  type ExportStudentRow,
} from "../_shared/securityGuards.ts";
import { authenticateRequestUser, createServiceClient } from "../_shared/supabaseAdmin.ts";

const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const PAGE_SIZE = 1000;
const MAX_EXPORT_RECORDS = 50000;
const MAX_RANGE_DAYS = 366;

function formatTimeInTimezone(isoString: string, timeZone: string): string {
  try {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
}

function diffDaysInclusive(fromDate: string, toDate: string): number {
  const fromMs = Date.parse(`${fromDate}T00:00:00Z`);
  const toMs = Date.parse(`${toDate}T00:00:00Z`);
  return Math.floor((toMs - fromMs) / 86_400_000) + 1;
}

async function fetchAllPaginated<T>(
  fetchPage: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: unknown }>,
  maxRows: number,
): Promise<T[]> {
  const all: T[] = [];
  let offset = 0;

  while (true) {
    const { data, error } = await fetchPage(offset, offset + PAGE_SIZE - 1);
    if (error) {
      throw new Error("PAGINATED_QUERY_FAILED");
    }
    const batch = data ?? [];
    all.push(...batch);

    if (all.length > maxRows) {
      throw new Error("EXPORT_LIMIT_EXCEEDED");
    }

    if (batch.length < PAGE_SIZE) {
      break;
    }
    offset += PAGE_SIZE;
  }

  return all;
}

Deno.serve(async (req: Request) => {
  const corsBlock = enforceCors(req);
  if (corsBlock) return corsBlock;

  if (req.method !== "POST") {
    return jsonResponse(req, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    const { user, jwt, error: authError } = await authenticateRequestUser(req);
    if (authError || !user || !jwt) {
      return jsonResponse(req, { ok: false, error: "UNAUTHORIZED" }, 401);
    }

    // Require MFA (AAL2) on the verified admin JWT
    if (!requireAal2Mfa(jwt)) {
      return jsonResponse(req, { ok: false, error: "MFA_REQUIRED" }, 403);
    }

    const adminClient = createServiceClient();

    const { data: adminProfile, error: adminErr } = await adminClient
      .from("profiles")
      .select("role, is_active")
      .eq("id", user.id)
      .single();

    if (
      adminErr ||
      !adminProfile ||
      adminProfile.role !== "admin" ||
      adminProfile.is_active !== true
    ) {
      return jsonResponse(req, { ok: false, error: "FORBIDDEN" }, 403);
    }

    const body = await req.json().catch(() => null);
    const fromDate = typeof body?.from_date === "string" ? body.from_date.trim() : "";
    const toDate = typeof body?.to_date === "string" ? body.to_date.trim() : "";
    const studentId = typeof body?.student_id === "string" ? body.student_id.trim() : "";
    const studentNumber =
      typeof body?.student_number === "string" ? body.student_number.trim() : "";
    const statusFilter = typeof body?.status === "string" ? body.status.trim() : "";

    if (!DATE_REGEX.test(fromDate) || !DATE_REGEX.test(toDate) || fromDate > toDate) {
      return jsonResponse(req, { ok: false, error: "INVALID_DATE_RANGE" }, 400);
    }

    if (diffDaysInclusive(fromDate, toDate) > MAX_RANGE_DAYS) {
      return jsonResponse(req, { ok: false, error: "DATE_RANGE_TOO_LARGE" }, 400);
    }

    if (statusFilter && statusFilter !== "present" && statusFilter !== "excused") {
      return jsonResponse(req, { ok: false, error: "INVALID_STATUS_FILTER" }, 400);
    }

    const { data: campus } = await adminClient
      .from("campus_settings")
      .select("timezone, campus_name")
      .limit(1)
      .single();

    const timezone = campus?.timezone ?? "Asia/Riyadh";

    const studyDays = await fetchAllPaginated<{ study_date: string }>(
      (from, to) =>
        adminClient
          .from("study_calendar")
          .select("study_date")
          .gte("study_date", fromDate)
          .lte("study_date", toDate)
          .eq("is_study_day", true)
          .order("study_date", { ascending: true })
          .range(from, to),
      MAX_RANGE_DAYS,
    );

    const totalStudyDays = studyDays.length;

    const students = await fetchAllPaginated<ExportStudentRow>(
      (from, to) => {
        let q = adminClient
          .from("profiles")
          .select("id, full_name, student_number")
          .eq("role", "student")
          .order("student_number", { ascending: true })
          .range(from, to);

        if (studentId) q = q.eq("id", studentId);
        if (studentNumber) q = q.eq("student_number", studentNumber);
        return q;
      },
      MAX_EXPORT_RECORDS,
    );

    const studentMap = new Map<string, ExportStudentRow>(
      students.map((s) => [s.id, s]),
    );

    // Always load ALL attendance statuses in range so summary calculations stay accurate even when statusFilter='excused'
    const allRecordsInRange = await fetchAllPaginated<ExportAttendanceRow>(
      (from, to) => {
        let q = adminClient
          .from("attendance_records")
          .select("student_id, attendance_date, checked_in_at, status")
          .gte("attendance_date", fromDate)
          .lte("attendance_date", toDate)
          .order("attendance_date", { ascending: true })
          .order("id", { ascending: true })
          .range(from, to);

        if (studentId) {
          q = q.eq("student_id", studentId);
        } else if (studentNumber) {
          const matchedIds = students.map((s) => s.id);
          if (matchedIds.length === 0) {
            return Promise.resolve({ data: [], error: null });
          }
          q = q.in("student_id", matchedIds);
        }
        return q;
      },
      MAX_EXPORT_RECORDS,
    );

    const filteredAllRecords = allRecordsInRange.filter((r) => studentMap.has(r.student_id));
    const detailRecords = statusFilter
      ? filteredAllRecords.filter((r) => r.status === statusFilter)
      : filteredAllRecords;

    const summaryRows = buildAttendanceSummaryRows(
      students,
      filteredAllRecords,
      totalStudyDays,
    );

    const workbook = new ExcelJS.Workbook();
    workbook.creator = "University Attendance System";
    workbook.created = new Date();

    const summarySheet = workbook.addWorksheet("ملخص الحضور", {
      views: [{ rightToLeft: true }],
    });
    summarySheet.columns = [
      { header: "الرقم الجامعي", key: "student_number", width: 18 },
      { header: "اسم الطالب", key: "full_name", width: 30 },
      { header: "أيام الحضور", key: "present_days", width: 14 },
      { header: "أيام الأعذار", key: "excused_days", width: 14 },
      { header: "أيام الغياب (وفق التقويم)", key: "absent_days", width: 22 },
      { header: "نسبة الحضور %", key: "attendance_rate", width: 16 },
    ];

    for (const row of summaryRows) {
      summarySheet.addRow({
        student_number: sanitizeExcelCell(row.student_number),
        full_name: sanitizeExcelCell(row.full_name),
        present_days: row.present_days,
        excused_days: row.excused_days,
        absent_days: row.absent_days,
        attendance_rate: row.attendance_rate,
      });
    }

    const detailsSheet = workbook.addWorksheet("سجل الحضور التفصيلي", {
      views: [{ rightToLeft: true }],
    });
    detailsSheet.columns = [
      { header: "الرقم الجامعي", key: "student_number", width: 18 },
      { header: "اسم الطالب", key: "full_name", width: 30 },
      { header: "تاريخ الحضور", key: "attendance_date", width: 16 },
      { header: "وقت التسجيل", key: "checked_in_time", width: 16 },
      { header: "الحالة", key: "status", width: 14 },
    ];

    for (const rec of detailRecords) {
      const student = studentMap.get(rec.student_id);
      detailsSheet.addRow({
        student_number: sanitizeExcelCell(student?.student_number ?? ""),
        full_name: sanitizeExcelCell(student?.full_name ?? ""),
        attendance_date: sanitizeExcelCell(rec.attendance_date),
        checked_in_time: sanitizeExcelCell(formatTimeInTimezone(rec.checked_in_at, timezone)),
        status: sanitizeExcelCell(rec.status === "present" ? "حاضر" : "بعذر"),
      });
    }

    const buffer = await workbook.xlsx.writeBuffer();
    const filename = `attendance_${fromDate}_to_${toDate}.xlsx`;

    return new Response(buffer, {
      status: 200,
      headers: {
        ...getCorsHeaders(req),
        "Content-Type":
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message === "EXPORT_LIMIT_EXCEEDED") {
      return jsonResponse(req, { ok: false, error: "EXPORT_LIMIT_EXCEEDED" }, 413);
    }
    return jsonResponse(req, { ok: false, error: "EXPORT_FAILED" }, 500);
  }
});
