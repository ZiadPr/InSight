import { secureFetchJson } from "../lib/secureTransport";
import type {
  AttendanceRecord,
  CheckInRequestPayload,
  CheckInResponse,
} from "../types/attendance";

export interface EmployeeAttendanceBundle {
  records: AttendanceRecord[];
  today_date: string;
  shift_info?: {
    company_name: string;
    branch_name: string;
    work_start_time: string;
    work_end_time: string;
    late_grace_minutes: number;
    enforce_geofence: boolean;
  };
  error: string | null;
}

export async function fetchMyAttendanceRecords(
  _employeeId: string,
): Promise<EmployeeAttendanceBundle> {
  const localToday = new Date().toISOString().slice(0, 10);

  try {
    const res = await secureFetchJson<{
      ok: boolean;
      today_date: string;
      records: AttendanceRecord[];
      settings?: EmployeeAttendanceBundle["shift_info"];
    }>("/api/attendance/me", { method: "GET" });

    if (!res.ok || !res.data?.ok) {
      return { records: [], today_date: localToday, error: "FETCH_FAILED" };
    }

    return {
      records: res.data.records ?? [],
      today_date: res.data.today_date ?? localToday,
      shift_info: res.data.settings,
      error: null,
    };
  } catch {
    return { records: [], today_date: localToday, error: "FETCH_FAILED" };
  }
}

export async function submitAttendanceCheckIn(
  payload: CheckInRequestPayload,
): Promise<CheckInResponse> {
  try {
    const res = await secureFetchJson<CheckInResponse>("/api/attendance/scan", {
      method: "POST",
      body: payload,
    });
    if (!res.data) {
      return { ok: false, error: "NETWORK_ERROR" };
    }
    return res.data;
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}
