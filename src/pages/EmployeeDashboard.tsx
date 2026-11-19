import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckCircle2,
  Clock,
  KeyRound,
  LogOut,
  QrCode,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { ChangePasswordModal } from "../components/ChangePasswordModal";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";
import { fetchMyAttendanceRecords } from "../services/attendanceService";
import type { AttendanceRecord, AttendanceStatus } from "../types/attendance";

function formatDurationMinutes(totalMins: number | null, lang: "ar" | "en"): string {
  if (totalMins === null || totalMins <= 0) return "—";
  const hrs = Math.floor(totalMins / 60);
  const mins = totalMins % 60;
  if (lang === "ar") {
    return `${String(hrs).padStart(2, "0")}:${String(mins).padStart(2, "0")} س`;
  }
  return `${String(hrs).padStart(2, "0")}h ${String(mins).padStart(2, "0")}m`;
}

export function EmployeeDashboard() {
  const { user, profile } = useAuth();
  const { lang, t } = useI18n();

  const [records, setRecords] = useState<AttendanceRecord[]>([]);
  const [serverTodayDate, setServerTodayDate] = useState<string>(
    new Date().toISOString().slice(0, 10),
  );
  const [companyMeta, setCompanyMeta] = useState<{
    company_name: string;
    branch_name: string;
    work_start_time: string;
    work_end_time: string;
  } | null>(null);
  const [statusFilter, setStatusFilter] = useState<"all" | AttendanceStatus>("all");
  const [loadingRecords, setLoadingRecords] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordUpdatedMsg, setPasswordUpdatedMsg] = useState(false);

  const loadRecords = useCallback(async () => {
    if (!user?.id) return;
    setLoadingRecords(true);
    setLoadError(null);
    const res = await fetchMyAttendanceRecords(user.id);
    if (res.error) {
      setLoadError(t.loadError);
    } else {
      setRecords(res.records);
      setServerTodayDate(res.today_date);
      setLastSyncedAt(new Date().toISOString());
      if (res.shift_info) {
        setCompanyMeta(res.shift_info);
      }
    }
    setLoadingRecords(false);
  }, [t.loadError, user?.id]);

  useEffect(() => {
    void loadRecords();
  }, [loadRecords]);

  useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 30_000);
    return () => window.clearInterval(id);
  }, []);

  const todayRecord = useMemo(() => {
    return records.find((r) => r.attendance_date === serverTodayDate) ?? null;
  }, [records, serverTodayDate]);

  const todayState: "not_checked_in" | "on_shift" | "completed" | "excused" = useMemo(() => {
    if (!todayRecord) return "not_checked_in";
    if (todayRecord.status === "excused") return "excused";
    if (todayRecord.checked_in_at && !todayRecord.checked_out_at) return "on_shift";
    return "completed";
  }, [todayRecord]);

  const elapsedMinutesToday = useMemo(() => {
    if (todayState !== "on_shift" || !todayRecord?.checked_in_at) return null;
    return Math.max(0, Math.floor((nowMs - Date.parse(todayRecord.checked_in_at)) / 60000));
  }, [nowMs, todayRecord, todayState]);

  const summaryStats = useMemo(() => {
    const presentOrLate = records.filter((r) => r.status === "present" || r.status === "late");
    const lateCount = records.filter((r) => r.status === "late").length;
    const totalMinutes = records.reduce((acc, r) => acc + (r.worked_minutes ?? 0), 0);
    const totalHours = (totalMinutes / 60).toFixed(1);
    const onTimeRate =
      presentOrLate.length > 0
        ? Math.round(((presentOrLate.length - lateCount) / presentOrLate.length) * 100)
        : 100;
    return {
      presentDays: presentOrLate.length,
      onTimeRate,
      lateCount,
      totalHours,
    };
  }, [records]);

  const filteredRecords = useMemo(() => {
    if (statusFilter === "all") return records;
    return records.filter((r) => r.status === statusFilter);
  }, [records, statusFilter]);

  const todayFormatted = useMemo(() => {
    return new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
    }).format(new Date());
  }, [lang]);

  const formatTime = (iso: string | null) => {
    if (!iso) return "—";
    return new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(new Date(iso));
  };

  const renderStatusLabel = (rec: AttendanceRecord) => {
    if (rec.status === "excused") {
      return <span className="font-semibold text-sky-700">{t.excusedLabel}</span>;
    }
    if (rec.status === "late") {
      return (
        <span className="font-semibold text-amber-700">
          {t.lateLabel} ({rec.late_minutes} {t.minutesUnit})
        </span>
      );
    }
    return <span className="font-semibold text-emerald-700">{t.presentLabel}</span>;
  };

  return (
    <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 sm:py-8 space-y-6">
      {/* Compact Employee Header & Sync Timestamp */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div className="space-y-1">
          <p className="text-xs font-semibold text-slate-500">
            {companyMeta ? `${companyMeta.company_name} · ${companyMeta.branch_name}` : t.employeeDashboardTitle}
            <span aria-hidden="true"> · </span>
            <span>{todayFormatted}</span>
          </p>
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-bold text-slate-900 sm:text-2xl">
            <span>{profile?.full_name ?? "—"}</span>
            {profile?.is_active && (
              <CheckCircle2
                className="h-5 w-5 shrink-0 text-sky-600"
                aria-label={t.verifiedEmployeeBadge}
              />
            )}
          </h1>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
            <span className="font-mono font-semibold text-slate-900 tabular-nums">
              {profile?.employee_number ?? "—"}
            </span>
            {profile?.department && (
              <>
                <span aria-hidden="true">·</span>
                <span>{profile.department}</span>
              </>
            )}
            {profile?.job_title && (
              <>
                <span aria-hidden="true">·</span>
                <span>{profile.job_title}</span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {lastSyncedAt && (
            <span className="text-xs text-slate-500">
              {t.lastSyncLabel}:{" "}
              <span className="font-mono font-semibold text-slate-700 tabular-nums">
                {formatTime(lastSyncedAt)}
              </span>
            </span>
          )}
          <button
            type="button"
            onClick={() => void loadRecords()}
            disabled={loadingRecords}
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${loadingRecords ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            <span>{t.retryBtn}</span>
          </button>
        </div>
      </div>

      {/* Top Focal Split: Primary Today Status + Check-In/Out Action FIRST, then History */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <section aria-label={t.todayStatusLabel} className="lg:col-span-5 space-y-5">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-5">
            <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-4">
              <div>
                <p className="text-xs font-medium text-slate-500">{t.todayStatusLabel}</p>
                <div className="mt-1.5">
                  {loadingRecords && records.length === 0 ? (
                    <span className="text-sm font-semibold text-slate-500">{t.loadingText}</span>
                  ) : loadError && records.length === 0 ? (
                    <span className="inline-flex items-center gap-2 text-sm font-semibold text-red-700">
                      <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
                      <span>{t.loadError}</span>
                    </span>
                  ) : !profile?.is_active ? (
                    <span className="inline-flex items-center gap-2 text-base font-bold text-red-700">
                      <ShieldAlert className="h-5 w-5 shrink-0" aria-hidden="true" />
                      <span>{t.accountInactive}</span>
                    </span>
                  ) : todayState === "excused" ? (
                    <span className="inline-flex items-center gap-2 text-base font-bold text-sky-700">
                      <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden="true" />
                      <span>{t.excusedTodayLabel}</span>
                    </span>
                  ) : todayState === "on_shift" ? (
                    <span className="inline-flex items-center gap-2 text-base font-bold text-emerald-700">
                      <Clock className="h-5 w-5 shrink-0" aria-hidden="true" />
                      <span>{t.onShiftNow}</span>
                    </span>
                  ) : todayState === "completed" ? (
                    <span className="inline-flex items-center gap-2 text-base font-bold text-emerald-700">
                      <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden="true" />
                      <span>{t.shiftCompletedToday}</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-2 text-base font-bold text-amber-700">
                      <Clock className="h-5 w-5 shrink-0" aria-hidden="true" />
                      <span>{t.notCheckedInYet}</span>
                    </span>
                  )}
                </div>
              </div>
              <div className="text-end">
                <p className="text-xs text-slate-500">{t.shiftLabel}</p>
                <p className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums" dir="ltr">
                  {profile?.shift_start ?? "09:00"} — {profile?.shift_end ?? "17:00"}
                </p>
              </div>
            </div>

            {todayState === "on_shift" && (
              <dl className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <dt className="text-slate-500">{t.checkInTimeLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatTime(todayRecord?.checked_in_at ?? null)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">{t.elapsedTimeLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatDurationMinutes(elapsedMinutesToday, lang)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">{t.expectedShiftEndLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums" dir="ltr">
                    {profile?.shift_end ?? companyMeta?.work_end_time ?? "17:00"}
                  </dd>
                </div>
              </dl>
            )}

            {todayState === "completed" && (
              <dl className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <dt className="text-slate-500">{t.checkInTimeLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatTime(todayRecord?.checked_in_at ?? null)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">{t.checkOutTimeLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatTime(todayRecord?.checked_out_at ?? null)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">{t.workedHoursLabel}</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatDurationMinutes(todayRecord?.worked_minutes ?? null, lang)}
                  </dd>
                </div>
              </dl>
            )}

            {/* Primary Daily Attendance Action CTA */}
            <div>
              {profile?.is_active && todayState === "not_checked_in" ? (
                <Link
                  to="/employee/scan?mode=check_in"
                  className="inline-flex min-h-[52px] w-full items-center justify-center gap-2.5 rounded-xl bg-slate-900 px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-800"
                >
                  <QrCode className="h-5 w-5 shrink-0" aria-hidden="true" />
                  <span>{t.checkInCta}</span>
                </Link>
              ) : profile?.is_active && todayState === "on_shift" ? (
                <Link
                  to="/employee/scan?mode=check_out"
                  className="inline-flex min-h-[52px] w-full items-center justify-center gap-2.5 rounded-xl bg-sky-800 px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-sky-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-800"
                >
                  <LogOut className="h-5 w-5 shrink-0" aria-hidden="true" />
                  <span>{t.checkOutCta}</span>
                </Link>
              ) : (
                <button
                  type="button"
                  disabled
                  className="inline-flex min-h-[52px] w-full cursor-not-allowed items-center justify-center gap-2.5 rounded-xl border border-slate-200 bg-slate-100 px-6 py-3.5 text-sm font-semibold text-slate-500"
                >
                  <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden="true" />
                  <span>
                    {!profile?.is_active
                      ? t.accountInactive
                      : todayState === "excused"
                        ? t.excusedTodayLabel
                        : t.alreadyCompletedCta}
                  </span>
                </button>
              )}
            </div>

            {passwordUpdatedMsg && (
              <div
                role="status"
                aria-live="polite"
                className="flex items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs font-medium text-emerald-900"
              >
                <span>
                  {lang === "ar"
                    ? "تم تحديث كلمة المرور وإنهاء جميع الجلسات السابقة."
                    : "Password updated and all previous sessions revoked."}
                </span>
                <button
                  type="button"
                  onClick={() => setPasswordUpdatedMsg(false)}
                  className="underline whitespace-nowrap shrink-0"
                >
                  {lang === "ar" ? "إغلاق" : "Dismiss"}
                </button>
              </div>
            )}

            <div className="flex flex-col gap-3 border-t border-slate-100 pt-4">
              <p className="text-xs leading-relaxed text-slate-500">{t.privacyNote}</p>
              <button
                type="button"
                onClick={() => setShowPasswordModal(true)}
                className="inline-flex min-h-[40px] w-fit items-center gap-2 rounded-lg border border-slate-200 px-3.5 py-1.5 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
              >
                <KeyRound className="h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden="true" />
                <span>{lang === "ar" ? "تغيير كلمة المرور" : "Change Password"}</span>
              </button>
            </div>
          </div>

          {/* Attendance Summary KPIs (clearly scoped to loaded records) */}
          <section aria-label={t.loadedRecordsScopeNote} className="space-y-2.5">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs font-medium text-slate-500">{t.monthlyPresentDays}</p>
                <p className="mt-1.5 font-mono text-xl font-bold text-slate-900 tabular-nums">
                  {summaryStats.presentDays}{" "}
                  <span className="font-sans text-xs font-medium text-slate-500">{t.daysUnit}</span>
                </p>
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs font-medium text-slate-500">{t.monthlyCommitmentRate}</p>
                <p className="mt-1.5 font-mono text-xl font-bold text-emerald-700 tabular-nums">
                  {summaryStats.onTimeRate}%
                </p>
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs font-medium text-slate-500">{t.monthlyLateCount}</p>
                <p className="mt-1.5 font-mono text-xl font-bold text-amber-700 tabular-nums">
                  {summaryStats.lateCount}
                </p>
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs font-medium text-slate-500">{t.monthlyTotalHours}</p>
                <p className="mt-1.5 font-mono text-xl font-bold text-slate-900 tabular-nums">
                  {summaryStats.totalHours}{" "}
                  <span className="font-sans text-xs font-medium text-slate-500">{t.hoursUnit}</span>
                </p>
              </div>
            </div>
            <p className="text-xs text-slate-500">{t.loadedRecordsScopeNote}</p>
          </section>
        </section>

        {/* Secondary Column: Attendance History (Cards on Mobile, Table on Desktop) */}
        <section className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 lg:col-span-7">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <h2 className="text-base font-bold text-slate-900 sm:text-lg">{t.historyTitle}</h2>

            <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1" role="group" aria-label={t.statusCol}>
              {(["all", "present", "late", "excused"] as const).map((key) => {
                const label =
                  key === "all"
                    ? t.allFilter
                    : key === "present"
                      ? t.presentLabel
                      : key === "late"
                        ? t.lateLabel
                        : t.excusedLabel;
                return (
                  <button
                    key={key}
                    type="button"
                    aria-pressed={statusFilter === key}
                    onClick={() => setStatusFilter(key)}
                    className={`rounded-md px-2.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                      statusFilter === key
                        ? "bg-white text-slate-900 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>

          {loadingRecords ? (
            <div className="mt-4 space-y-2.5" aria-busy="true">
              {[1, 2, 3, 4, 5].map((row) => (
                <div key={row} className="h-11 w-full animate-pulse rounded-lg bg-slate-100" />
              ))}
            </div>
          ) : loadError ? (
            <div className="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-5 text-sm text-red-800">
              <span>{loadError}</span>
              <button
                type="button"
                onClick={() => void loadRecords()}
                className="min-h-[38px] rounded-lg border border-red-300 bg-white px-4 py-1.5 text-xs font-semibold text-red-800 hover:bg-red-50"
              >
                {t.retryBtn}
              </button>
            </div>
          ) : filteredRecords.length === 0 ? (
            <div className="py-12 text-center space-y-3">
              <p className="text-sm text-slate-500">
                {statusFilter === "all" ? t.historyEmpty : t.historyFilteredEmpty}
              </p>
              {statusFilter !== "all" && (
                <button
                  type="button"
                  onClick={() => setStatusFilter("all")}
                  className="min-h-[38px] rounded-lg border border-slate-300 px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                >
                  {t.clearFilterBtn}
                </button>
              )}
            </div>
          ) : (
            <>
              {/* Mobile Card View */}
              <div className="mt-4 space-y-3 sm:hidden">
                {filteredRecords.map((rec) => (
                  <div
                    key={rec.id}
                    className="rounded-xl border border-slate-200 bg-slate-50/50 p-3.5 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">
                        {rec.attendance_date}
                      </span>
                      {renderStatusLabel(rec)}
                    </div>
                    <div className="flex items-center justify-between text-slate-600">
                      <span>
                        {t.checkInCol}:{" "}
                        <strong className="font-mono text-slate-900 tabular-nums">
                          {formatTime(rec.checked_in_at)}
                        </strong>
                      </span>
                      <span>
                        {t.checkOutCol}:{" "}
                        <strong className="font-mono text-slate-900 tabular-nums">
                          {formatTime(rec.checked_out_at)}
                        </strong>
                      </span>
                      <span>
                        <strong className="font-mono text-slate-900 tabular-nums">
                          {formatDurationMinutes(rec.worked_minutes, lang)}
                        </strong>
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop Table View */}
              <div className="mt-4 hidden overflow-x-auto sm:block">
                <table className="w-full text-start text-xs sm:text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                      <th className="py-3 pe-3 text-start">{t.dateCol}</th>
                      <th className="py-3 px-2 text-start">{t.checkInCol}</th>
                      <th className="py-3 px-2 text-start">{t.checkOutCol}</th>
                      <th className="py-3 px-2 text-start">{t.hoursCol}</th>
                      <th className="py-3 ps-2 text-start">{t.statusCol}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredRecords.map((rec) => (
                      <tr key={rec.id} className="hover:bg-slate-50/80">
                        <td className="whitespace-nowrap py-3 pe-3 font-mono text-slate-900 tabular-nums">
                          {rec.attendance_date}
                        </td>
                        <td className="whitespace-nowrap py-3 px-2 font-mono text-slate-700 tabular-nums">
                          {formatTime(rec.checked_in_at)}
                        </td>
                        <td className="whitespace-nowrap py-3 px-2 font-mono text-slate-700 tabular-nums">
                          {formatTime(rec.checked_out_at)}
                        </td>
                        <td className="whitespace-nowrap py-3 px-2 font-mono text-slate-700 tabular-nums">
                          {formatDurationMinutes(rec.worked_minutes, lang)}
                        </td>
                        <td className="whitespace-nowrap py-3 ps-2">
                          {renderStatusLabel(rec)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      </div>

      <ChangePasswordModal
        open={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
        onSuccess={() => setPasswordUpdatedMsg(true)}
      />
    </main>
  );
}
