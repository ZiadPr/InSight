import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import QRCode from "qrcode";
import {
  AlertTriangle,
  Archive,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Eye,
  EyeOff,
  Globe,
  KeyRound,
  Lock,
  MapPin,
  Monitor,
  Plus,
  Power,
  Printer,
  QrCode,
  RefreshCw,
  Search,
  ShieldCheck,
  UserCog,
  UserPlus,
  X,
} from "lucide-react";
import { ChangePasswordModal } from "../components/ChangePasswordModal";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";
import {
  getAdminStepUpRemainingMs,
  hasActiveAdminStepUp,
} from "../lib/secureTransport";
import {
  activateAdminMfa,
  assignUserRbac,
  createEmployee,
  createKioskDevice,
  downloadHrCsvExport,
  enrollAdminMfa,
  exportEncryptedBackup,
  fetchHrOverview,
  lockAdminSessionNow,
  logEmployeeExcuse,
  revokeAllSessions,
  revokeKioskDevice,
  revokeSessionByJti,
  updateCompanySettings,
  updateEmployee,
  updateKioskDevice,
  updateRbacRole,
  updateSecurityPolicy,
  verifyAdminStepUp,
} from "../services/hrService";
import type {
  AttendanceStatus,
  CompanySettings,
  HrOverviewResponse,
  KioskDeviceInfo,
  PermissionKey,
  Profile,
  RbacRoleDefinition,
  SecurityPolicySettings,
} from "../types/attendance";

type HrTab =
  | "overview"
  | "records"
  | "employees"
  | "settings"
  | "security"
  | "permissions"
  | "catalog";
type RecordSortKey = "newest" | "name" | "status";
type EmployeeSortKey = "name" | "number" | "status";

const PERMISSION_LABELS: Array<{ key: PermissionKey; ar: string; en: string }> = [
  { key: "view_overview", ar: "عرض النظرة العامة والإحصائيات", en: "View Overview & KPIs" },
  { key: "view_records", ar: "الاطلاع على سجلات الحضور", en: "View Attendance Records" },
  { key: "export_reports", ar: "تصدير التقارير المشفرة (CSV)", en: "Export CSV Reports" },
  { key: "manage_excuses", ar: "تسجيل واعتماد الأعذار", en: "Approve & Log Excuses" },
  { key: "manage_employees", ar: "إدارة الموظفين وإيقافهم", en: "Manage Employees" },
  { key: "manage_kiosks", ar: "إدارة واعتماد أجهزة الاستقبال", en: "Manage Reception Kiosks" },
  { key: "manage_settings", ar: "تعديل الفروع والجدول والنطاق", en: "Manage Branch & Schedule" },
  { key: "manage_security", ar: "إدارة الأمان و Cloudflare والنسخ", en: "Manage Security & WAF" },
  { key: "manage_permissions", ar: "إدارة الأدوار والصلاحيات", en: "Manage Roles & RBAC" },
];

interface ConfirmActionState {
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => Promise<void>;
}

const PAGE_SIZE = 15;

function formatDuration(mins: number | null, lang: "ar" | "en"): string {
  if (mins === null || mins <= 0) return "—";
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return lang === "ar"
    ? `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")} س`
    : `${String(h).padStart(2, "0")}h ${String(m).padStart(2, "0")}m`;
}

export function HrDashboardPage() {
  const { lang, t } = useI18n();
  const { profile } = useAuth();

  const [adminUnlocked, setAdminUnlocked] = useState<boolean>(() => hasActiveAdminStepUp());
  const [stepUpPassword, setStepUpPassword] = useState("");
  const [showStepUpPassword, setShowStepUpPassword] = useState(false);
  const [stepUpTotpCode, setStepUpTotpCode] = useState("");
  const [needsTotpInput, setNeedsTotpInput] = useState<boolean>(() => Boolean(profile?.mfa_enabled));
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [verifyingStepUp, setVerifyingStepUp] = useState(false);
  const [stepUpCountdownSec, setStepUpCountdownSec] = useState<number>(() =>
    Math.floor(getAdminStepUpRemainingMs() / 1000),
  );

  // TOTP MFA enrollment state
  const [mfaSetupGate, setMfaSetupGate] = useState(false);
  const [mfaEnrollSecret, setMfaEnrollSecret] = useState<string | null>(null);
  const [mfaEnrollQrUrl, setMfaEnrollQrUrl] = useState<string | null>(null);
  const [mfaActivateCode, setMfaActivateCode] = useState("");
  const [mfaBusy, setMfaBusy] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);

  const [tab, setTab] = useState<HrTab>("overview");
  const tabRefs = useRef<Partial<Record<HrTab, HTMLButtonElement | null>>>({});

  const [data, setData] = useState<HrOverviewResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  // Records filters, sorting & pagination
  const [searchQuery, setSearchQuery] = useState("");
  const [departmentFilter, setDepartmentFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState<"all" | AttendanceStatus>("all");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [recordSort, setRecordSort] = useState<RecordSortKey>("newest");
  const [recordsPage, setRecordsPage] = useState(1);

  // Employee directory search, sort & pagination
  const [empSearch, setEmpSearch] = useState("");
  const [empSort, setEmpSort] = useState<EmployeeSortKey>("number");
  const [employeesPage, setEmployeesPage] = useState(1);

  // Add employee modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [showNewEmpPassword, setShowNewEmpPassword] = useState(false);
  const [creatingEmployee, setCreatingEmployee] = useState(false);
  const [newEmpForm, setNewEmpForm] = useState({
    full_name: "",
    email: "",
    password: "",
    employee_number: "",
    department: "تطوير البرمجيات",
    job_title: "",
    shift_start: "09:00",
    shift_end: "17:00",
  });

  // Excuse modal
  const [excuseTarget, setExcuseTarget] = useState<{
    employee_id: string;
    attendance_date: string;
    notes: string;
  } | null>(null);
  const [savingExcuse, setSavingExcuse] = useState(false);

  // Sensitive action confirmation modal
  const [confirmState, setConfirmState] = useState<ConfirmActionState | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  // Settings & Kiosk Manager drafts
  const [settingsDraft, setSettingsDraft] = useState<CompanySettings | null>(null);
  const [kioskSecretById, setKioskSecretById] = useState<Record<string, string>>({});
  const [savingSettings, setSavingSettings] = useState(false);
  const [showAddKioskModal, setShowAddKioskModal] = useState(false);
  const [creatingKiosk, setCreatingKiosk] = useState(false);
  const [showNewKioskPass, setShowNewKioskPass] = useState(false);
  const [newKioskForm, setNewKioskForm] = useState({
    device_name: "",
    branch_name: "",
    email: "",
    password: "",
    device_secret: "",
  });

  // Security Policy (Cloudflare WAF & Turnstile) draft
  const [policyDraft, setPolicyDraft] = useState<SecurityPolicySettings | null>(null);
  const [countriesInput, setCountriesInput] = useState("");
  const [savingPolicy, setSavingPolicy] = useState(false);

  // DB RBAC Roles & Staff Assignment drafts
  const [rbacRoleDrafts, setRbacRoleDrafts] = useState<Record<string, RbacRoleDefinition>>({});
  const [savingRoleKey, setSavingRoleKey] = useState<string | null>(null);
  const [userRoleSelection, setUserRoleSelection] = useState<Record<string, string>>({});
  const [savingUserId, setSavingUserId] = useState<string | null>(null);

  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [revokingSessions, setRevokingSessions] = useState(false);
  const [revokingJti, setRevokingJti] = useState<string | null>(null);
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [exportingBackup, setExportingBackup] = useState(false);

  const lockAdminConsole = useCallback(() => {
    lockAdminSessionNow();
    setAdminUnlocked(false);
    setData(null);
    setSettingsDraft(null);
    setPolicyDraft(null);
    setRbacRoleDrafts({});
    setUserRoleSelection({});
    setKioskSecretById({});
    setStepUpPassword("");
    setShowStepUpPassword(false);
    setStepUpTotpCode("");
    setMfaSetupGate(false);
    setMfaEnrollSecret(null);
    setMfaEnrollQrUrl(null);
    setMfaActivateCode("");
    setBackupPassphrase("");
    setShowAddModal(false);
    setShowAddKioskModal(false);
    setExcuseTarget(null);
    setConfirmState(null);
    setShowPasswordModal(false);
  }, []);

  const startMfaEnrollment = useCallback(async () => {
    setMfaBusy(true);
    setMfaError(null);
    const res = await enrollAdminMfa();
    setMfaBusy(false);
    if (!res.ok || !res.secret || !res.otpauth_uri) {
      setMfaError(
        lang === "ar"
          ? "تعذر بدء إعداد المصادقة الثنائية."
          : "Unable to initialize TOTP MFA enrollment.",
      );
      return;
    }
    setMfaEnrollSecret(res.secret);
    try {
      const qrUrl = await QRCode.toDataURL(res.otpauth_uri, { width: 220, margin: 1 });
      setMfaEnrollQrUrl(qrUrl);
    } catch {
      setMfaEnrollQrUrl(null);
    }
  }, [lang]);

  const loadOverview = useCallback(async () => {
    if (!hasActiveAdminStepUp()) {
      lockAdminConsole();
      return;
    }
    setLoading(true);
    setLoadFailed(false);
    const res = await fetchHrOverview();
    if (res.ok) {
      setData(res);
      setSettingsDraft(res.settings);
      if (res.security_policy) {
        setPolicyDraft(res.security_policy);
        setCountriesInput(res.security_policy.allowed_countries.join(", "));
      }
      if (res.rbac_roles) {
        setRbacRoleDrafts(res.rbac_roles);
      }
      if (res.staff_users) {
        const nextMap: Record<string, string> = {};
        for (const su of res.staff_users) {
          nextMap[su.id] = su.role === "admin" ? (su.admin_role_key || "super_admin") : "employee";
        }
        setUserRoleSelection(nextMap);
      }
      if (res.mfa_status?.enabled) {
        setNeedsTotpInput(true);
      }
    } else if (res.error === "MFA_SETUP_REQUIRED") {
      setAdminUnlocked(false);
      setMfaSetupGate(true);
      void startMfaEnrollment();
    } else if (res.error === "MFA_REQUIRED") {
      setNeedsTotpInput(true);
      lockAdminConsole();
    } else if (
      res.error === "ADMIN_STEP_UP_REQUIRED" ||
      res.error === "ENCRYPTED_CHANNEL_REQUIRED"
    ) {
      lockAdminConsole();
    } else {
      setLoadFailed(true);
    }
    setLoading(false);
  }, [lockAdminConsole, startMfaEnrollment]);

  useEffect(() => {
    if (profile?.mfa_enabled) {
      setNeedsTotpInput(true);
    }
  }, [profile?.mfa_enabled]);

  useEffect(() => {
    if (adminUnlocked) {
      void loadOverview();
    }
  }, [adminUnlocked, loadOverview]);

  // Wipe sensitive admin data on unmount
  useEffect(() => {
    return () => {
      setData(null);
      setSettingsDraft(null);
    };
  }, []);

  // Global Escape handler for open modals
  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (confirmState && !confirmBusy) {
        setConfirmState(null);
      } else if (excuseTarget && !savingExcuse) {
        setExcuseTarget(null);
      } else if (showAddKioskModal && !creatingKiosk) {
        setShowAddKioskModal(false);
      } else if (showAddModal && !creatingEmployee) {
        setShowAddModal(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    confirmBusy,
    confirmState,
    creatingEmployee,
    creatingKiosk,
    excuseTarget,
    savingExcuse,
    showAddKioskModal,
    showAddModal,
  ]);

  // 5-minute idle auto-lock & live step-up TTL countdown
  useEffect(() => {
    if (!adminUnlocked) return;

    let idleTimer = window.setTimeout(() => {
      lockAdminConsole();
    }, 5 * 60_000);

    const resetIdleTimer = () => {
      window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(() => {
        lockAdminConsole();
      }, 5 * 60_000);
    };

    const events: Array<keyof WindowEventMap> = [
      "mousemove",
      "keydown",
      "click",
      "scroll",
      "touchstart",
    ];
    for (const ev of events) {
      window.addEventListener(ev, resetIdleTimer, { passive: true });
    }

    const countdownInterval = window.setInterval(() => {
      const remSec = Math.floor(getAdminStepUpRemainingMs() / 1000);
      setStepUpCountdownSec(remSec);
      if (remSec <= 0) {
        lockAdminConsole();
      }
    }, 1000);

    return () => {
      window.clearTimeout(idleTimer);
      window.clearInterval(countdownInterval);
      for (const ev of events) {
        window.removeEventListener(ev, resetIdleTimer);
      }
    };
  }, [adminUnlocked, lockAdminConsole]);

  const handleStepUpSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setStepUpError(null);
    setVerifyingStepUp(true);
    const res = await verifyAdminStepUp(
      stepUpPassword,
      needsTotpInput || stepUpTotpCode.trim().length > 0 ? stepUpTotpCode : undefined,
    );
    setVerifyingStepUp(false);
    if (!res.ok) {
      if (res.mfa_enabled || res.error === "MFA_CODE_REQUIRED" || res.error === "INVALID_MFA_CODE") {
        setNeedsTotpInput(true);
      }
      setStepUpError(
        res.error === "RATE_LIMITED"
          ? lang === "ar"
            ? "محاولات فاشلة متعددة. تم قفل التحقق مؤقتاً."
            : "Too many failed attempts. Verification temporarily locked."
          : res.error === "MFA_CODE_REQUIRED"
            ? lang === "ar"
              ? "حساب الإدارة محمي بـ TOTP MFA. أدخل الرمز السداسي من تطبيق المصادقة."
              : "TOTP MFA is enabled. Enter the 6-digit code from your authenticator app."
            : res.error === "INVALID_MFA_CODE"
              ? lang === "ar"
                ? "رمز المصادقة الثنائية غير صحيح أو منتهي الصلاحية."
                : "Invalid or expired 6-digit TOTP authenticator code."
              : lang === "ar"
                ? "كلمة المرور غير صحيحة لتأكيد الهوية الإدارية."
                : "Incorrect password for admin verification.",
      );
      return;
    }
    setStepUpPassword("");
    setShowStepUpPassword(false);
    setStepUpTotpCode("");
    setStepUpCountdownSec(Math.floor(getAdminStepUpRemainingMs() / 1000));
    if (res.mfa_setup_required) {
      setMfaSetupGate(true);
      await startMfaEnrollment();
      return;
    }
    setAdminUnlocked(true);
  };

  const handleActivateMfa = async (e: FormEvent, unlockAfter: boolean) => {
    e.preventDefault();
    setMfaError(null);
    setMfaBusy(true);
    const res = await activateAdminMfa(mfaActivateCode);
    setMfaBusy(false);
    if (!res.ok) {
      setMfaError(
        lang === "ar"
          ? "رمز التحقق غير صحيح. تأكد من مزامنة وقت الجهاز وأعد إدخال الأرقام الستة."
          : "Invalid 6-digit code. Check device clock and try again.",
      );
      return;
    }
    setMfaEnrollSecret(null);
    setMfaEnrollQrUrl(null);
    setMfaActivateCode("");
    setNeedsTotpInput(true);
    setStepUpCountdownSec(Math.floor(getAdminStepUpRemainingMs() / 1000));
    if (unlockAfter) {
      setMfaSetupGate(false);
      setAdminUnlocked(true);
    } else {
      setFeedback({
        type: "ok",
        text:
          lang === "ar"
            ? "تم تفعيل المصادقة الثنائية TOTP MFA (AAL2) لحساب الإدارة."
            : "TOTP MFA (AAL2) activated for Admin account.",
      });
      await loadOverview();
    }
  };

  const departments = useMemo(() => {
    const set = new Set<string>();
    for (const emp of data?.employees ?? []) {
      if (emp.department) set.add(emp.department);
    }
    return Array.from(set);
  }, [data?.employees]);

  const hasActiveRecordFilters = Boolean(
    searchQuery.trim() || departmentFilter !== "all" || statusFilter !== "all" || fromDate || toDate,
  );

  const clearRecordFilters = () => {
    setSearchQuery("");
    setDepartmentFilter("all");
    setStatusFilter("all");
    setFromDate("");
    setToDate("");
    setRecordsPage(1);
  };

  const filteredRecords = useMemo(() => {
    const list = data?.records ?? [];
    const q = searchQuery.trim().toLowerCase();
    const filtered = list.filter((rec) => {
      if (fromDate && rec.attendance_date < fromDate) return false;
      if (toDate && rec.attendance_date > toDate) return false;
      if (departmentFilter !== "all" && rec.department !== departmentFilter) return false;
      if (statusFilter !== "all" && rec.status !== statusFilter) return false;
      if (q) {
        const hay = `${rec.employee_name ?? ""} ${rec.employee_number ?? ""} ${rec.department ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const sorted = [...filtered];
    sorted.sort((a, b) => {
      if (recordSort === "name") {
        return (a.employee_name ?? "").localeCompare(b.employee_name ?? "", lang);
      }
      if (recordSort === "status") {
        const rank: Record<AttendanceStatus, number> = { late: 0, present: 1, excused: 2 };
        return rank[a.status] - rank[b.status] || b.attendance_date.localeCompare(a.attendance_date);
      }
      const dateCmp = b.attendance_date.localeCompare(a.attendance_date);
      if (dateCmp !== 0) return dateCmp;
      return (b.checked_in_at ?? "").localeCompare(a.checked_in_at ?? "");
    });
    return sorted;
  }, [data?.records, departmentFilter, fromDate, lang, recordSort, searchQuery, statusFilter, toDate]);

  const totalRecordsPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const safeRecordsPage = Math.min(recordsPage, totalRecordsPages);
  const paginatedRecords = useMemo(() => {
    const start = (safeRecordsPage - 1) * PAGE_SIZE;
    return filteredRecords.slice(start, start + PAGE_SIZE);
  }, [filteredRecords, safeRecordsPage]);

  useEffect(() => {
    setRecordsPage(1);
  }, [searchQuery, departmentFilter, statusFilter, fromDate, toDate, recordSort]);

  const filteredEmployees = useMemo(() => {
    const list = data?.employees ?? [];
    const q = empSearch.trim().toLowerCase();
    const filtered = !q
      ? [...list]
      : list.filter((emp) =>
          `${emp.full_name} ${emp.employee_number ?? ""} ${emp.department ?? ""} ${emp.email}`
            .toLowerCase()
            .includes(q),
        );

    filtered.sort((a, b) => {
      if (empSort === "name") {
        return a.full_name.localeCompare(b.full_name, lang);
      }
      if (empSort === "status") {
        if (a.is_active !== b.is_active) return a.is_active ? -1 : 1;
        return a.full_name.localeCompare(b.full_name, lang);
      }
      return (a.employee_number ?? "").localeCompare(b.employee_number ?? "", "en");
    });
    return filtered;
  }, [data?.employees, empSearch, empSort, lang]);

  const totalEmployeesPages = Math.max(1, Math.ceil(filteredEmployees.length / PAGE_SIZE));
  const safeEmployeesPage = Math.min(employeesPage, totalEmployeesPages);
  const paginatedEmployees = useMemo(() => {
    const start = (safeEmployeesPage - 1) * PAGE_SIZE;
    return filteredEmployees.slice(start, start + PAGE_SIZE);
  }, [filteredEmployees, safeEmployeesPage]);

  useEffect(() => {
    setEmployeesPage(1);
  }, [empSearch, empSort]);

  // Overview actionable daily queues
  const todayLateRecords = useMemo(() => {
    if (!data?.today_date) return [];
    return data.records.filter(
      (r) => r.attendance_date === data.today_date && r.status === "late",
    );
  }, [data]);

  const todayPendingEmployees = useMemo(() => {
    if (!data?.today_date) return [];
    const checkedIds = new Set(
      data.records
        .filter((r) => r.attendance_date === data.today_date)
        .map((r) => r.employee_id),
    );
    return data.employees.filter(
      (emp) => emp.is_active && emp.role === "employee" && !checkedIds.has(emp.id),
    );
  }, [data]);

  const formatClock = (iso: string | null) => {
    if (!iso) return "—";
    return new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(new Date(iso));
  };

  const handleExport = async () => {
    const res = await downloadHrCsvExport({
      from: fromDate || undefined,
      to: toDate || undefined,
      department: departmentFilter === "all" ? undefined : departmentFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
    });
    if (!res.ok) {
      if (res.error === "ADMIN_STEP_UP_REQUIRED") {
        lockAdminConsole();
        return;
      }
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر تصدير التقرير المشفر." : "Failed to export encrypted report.",
      });
    }
  };

  const handleCreateEmployee = async (e: FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    setCreatingEmployee(true);
    const res = await createEmployee(newEmpForm);
    setCreatingEmployee(false);
    if (!res.ok) {
      setFeedback({
        type: "err",
        text:
          res.error === "EMAIL_ALREADY_EXISTS"
            ? lang === "ar"
              ? "البريد الإلكتروني مسجل مسبقاً."
              : "Email already exists."
            : res.error === "EMPLOYEE_NUMBER_EXISTS"
              ? lang === "ar"
                ? "الرقم الوظيفي مسجل مسبقاً."
                : "Employee ID already exists."
              : res.error === "WEAK_PASSWORD"
                ? lang === "ar"
                  ? "كلمة المرور ضعيفة: يجب أن تكون 8 أحرف على الأقل وتحتوي على حروف وأرقام."
                  : "Weak password: minimum 8 characters with letters and numbers."
                : lang === "ar"
                  ? "يرجى التحقق من جميع بيانات الموظف (كلمة المرور 8 أحرف+ مع حروف وأرقام)."
                  : "Please check all employee fields (password 8+ chars with letters & numbers).",
      });
      return;
    }
    setShowAddModal(false);
    setShowNewEmpPassword(false);
    setNewEmpForm({
      full_name: "",
      email: "",
      password: "",
      employee_number: "",
      department: "تطوير البرمجيات",
      job_title: "",
      shift_start: "09:00",
      shift_end: "17:00",
    });
    setFeedback({
      type: "ok",
      text: lang === "ar" ? "تمت إضافة حساب الموظف بنجاح." : "Employee account created.",
    });
    await loadOverview();
  };

  const requestToggleEmployeeActive = (emp: Profile) => {
    const suspending = emp.is_active;
    setConfirmState({
      title: suspending
        ? lang === "ar"
          ? `إيقاف حساب ${emp.full_name}`
          : `Suspend ${emp.full_name}`
        : lang === "ar"
          ? `إعادة تفعيل حساب ${emp.full_name}`
          : `Reactivate ${emp.full_name}`,
      description: suspending
        ? lang === "ar"
          ? "سيتم منع الموظف من تسجيل الحضور والانصراف وإنهاء جلساته النشطة فوراً."
          : "This employee will immediately lose check-in access and any active sessions will be revoked."
        : lang === "ar"
          ? "سيُسمح للموظف بتسجيل الدخول واستخدام بوابة الحضور مجدداً."
          : "This employee will regain access to the attendance portal.",
      confirmLabel: suspending
        ? lang === "ar"
          ? "تأكيد الإيقاف"
          : "Confirm Suspend"
        : lang === "ar"
          ? "تأكيد التفعيل"
          : "Confirm Activate",
      danger: suspending,
      onConfirm: async () => {
        const res = await updateEmployee(emp.id, { is_active: !emp.is_active });
        if (res.ok) {
          setFeedback({
            type: "ok",
            text: suspending
              ? lang === "ar"
                ? `تم إيقاف حساب ${emp.full_name}.`
                : `${emp.full_name} suspended.`
              : lang === "ar"
                ? `تم تفعيل حساب ${emp.full_name}.`
                : `${emp.full_name} activated.`,
          });
          await loadOverview();
        } else {
          setFeedback({
            type: "err",
            text: lang === "ar" ? "تعذر تحديث حالة الحساب." : "Failed to update employee status.",
          });
        }
      },
    });
  };

  const handleSaveExcuse = async (e: FormEvent) => {
    e.preventDefault();
    if (!excuseTarget) return;
    setSavingExcuse(true);
    const res = await logEmployeeExcuse(excuseTarget);
    setSavingExcuse(false);
    if (res.ok) {
      setExcuseTarget(null);
      setFeedback({
        type: "ok",
        text: lang === "ar" ? "تم اعتماد العذر الرسمي وتحديث السجل." : "Excuse recorded.",
      });
      await loadOverview();
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر اعتماد العذر. تحقق من البيانات." : "Failed to record excuse.",
      });
    }
  };

  const handleSaveSettings = async (e: FormEvent) => {
    e.preventDefault();
    if (!settingsDraft) return;
    setSavingSettings(true);
    setFeedback(null);
    const res = await updateCompanySettings(settingsDraft);
    setSavingSettings(false);
    if (res.ok) {
      setFeedback({
        type: "ok",
        text: lang === "ar" ? "تم حفظ إعدادات الشركة والجدول الزمني والنطاق الجغرافي." : "Settings & QR schedule saved.",
      });
      await loadOverview();
    } else if (res.error === "INVALID_QR_SCHEDULE_ORDER") {
      setFeedback({
        type: "err",
        text:
          lang === "ar"
            ? "ترتيب أوقات جدول QR غير منطقي: يجب أن يكون البداية ≤ الإخفاء ≤ عودة الظهور ≤ نهاية اليوم."
            : "Invalid QR schedule time ordering: start <= cutoff <= reappear <= end.",
      });
    } else if (res.error === "INVALID_TIMEZONE") {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "المنطقة الزمنية غير صالحة." : "Invalid timezone identifier.",
      });
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر حفظ الإعدادات." : "Failed to save settings.",
      });
    }
  };

  const handleFillCurrentGps = () => {
    if (!navigator.geolocation || !settingsDraft) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setSettingsDraft({
          ...settingsDraft,
          latitude: Number(pos.coords.latitude.toFixed(6)),
          longitude: Number(pos.coords.longitude.toFixed(6)),
        });
      },
      () => {
        setFeedback({
          type: "err",
          text: lang === "ar" ? "تعذر التقاط موقع المتصفح الحالي." : "Unable to read browser GPS.",
        });
      },
      { enableHighAccuracy: true, timeout: 8000 },
    );
  };

  const handleCreateKiosk = async (e: FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    setCreatingKiosk(true);
    const res = await createKioskDevice(newKioskForm);
    setCreatingKiosk(false);
    if (!res.ok) {
      setFeedback({
        type: "err",
        text:
          res.error === "EMAIL_ALREADY_EXISTS"
            ? lang === "ar"
              ? "البريد الإلكتروني مستخدم مسبقاً."
              : "Email already exists."
            : res.error === "WEAK_PASSWORD"
              ? lang === "ar"
                ? "كلمة مرور الجهاز ضعيفة (8 أحرف+ حروف وأرقام)."
                : "Weak password (8+ chars with letters and numbers)."
              : res.error === "WEAK_SECRET"
                ? lang === "ar"
                  ? "سر اعتماد الجهاز يجب أن لا يقل عن 8 أحرف."
                  : "Device secret must be at least 8 characters."
                : lang === "ar"
                  ? "يرجى التحقق من جميع حقول جهاز الاستقبال."
                  : "Please check all kiosk terminal fields.",
      });
      return;
    }
    setShowAddKioskModal(false);
    setShowNewKioskPass(false);
    setNewKioskForm({
      device_name: "",
      branch_name: "",
      email: "",
      password: "",
      device_secret: "",
    });
    setFeedback({
      type: "ok",
      text:
        lang === "ar"
          ? `تم اعتماد جهاز الاستقبال (${res.device?.device_name ?? ""}) بنجاح.`
          : "New reception kiosk authorized.",
    });
    await loadOverview();
  };

  const requestToggleKioskActive = (dev: KioskDeviceInfo) => {
    const disabling = dev.is_active;
    setConfirmState({
      title: disabling
        ? lang === "ar"
          ? `إيقاف شاشة ${dev.device_name}`
          : `Suspend ${dev.device_name}`
        : lang === "ar"
          ? `تفعيل شاشة ${dev.device_name}`
          : `Activate ${dev.device_name}`,
      description: disabling
        ? lang === "ar"
          ? "سيتم فصل هذا الجهاز وإبطال رموزه فوراً دون التأثير على باقي شاشات الاستقبال."
          : "This kiosk will be disconnected and its QR codes invalidated without affecting other kiosks."
        : lang === "ar"
          ? "سيُسمح لهذا الجهاز بإصدار رموز الحضور مجدداً بعد إعادة تسجيل الدخول."
          : "This kiosk terminal will be allowed to issue QR tokens again.",
      confirmLabel: disabling
        ? lang === "ar"
          ? "إيقاف الجهاز"
          : "Suspend Kiosk"
        : lang === "ar"
          ? "تفعيل الجهاز"
          : "Activate Kiosk",
      danger: disabling,
      onConfirm: async () => {
        const res = await updateKioskDevice(dev.id, { is_active: !dev.is_active });
        if (res.ok) {
          setFeedback({
            type: "ok",
            text: disabling
              ? lang === "ar"
                ? `تم إيقاف جهاز ${dev.device_name}.`
                : `${dev.device_name} suspended.`
              : lang === "ar"
                ? `تم تفعيل جهاز ${dev.device_name}.`
                : `${dev.device_name} activated.`,
          });
          await loadOverview();
        } else {
          setFeedback({
            type: "err",
            text: lang === "ar" ? "تعذر تحديث حالة جهاز الاستقبال." : "Failed to update kiosk status.",
          });
        }
      },
    });
  };

  const requestRevokeKiosk = (deviceId: string, deviceName: string) => {
    const candidateSecret = (kioskSecretById[deviceId] ?? "").trim();
    setConfirmState({
      title: lang === "ar" ? `إبطال شاشة ${deviceName}` : `Revoke ${deviceName}`,
      description:
        lang === "ar"
          ? "سيتم فصل شاشة الاستقبال فوراً وإلغاء جميع رموز QR الصادرة منها، ويجب إعادة توثيقها عند المكتب."
          : "This will immediately disconnect the reception monitor and invalidate its active QR codes.",
      confirmLabel: t.hrRevokeKiosk,
      danger: true,
      onConfirm: async () => {
        const res = await revokeKioskDevice({
          device_id: deviceId,
          new_secret: candidateSecret || undefined,
        });
        if (res.ok) {
          setKioskSecretById((prev) => ({ ...prev, [deviceId]: "" }));
          setFeedback({
            type: "ok",
            text:
              lang === "ar"
                ? "تم إبطال جلسات شاشة الاستقبال النشطة."
                : "Kiosk sessions revoked successfully.",
          });
          await loadOverview();
        } else if (res.error === "WEAK_SECRET") {
          setFeedback({
            type: "err",
            text:
              lang === "ar"
                ? "سر الجهاز الجديد يجب أن يكون 8 أحرف على الأقل."
                : "New device secret must be at least 8 characters.",
          });
        }
      },
    });
  };

  const handleSaveSecurityPolicy = async (e: FormEvent) => {
    e.preventDefault();
    if (!policyDraft) return;
    const countries = countriesInput
      .split(/[,\s]+/)
      .map((c) => c.trim().toUpperCase())
      .filter((c) => /^[A-Z]{2}$/.test(c));
    setSavingPolicy(true);
    setFeedback(null);
    const res = await updateSecurityPolicy({
      ...policyDraft,
      allowed_countries: countries,
    });
    setSavingPolicy(false);
    if (res.ok) {
      setFeedback({
        type: "ok",
        text:
          lang === "ar"
            ? "تم تحديث سياسة الحماية و Cloudflare WAF على الخادم."
            : "Cloudflare WAF & security policy saved.",
      });
      await loadOverview();
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر حفظ السياسة الأمنية." : "Failed to save security policy.",
      });
    }
  };

  const handleToggleRolePerm = (roleKey: string, perm: PermissionKey) => {
    setRbacRoleDrafts((prev) => {
      const target = prev[roleKey];
      if (!target) return prev;
      if (roleKey === "super_admin" && perm === "manage_permissions") return prev;
      const exists = target.permissions.includes(perm);
      const updatedPerms = exists
        ? target.permissions.filter((p) => p !== perm)
        : [...target.permissions, perm];
      if (updatedPerms.length === 0) return prev;
      return {
        ...prev,
        [roleKey]: {
          ...target,
          permissions: updatedPerms,
        },
      };
    });
  };

  const handleSaveRbacRole = async (roleKey: string) => {
    const def = rbacRoleDrafts[roleKey];
    if (!def) return;
    setSavingRoleKey(roleKey);
    setFeedback(null);
    const res = await updateRbacRole(roleKey, def.permissions);
    setSavingRoleKey(null);
    if (res.ok) {
      setFeedback({
        type: "ok",
        text:
          lang === "ar"
            ? `تم تحديث صلاحيات دور (${def.label_ar}) في قاعدة البيانات.`
            : `Updated permissions for role ${def.label_en}.`,
      });
      await loadOverview();
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر تحديث صلاحيات الدور." : "Failed to update role permissions.",
      });
    }
  };

  const requestAssignUserRbac = (targetUser: Profile) => {
    const selected = userRoleSelection[targetUser.id] ?? "employee";
    const isPromotingAdmin = selected !== "employee";
    setConfirmState({
      title:
        lang === "ar"
          ? `تحديث صلاحيات ${targetUser.full_name}`
          : `Update Role for ${targetUser.full_name}`,
      description:
        lang === "ar"
          ? "سيتم حفظ الدور الجديد في قاعدة البيانات وإنهاء الجلسات النشطة للحساب لتطبيق الصلاحية فوراً."
          : "This updates the user role in the database and revokes active sessions immediately.",
      confirmLabel: lang === "ar" ? "اعتماد الصلاحية" : "Apply Role",
      danger: isPromotingAdmin,
      onConfirm: async () => {
        setSavingUserId(targetUser.id);
        const res = await assignUserRbac(
          targetUser.id,
          isPromotingAdmin
            ? { role: "admin", admin_role_key: selected }
            : { role: "employee", admin_role_key: null },
        );
        setSavingUserId(null);
        if (res.ok) {
          setFeedback({
            type: "ok",
            text:
              lang === "ar"
                ? `تم تحديث صلاحيات ${targetUser.full_name} بنجاح.`
                : `Updated access role for ${targetUser.full_name}.`,
          });
          await loadOverview();
        } else {
          setFeedback({
            type: "err",
            text:
              res.error === "CANNOT_DEMOTE_LAST_SUPER_ADMIN"
                ? lang === "ar"
                  ? "لا يمكن سحب صلاحية إدارة الصلاحيات من آخر مشرف أعلى نشط."
                  : "Cannot demote the last active Super Admin."
                : lang === "ar"
                  ? "تعذر تحديث صلاحيات الحساب."
                  : "Failed to update account permissions.",
          });
        }
      },
    });
  };

  const handleDownloadCatalogMd = () => {
    const mdContent = [
      "# كتالوج التسطيب والتشغيل المؤسسي — نظام ان سايت (InSight)",
      "",
      "## 1. المتطلبات الأساسية (Prerequisites)",
      "- Node.js v22 LTS + Nginx / Reverse Proxy مع HTTPS إجباري.",
      "- تفعيل متغيرات الإنتاج: NODE_ENV=production · STRICT_PROD_SECRETS=true · REQUIRE_ADMIN_MFA=true",
      "- مفتاح KMS للتشفير (32 بايت / 64 Hex): DATA_ENCRYPTION_KEY",
      "",
      "## 2. أوامر البناء والتشغيل (Build & Start)",
      "```bash",
      "npm ci",
      "npx tsc --noEmit",
      "npm run build",
      "npm test",
      "npm start",
      "```",
      "",
      "## 3. ربط حماية Cloudflare المجانية + Turnstile",
      "- تفعيل السحابة البرتقالية Proxied على سجل DNS + SSL/TLS: Full (Strict).",
      "- تفعيل Bot Fight Mode و WAF Custom Rules لحماية مسارات /api/hr/*.",
      "- إضافة Site Key من تبويب الأمان ووضع TURNSTILE_SECRET_KEY في بيئة الخادم.",
      "- تمرير ترويسات CF-Connecting-IP و CF-IPCountry و CF-Threat-Score و CF-Ray من Nginx.",
      "",
      "## 4. تشغيل شاشات الاستقبال المتعددة وجدولة الـ QR",
      "- اعتماد حساب وسر جهاز مستقل لكل بوابة من تبويب (الفروع والدوام).",
      "- ضبط جدول QR: البداية، وقت الإخفاء التلقائي، وقت رجوع الظهور، ونهاية اليوم.",
      "- تشغيل متصفح الشاشة بوضع: google-chrome --kiosk --app=https://attendance.your-org.com/kiosk",
      "",
      "## 5. الصلاحيات المرتبطة بقاعدة البيانات (RBAC)",
      "- تطبيق ترحيلات قاعدة البيانات حتى 202611190007_multi_kiosk_schedule_rbac.sql.",
      "- تخصيص الأدوار من تبويب (الصلاحيات والتحكم) وحفظ نسخة احتياطية مشفرة دورياً.",
    ].join("\n");
    const blob = new Blob([`\uFEFF${mdContent}`], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ENTERPRISE_SETUP_CATALOG.md";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleRevokeSingleSession = async (jti: string) => {
    setRevokingJti(jti);
    const res = await revokeSessionByJti(jti);
    setRevokingJti(null);
    if (res.ok) {
      setFeedback({
        type: "ok",
        text: lang === "ar" ? "تم إنهاء الجلسة المحددة بنجاح." : "Session revoked.",
      });
      await loadOverview();
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر إنهاء الجلسة." : "Failed to revoke session.",
      });
    }
  };

  const handleExportBackup = async (e: FormEvent) => {
    e.preventDefault();
    if (backupPassphrase.trim().length < 12) {
      setFeedback({
        type: "err",
        text:
          lang === "ar"
            ? "كلمة مرور النسخة الاحتياطية يجب أن تكون 12 حرفاً على الأقل."
            : "Backup passphrase must be at least 12 characters.",
      });
      return;
    }
    setExportingBackup(true);
    const res = await exportEncryptedBackup(backupPassphrase);
    setExportingBackup(false);
    if (res.ok) {
      setBackupPassphrase("");
      setFeedback({
        type: "ok",
        text:
          lang === "ar"
            ? "تم تنزيل النسخة الاحتياطية المشفّرة (PBKDF2 + AES-256-GCM) بمعزل عن مفاتيح الخادم."
            : "Encrypted isolated backup exported.",
      });
      await loadOverview();
    } else {
      setFeedback({
        type: "err",
        text: lang === "ar" ? "تعذر إنشاء النسخة الاحتياطية." : "Failed to export backup.",
      });
    }
  };

  const requestRevokeAllSessions = () => {
    setConfirmState({
      title: lang === "ar" ? "إنهاء جميع الجلسات النشطة" : "Revoke All Active Sessions",
      description:
        lang === "ar"
          ? "سيتم تسجيل خروج جميع الموظفين وأجهزة الاستقبال وإبطال رموز QR النشطة فوراً."
          : "All employees and reception terminals will be signed out immediately and active QR codes invalidated.",
      confirmLabel: lang === "ar" ? "إنهاء جميع الجلسات" : "Revoke All Sessions",
      danger: true,
      onConfirm: async () => {
        setRevokingSessions(true);
        const res = await revokeAllSessions();
        setRevokingSessions(false);
        if (res.ok) {
          setFeedback({
            type: "ok",
            text:
              lang === "ar"
                ? "تم إنهاء جميع الجلسات النشطة للموظفين وأجهزة الاستقبال وإبطال رموز QR الحالية."
                : "All employee & kiosk sessions and active QR tokens have been revoked.",
          });
          await loadOverview();
        } else {
          setFeedback({
            type: "err",
            text:
              lang === "ar"
                ? "تعذر تنفيذ أمر إنهاء الجلسات."
                : "Failed to revoke active sessions.",
          });
        }
      },
    });
  };

  const executeConfirm = async () => {
    if (!confirmState) return;
    setConfirmBusy(true);
    await confirmState.onConfirm();
    setConfirmBusy(false);
    setConfirmState(null);
  };

  const effectivePermissions = useMemo<PermissionKey[]>(
    () => data?.current_permissions ?? profile?.permissions ?? [],
    [data?.current_permissions, profile?.permissions],
  );

  const hasPerm = useCallback(
    (perm: PermissionKey) => {
      if (effectivePermissions.length === 0) return true;
      return effectivePermissions.includes(perm);
    },
    [effectivePermissions],
  );

  const tabItems = useMemo<Array<{ id: HrTab; label: string }>>(() => {
    const items: Array<{ id: HrTab; label: string }> = [
      { id: "overview", label: t.hrTabOverview },
    ];
    if (hasPerm("view_records")) {
      items.push({ id: "records", label: t.hrTabRecords });
    }
    if (hasPerm("manage_employees")) {
      items.push({ id: "employees", label: t.hrTabEmployees });
    }
    if (hasPerm("manage_settings") || hasPerm("manage_kiosks")) {
      items.push({ id: "settings", label: t.hrTabSettings });
    }
    if (hasPerm("manage_security")) {
      items.push({ id: "security", label: t.hrTabSecurity });
    }
    if (hasPerm("manage_permissions")) {
      items.push({ id: "permissions", label: t.hrTabPermissions });
    }
    items.push({ id: "catalog", label: t.hrTabCatalog });
    return items;
  }, [hasPerm, t]);

  useEffect(() => {
    if (!tabItems.some((item) => item.id === tab)) {
      setTab(tabItems[0]?.id ?? "overview");
    }
  }, [tab, tabItems]);

  const handleTabKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const prevKey = lang === "ar" ? "ArrowRight" : "ArrowLeft";
    const nextKey = lang === "ar" ? "ArrowLeft" : "ArrowRight";
    let nextIndex = -1;
    if (e.key === nextKey) nextIndex = (index + 1) % tabItems.length;
    else if (e.key === prevKey) nextIndex = (index - 1 + tabItems.length) % tabItems.length;
    else if (e.key === "Home") nextIndex = 0;
    else if (e.key === "End") nextIndex = tabItems.length - 1;

    if (nextIndex !== -1) {
      e.preventDefault();
      const targetTab = tabItems[nextIndex].id;
      setTab(targetTab);
      tabRefs.current[targetTab]?.focus();
    }
  };

  const stats = data?.stats;

  const formattedCountdown = `${String(Math.floor(stepUpCountdownSec / 60)).padStart(2, "0")}:${String(
    stepUpCountdownSec % 60,
  ).padStart(2, "0")}`;

  if (!adminUnlocked && mfaSetupGate) {
    return (
      <main className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-lg items-center px-4 py-10">
        <section className="w-full rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 space-y-5">
          <div className="space-y-2 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 text-white">
              <QrCode className="h-6 w-6" aria-hidden="true" />
            </div>
            <h1 className="text-xl font-bold text-slate-900">
              {lang === "ar"
                ? "إعداد المصادقة الثنائية الإلزامية (TOTP MFA)"
                : "Mandatory Admin TOTP MFA Setup"}
            </h1>
            <p className="text-xs leading-relaxed text-slate-600">
              {lang === "ar"
                ? "سياسة الإنتاج تشترط تفعيل TOTP (AAL2) قبل الوصول إلى بيانات الموارد البشرية. امسح الرمز بتطبيق المصادقة ثم أدخل الرمز السداسي."
                : "Production policy requires TOTP MFA (AAL2) before accessing HR data. Scan the QR code with your authenticator app and enter the 6-digit code."}
            </p>
          </div>

          {mfaEnrollQrUrl && (
            <div className="flex justify-center">
              <img
                src={mfaEnrollQrUrl}
                alt="TOTP MFA QR Code"
                className="h-44 w-44 rounded-xl border border-slate-200 bg-white p-2"
              />
            </div>
          )}

          {mfaEnrollSecret && (
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-center">
              <p className="text-xs text-slate-500">
                {lang === "ar" ? "المفتاح اليدوي (Base32)" : "Manual Base32 Secret"}
              </p>
              <p dir="ltr" className="mt-1 font-mono text-xs font-semibold text-slate-900 select-all">
                {mfaEnrollSecret}
              </p>
            </div>
          )}

          <form onSubmit={(e) => void handleActivateMfa(e, true)} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="mfa-gate-code" className="block text-xs font-semibold text-slate-700">
                {lang === "ar" ? "رمز التحقق (6 أرقام)" : "6-Digit Verification Code"}
              </label>
              <input
                id="mfa-gate-code"
                type="text"
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                required
                dir="ltr"
                value={mfaActivateCode}
                onChange={(e) => setMfaActivateCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="123456"
                className="min-h-[44px] w-full rounded-xl border border-slate-300 px-3.5 text-center font-mono text-base tracking-[0.25em] focus:border-sky-800 focus:outline-none"
              />
            </div>

            {mfaError && (
              <div
                role="alert"
                className="rounded-xl border border-red-200 bg-red-50 px-3.5 py-2.5 text-xs font-medium text-red-800"
              >
                {mfaError}
              </div>
            )}

            <div className="flex gap-2">
              <button
                type="button"
                onClick={lockAdminConsole}
                className="min-h-[44px] rounded-xl border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              >
                {lang === "ar" ? "رجوع" : "Back"}
              </button>
              <button
                type="submit"
                disabled={mfaBusy || mfaActivateCode.length !== 6}
                className="flex-1 min-h-[44px] rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
              >
                {mfaBusy
                  ? lang === "ar"
                    ? "جارٍ التفعيل..."
                    : "Activating..."
                  : lang === "ar"
                    ? "تفعيل TOTP وفتح اللوحة"
                    : "Activate TOTP & Unlock"}
              </button>
            </div>
          </form>
        </section>
      </main>
    );
  }

  if (!adminUnlocked) {
    return (
      <main className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-lg items-center px-4 py-10">
        <section className="w-full rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 space-y-6">
          <div className="space-y-2 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 text-white">
              <Lock className="h-6 w-6" aria-hidden="true" />
            </div>
            <h1 className="text-xl font-bold text-slate-900">
              {lang === "ar"
                ? "قفل الأمان الإداري — تأكيد الهوية"
                : "Admin Security Lock — Step-Up Verification"}
            </h1>
            <p className="text-xs leading-relaxed text-slate-600">
              {lang === "ar"
                ? "بيانات لوحة الموارد البشرية تُنقل فوق TLS مع طبقة تشفير تطبيقية موقّعة وتُقفل تلقائياً عند الخمول."
                : "HR Admin data uses TLS plus a signed application-layer encrypted envelope and auto-locks on idle."}
            </p>
          </div>

          <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3 text-xs text-slate-700">
            <span className="font-semibold text-slate-900">{profile?.full_name ?? "—"}</span>
            {profile?.email && (
              <>
                <span aria-hidden="true"> · </span>
                <span className="font-mono text-slate-600" dir="ltr">
                  {profile.email}
                </span>
              </>
            )}
          </div>

          <form onSubmit={handleStepUpSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="admin-stepup-password"
                className="block text-xs font-semibold text-slate-700"
              >
                {t.passwordLabel}
              </label>
              <div className="relative">
                <input
                  id="admin-stepup-password"
                  type={showStepUpPassword ? "text" : "password"}
                  required
                  dir="ltr"
                  autoFocus
                  value={stepUpPassword}
                  onChange={(e) => setStepUpPassword(e.target.value)}
                  placeholder="••••••••"
                  className="min-h-[44px] w-full rounded-xl border border-slate-300 ps-3.5 pe-11 text-sm focus:border-sky-800 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowStepUpPassword((v) => !v)}
                  aria-label={showStepUpPassword ? t.hidePasswordLabel : t.showPasswordLabel}
                  className="absolute inset-y-0 end-0 flex w-11 items-center justify-center rounded-e-xl text-slate-500 hover:text-slate-800"
                >
                  {showStepUpPassword ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            {needsTotpInput && (
              <div className="space-y-1.5">
                <label
                  htmlFor="admin-stepup-totp"
                  className="block text-xs font-semibold text-slate-700"
                >
                  {lang === "ar"
                    ? "رمز المصادقة الثنائية (TOTP 6 أرقام)"
                    : "Authenticator Code (6 digits)"}
                </label>
                <input
                  id="admin-stepup-totp"
                  type="text"
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  dir="ltr"
                  value={stepUpTotpCode}
                  onChange={(e) => setStepUpTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="123456"
                  className="min-h-[44px] w-full rounded-xl border border-slate-300 px-3.5 font-mono text-base tracking-[0.2em] focus:border-sky-800 focus:outline-none"
                />
              </div>
            )}

            {stepUpError && (
              <div
                role="alert"
                className="rounded-xl border border-red-200 bg-red-50 px-3.5 py-2.5 text-xs font-medium text-red-800"
              >
                {stepUpError}
              </div>
            )}

            <button
              type="submit"
              disabled={verifyingStepUp}
              className="inline-flex min-h-[46px] w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800 disabled:bg-slate-400"
            >
              <ShieldCheck className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>
                {verifyingStepUp
                  ? lang === "ar"
                    ? "جارٍ فتح القناة المشفّرة..."
                    : "Unlocking Encrypted Channel..."
                  : lang === "ar"
                    ? "تأكيد الهوية وفتح اللوحة المشفّرة"
                    : "Verify & Unlock Encrypted Console"}
              </span>
            </button>

            {import.meta.env.DEV && profile?.email === "hr@company.com" && (
              <button
                type="button"
                onClick={() => setStepUpPassword("Admin@2026")}
                className="w-full text-center text-xs font-medium text-sky-800 underline hover:text-sky-700"
              >
                {lang === "ar"
                  ? "تعبئة كلمة المرور التجريبية لحساب الموارد البشرية"
                  : "Fill demo HR password"}
              </button>
            )}
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 sm:py-8 space-y-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-semibold text-slate-500">
            {data?.settings.company_name ?? t.brandName}
            {data?.today_date ? (
              <>
                <span aria-hidden="true"> · </span>
                <span className="font-mono tabular-nums">{data.today_date}</span>
              </>
            ) : null}
            <span aria-hidden="true"> · </span>
            <span className="font-mono text-emerald-700 tabular-nums" dir="ltr">
              AES-256-GCM · {formattedCountdown}
            </span>
          </p>
          <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">{t.hrPageTitle}</h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={lockAdminConsole}
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-2 text-xs font-semibold text-red-800 hover:bg-red-100 whitespace-nowrap shrink-0"
          >
            <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>{lang === "ar" ? "قفل اللوحة الآن" : "Lock Console"}</span>
          </button>

          <button
            type="button"
            onClick={() => void loadOverview()}
            disabled={loading}
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
            <span>{t.retryBtn}</span>
          </button>

          {hasPerm("manage_excuses") && (
            <button
              type="button"
              onClick={() => {
                setExcuseTarget({
                  employee_id: data?.employees[0]?.id ?? "",
                  attendance_date: data?.today_date ?? new Date().toISOString().slice(0, 10),
                  notes: lang === "ar" ? "عذر رسمي معتمد" : "Approved official excuse",
                });
              }}
              className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <span>{t.hrMarkExcuse}</span>
            </button>
          )}

          {hasPerm("manage_employees") && (
            <button
              type="button"
              onClick={() => setShowAddModal(true)}
              className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 whitespace-nowrap shrink-0"
            >
              <UserPlus className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>{t.hrAddEmployee}</span>
            </button>
          )}
        </div>
      </div>

      {feedback && (
        <div
          role="status"
          aria-live="polite"
          className={`flex items-center justify-between gap-4 rounded-xl border px-4 py-3 text-sm font-medium ${
            feedback.type === "ok"
              ? "border-emerald-200 bg-emerald-50 text-emerald-900"
              : "border-red-200 bg-red-50 text-red-800"
          }`}
        >
          <span>{feedback.text}</span>
          <button type="button" onClick={() => setFeedback(null)} className="text-xs underline">
            {lang === "ar" ? "إغلاق" : "Dismiss"}
          </button>
        </div>
      )}

      {loadFailed && !loading && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
        >
          <span>{t.loadError}</span>
          <button
            type="button"
            onClick={() => void loadOverview()}
            className="rounded-lg border border-red-300 bg-white px-3 py-1.5 text-xs font-semibold text-red-800 hover:bg-red-50"
          >
            {t.retryBtn}
          </button>
        </div>
      )}

      {/* Accessible 5-Tab Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-3">
        <div
          role="tablist"
          aria-label={t.hrPageTitle}
          className="flex items-center gap-1 overflow-x-auto rounded-lg bg-slate-100 p-1 max-w-full"
        >
          {tabItems.map((item, idx) => {
            const isSelected = tab === item.id;
            return (
              <button
                key={item.id}
                ref={(el) => {
                  tabRefs.current[item.id] = el;
                }}
                type="button"
                role="tab"
                id={`hr-tab-${item.id}`}
                aria-selected={isSelected}
                aria-controls={`hr-panel-${item.id}`}
                tabIndex={isSelected ? 0 : -1}
                onClick={() => setTab(item.id)}
                onKeyDown={(e) => handleTabKeyDown(e, idx)}
                className={`rounded-md px-3.5 py-2 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-sky-700 ${
                  isSelected
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        {tab === "records" && hasPerm("export_reports") && (
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-medium text-slate-600 tabular-nums">
              {t.hrExportCountPrefix} {filteredRecords.length} {t.hrExportCountSuffix}
            </span>
            <button
              type="button"
              onClick={() => void handleExport()}
              className="inline-flex min-h-[40px] items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <Download className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{t.hrExportCsv}</span>
            </button>
          </div>
        )}
      </div>

      {/* TAB 1: Overview */}
      {tab === "overview" && (
        <div
          role="tabpanel"
          id="hr-panel-overview"
          aria-labelledby="hr-tab-overview"
          className="space-y-6"
        >
          {/* Executive KPI Strip */}
          <section
            aria-label={t.hrTabOverview}
            className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5"
          >
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <p className="text-xs font-medium text-slate-500">{t.hrKpiActiveEmployees}</p>
              <p className="mt-1.5 font-mono text-2xl font-bold text-slate-900 tabular-nums">
                {stats?.total_active_employees ?? "—"}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <p className="text-xs font-medium text-slate-500">{t.hrKpiPresentToday}</p>
              <p className="mt-1.5 font-mono text-2xl font-bold text-emerald-700 tabular-nums">
                {stats?.checked_in_today ?? "—"}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <p className="text-xs font-medium text-slate-500">{t.hrKpiOnShiftNow}</p>
              <p className="mt-1.5 font-mono text-2xl font-bold text-sky-800 tabular-nums">
                {stats?.on_shift_now ?? "—"}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <p className="text-xs font-medium text-slate-500">{t.hrKpiLateToday}</p>
              <p className="mt-1.5 font-mono text-2xl font-bold text-amber-700 tabular-nums">
                {stats?.late_today ?? "—"}
              </p>
            </div>
            <div className="col-span-2 rounded-xl border border-slate-200 bg-white p-4 sm:col-span-1">
              <p className="text-xs font-medium text-slate-500">{t.hrKpiPendingToday}</p>
              <p className="mt-1.5 font-mono text-2xl font-bold text-slate-700 tabular-nums">
                {stats?.not_checked_in_today ?? "—"}
              </p>
            </div>
          </section>

          {/* Actionable Daily Queues */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Late Arrivals Today */}
            <section className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h2 className="text-base font-bold text-slate-900">{t.hrLateTodayList}</h2>
                <span className="font-mono text-xs font-semibold text-amber-700 tabular-nums">
                  {todayLateRecords.length}
                </span>
              </div>
              {todayLateRecords.length === 0 ? (
                <p className="py-6 text-center text-sm text-slate-500">
                  {lang === "ar"
                    ? "لا توجد حالات تأخير مسجلة اليوم."
                    : "No late arrivals recorded today."}
                </p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {todayLateRecords.map((rec) => (
                    <li key={rec.id} className="flex items-center justify-between gap-3 py-3 text-sm">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-slate-900">{rec.employee_name}</p>
                        <p className="font-mono text-xs text-slate-500 tabular-nums">
                          {rec.employee_number ?? "—"} · {formatClock(rec.checked_in_at)} ·{" "}
                          <span className="text-amber-700">
                            {rec.late_minutes} {t.minutesUnit}
                          </span>
                        </p>
                      </div>
                      {hasPerm("manage_excuses") && (
                        <button
                          type="button"
                          onClick={() =>
                            setExcuseTarget({
                              employee_id: rec.employee_id,
                              attendance_date: rec.attendance_date,
                              notes: lang === "ar" ? "عذر تأخير معتمد" : "Approved late excuse",
                            })
                          }
                          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
                        >
                          {t.hrMarkExcuse}
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {/* Pending Check-In Today */}
            <section className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h2 className="text-base font-bold text-slate-900">{t.hrPendingTodayList}</h2>
                <span className="font-mono text-xs font-semibold text-slate-700 tabular-nums">
                  {todayPendingEmployees.length}
                </span>
              </div>
              {todayPendingEmployees.length === 0 ? (
                <p className="py-6 text-center text-sm text-slate-500">
                  {lang === "ar"
                    ? "سجّل جميع الموظفين النشطين حضورهم اليوم."
                    : "All active employees have checked in today."}
                </p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {todayPendingEmployees.map((emp) => (
                    <li key={emp.id} className="flex items-center justify-between gap-3 py-3 text-sm">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-slate-900">{emp.full_name}</p>
                        <p className="text-xs text-slate-500">
                          {emp.department ?? "—"} ·{" "}
                          <span className="font-mono tabular-nums" dir="ltr">
                            {emp.shift_start}
                          </span>
                        </p>
                      </div>
                      {hasPerm("manage_excuses") && (
                        <button
                          type="button"
                          onClick={() =>
                            setExcuseTarget({
                              employee_id: emp.id,
                              attendance_date: data?.today_date ?? new Date().toISOString().slice(0, 10),
                              notes: lang === "ar" ? "إجازة / عذر رسمي" : "Approved absence excuse",
                            })
                          }
                          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
                        >
                          {t.hrMarkExcuse}
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </div>
      )}

      {/* TAB 2: Attendance Records & Reports */}
      {tab === "records" && (
        <section
          role="tabpanel"
          id="hr-panel-records"
          aria-labelledby="hr-tab-records"
          className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 space-y-5"
        >
          {/* Filter & Sort Bar */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-12">
            <div className="relative lg:col-span-3">
              <Search
                className="pointer-events-none absolute top-1/2 start-3 h-4 w-4 -translate-y-1/2 text-slate-400"
                aria-hidden="true"
              />
              <input
                type="search"
                aria-label={t.hrSearchPlaceholder}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t.hrSearchPlaceholder}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 ps-9 pe-3 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
              />
            </div>

            <div className="lg:col-span-2">
              <select
                aria-label={t.departmentLabel}
                value={departmentFilter}
                onChange={(e) => setDepartmentFilter(e.target.value)}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
              >
                <option value="all">{t.hrAllDepartments}</option>
                {departments.map((dept) => (
                  <option key={dept} value={dept}>
                    {dept}
                  </option>
                ))}
              </select>
            </div>

            <div className="lg:col-span-2">
              <input
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
                aria-label={lang === "ar" ? "من تاريخ" : "From date"}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 px-2.5 py-1.5 font-mono text-xs text-slate-900"
              />
            </div>

            <div className="lg:col-span-2">
              <input
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
                aria-label={lang === "ar" ? "إلى تاريخ" : "To date"}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 px-2.5 py-1.5 font-mono text-xs text-slate-900"
              />
            </div>

            <div className="lg:col-span-1">
              <select
                aria-label={t.statusCol}
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as "all" | AttendanceStatus)}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
              >
                <option value="all">{t.allFilter}</option>
                <option value="present">{t.presentLabel}</option>
                <option value="late">{t.lateLabel}</option>
                <option value="excused">{t.excusedLabel}</option>
              </select>
            </div>

            <div className="lg:col-span-2 flex items-center gap-2">
              <select
                aria-label={lang === "ar" ? "ترتيب النتائج" : "Sort records"}
                value={recordSort}
                onChange={(e) => setRecordSort(e.target.value as RecordSortKey)}
                className="min-h-[40px] w-full rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
              >
                <option value="newest">{t.hrSortNewest}</option>
                <option value="name">{t.hrSortName}</option>
                <option value="status">{t.hrSortStatus}</option>
              </select>

              {hasActiveRecordFilters && (
                <button
                  type="button"
                  onClick={clearRecordFilters}
                  className="min-h-[40px] rounded-lg border border-slate-300 bg-slate-50 px-3 text-xs font-semibold text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0"
                >
                  {t.hrClearFilters}
                </button>
              )}
            </div>
          </div>

          {paginatedRecords.length === 0 ? (
            <div className="py-12 text-center space-y-3">
              <p className="text-sm text-slate-500">
                {hasActiveRecordFilters ? t.hrNoFilterMatches : t.historyEmpty}
              </p>
              {hasActiveRecordFilters && (
                <button
                  type="button"
                  onClick={clearRecordFilters}
                  className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50"
                >
                  {t.hrClearFilters}
                </button>
              )}
            </div>
          ) : (
            <>
              {/* Mobile Card View */}
              <div className="space-y-3 md:hidden">
                {paginatedRecords.map((rec) => (
                  <article
                    key={rec.id}
                    className="rounded-xl border border-slate-200 bg-slate-50/50 p-4 space-y-2.5"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-sm font-bold text-slate-900">{rec.employee_name}</p>
                        <p className="font-mono text-xs text-slate-500 tabular-nums">
                          {rec.employee_number ?? "—"} · {rec.department ?? "—"}
                        </p>
                      </div>
                      <span
                        className={`text-xs font-semibold ${
                          rec.status === "excused"
                            ? "text-sky-700"
                            : rec.status === "late"
                              ? "text-amber-700"
                              : "text-emerald-700"
                        }`}
                      >
                        {rec.status === "excused"
                          ? t.excusedLabel
                          : rec.status === "late"
                            ? `${t.lateLabel} (${rec.late_minutes} ${t.minutesUnit})`
                            : t.presentLabel}
                      </span>
                    </div>
                    <div className="grid grid-cols-3 gap-2 border-t border-slate-200/70 pt-2 text-xs">
                      <div>
                        <span className="block text-[11px] text-slate-500">{t.dateCol}</span>
                        <span className="font-mono text-slate-900 tabular-nums">
                          {rec.attendance_date}
                        </span>
                      </div>
                      <div>
                        <span className="block text-[11px] text-slate-500">{t.checkInCol}</span>
                        <span className="font-mono text-slate-900 tabular-nums">
                          {formatClock(rec.checked_in_at)}
                        </span>
                      </div>
                      <div>
                        <span className="block text-[11px] text-slate-500">{t.checkOutCol}</span>
                        <span className="font-mono text-slate-900 tabular-nums">
                          {formatClock(rec.checked_out_at)}
                        </span>
                      </div>
                    </div>
                  </article>
                ))}
              </div>

              {/* Desktop Table View */}
              <div className="hidden overflow-x-auto md:block">
                <table className="w-full text-start text-xs sm:text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                      <th className="py-3 pe-3 text-start">{t.hrEmployeeCol}</th>
                      <th className="py-3 px-2 text-start">{t.departmentLabel}</th>
                      <th className="py-3 px-2 text-start">{t.dateCol}</th>
                      <th className="py-3 px-2 text-start">{t.checkInCol}</th>
                      <th className="py-3 px-2 text-start">{t.checkOutCol}</th>
                      <th className="py-3 px-2 text-start">{t.hoursCol}</th>
                      <th className="py-3 ps-2 text-start">{t.statusCol}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {paginatedRecords.map((rec) => (
                      <tr key={rec.id} className="hover:bg-slate-50/70">
                        <td className="py-2.5 pe-3">
                          <div className="font-semibold text-slate-900">{rec.employee_name}</div>
                          <div className="font-mono text-xs text-slate-500 tabular-nums">
                            {rec.employee_number ?? "—"}
                          </div>
                        </td>
                        <td className="py-2.5 px-2 text-xs text-slate-600">
                          {rec.department ?? "—"}
                        </td>
                        <td className="whitespace-nowrap py-2.5 px-2 font-mono text-xs text-slate-800 tabular-nums">
                          {rec.attendance_date}
                        </td>
                        <td className="whitespace-nowrap py-2.5 px-2 font-mono text-xs text-slate-800 tabular-nums">
                          {formatClock(rec.checked_in_at)}
                        </td>
                        <td className="whitespace-nowrap py-2.5 px-2 font-mono text-xs text-slate-800 tabular-nums">
                          {formatClock(rec.checked_out_at)}
                        </td>
                        <td className="whitespace-nowrap py-2.5 px-2 font-mono text-xs text-slate-700 tabular-nums">
                          {formatDuration(rec.worked_minutes, lang)}
                        </td>
                        <td className="whitespace-nowrap py-2.5 ps-2 text-xs font-semibold">
                          {rec.status === "excused" ? (
                            <span className="text-sky-700">
                              {t.excusedLabel}
                              {rec.notes ? ` · ${rec.notes}` : ""}
                            </span>
                          ) : rec.status === "late" ? (
                            <span className="text-amber-700">
                              {t.lateLabel} ({rec.late_minutes} {t.minutesUnit})
                            </span>
                          ) : (
                            <span className="text-emerald-700">{t.presentLabel}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              {totalRecordsPages > 1 && (
                <div className="flex items-center justify-between border-t border-slate-100 pt-4 text-xs">
                  <button
                    type="button"
                    disabled={safeRecordsPage <= 1}
                    onClick={() => setRecordsPage((p) => Math.max(1, p - 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <ChevronRight className="h-3.5 w-3.5 rtl:rotate-0 ltr:rotate-180" aria-hidden="true" />
                    <span>{t.hrPrevPage}</span>
                  </button>
                  <span className="font-mono text-slate-600 tabular-nums">
                    {safeRecordsPage} / {totalRecordsPages}
                  </span>
                  <button
                    type="button"
                    disabled={safeRecordsPage >= totalRecordsPages}
                    onClick={() => setRecordsPage((p) => Math.min(totalRecordsPages, p + 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <span>{t.hrNextPage}</span>
                    <ChevronLeft className="h-3.5 w-3.5 rtl:rotate-0 ltr:rotate-180" aria-hidden="true" />
                  </button>
                </div>
              )}
            </>
          )}
        </section>
      )}

      {/* TAB 3: Employees Directory */}
      {tab === "employees" && (
        <section
          role="tabpanel"
          id="hr-panel-employees"
          aria-labelledby="hr-tab-employees"
          className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-1 flex-wrap items-center gap-3">
              <div className="relative w-full max-w-sm">
                <Search
                  className="pointer-events-none absolute top-1/2 start-3 h-4 w-4 -translate-y-1/2 text-slate-400"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  aria-label={t.hrSearchPlaceholder}
                  value={empSearch}
                  onChange={(e) => setEmpSearch(e.target.value)}
                  placeholder={t.hrSearchPlaceholder}
                  className="min-h-[40px] w-full rounded-lg border border-slate-300 ps-9 pe-3 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
                />
              </div>

              <select
                aria-label={lang === "ar" ? "ترتيب الموظفين" : "Sort employees"}
                value={empSort}
                onChange={(e) => setEmpSort(e.target.value as EmployeeSortKey)}
                className="min-h-[40px] rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-900 focus:border-sky-800 focus:outline-none"
              >
                <option value="number">{t.employeeNumberLabel}</option>
                <option value="name">{t.hrSortName}</option>
                <option value="status">{t.hrSortStatus}</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setShowAddModal(true)}
              className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 whitespace-nowrap shrink-0"
            >
              <Plus className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{t.hrAddEmployee}</span>
            </button>
          </div>

          {paginatedEmployees.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-500">
              {t.hrNoFilterMatches}
            </p>
          ) : (
            <>
              {/* Mobile Cards */}
              <div className="space-y-3 md:hidden">
                {paginatedEmployees.map((emp) => (
                  <article
                    key={emp.id}
                    className="rounded-xl border border-slate-200 bg-slate-50/50 p-4 space-y-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-sm font-bold text-slate-900">{emp.full_name}</p>
                        <p className="font-mono text-xs text-slate-500 tabular-nums" dir="ltr">
                          {emp.employee_number ?? "—"} · {emp.email}
                        </p>
                      </div>
                      <span
                        className={`text-xs font-semibold ${
                          emp.is_active ? "text-emerald-700" : "text-red-700"
                        }`}
                      >
                        {emp.is_active
                          ? lang === "ar"
                            ? "نشط"
                            : "Active"
                          : lang === "ar"
                            ? "موقوف"
                            : "Suspended"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between border-t border-slate-200/70 pt-2.5 text-xs">
                      <span className="text-slate-600">
                        {emp.department ?? "—"} ·{" "}
                        <span className="font-mono tabular-nums" dir="ltr">
                          {emp.shift_start}–{emp.shift_end}
                        </span>
                      </span>
                      <button
                        type="button"
                        onClick={() => requestToggleEmployeeActive(emp)}
                        className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                      >
                        {emp.is_active
                          ? lang === "ar"
                            ? "إيقاف"
                            : "Suspend"
                          : lang === "ar"
                            ? "تفعيل"
                            : "Activate"}
                      </button>
                    </div>
                  </article>
                ))}
              </div>

              {/* Desktop Table */}
              <div className="hidden overflow-x-auto md:block">
                <table className="w-full text-start text-xs sm:text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                      <th className="py-3 pe-3 text-start">{t.employeeNumberLabel}</th>
                      <th className="py-3 px-2 text-start">{t.hrEmployeeCol}</th>
                      <th className="py-3 px-2 text-start">{t.hrDepartmentCol}</th>
                      <th className="py-3 px-2 text-start">{t.shiftLabel}</th>
                      <th className="py-3 px-2 text-start">{t.statusCol}</th>
                      <th className="py-3 ps-2 text-start">{t.hrActionsCol}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {paginatedEmployees.map((emp) => (
                      <tr key={emp.id} className="hover:bg-slate-50/70">
                        <td className="whitespace-nowrap py-3 pe-3 font-mono text-xs font-semibold text-slate-900 tabular-nums">
                          {emp.employee_number ?? "—"}
                        </td>
                        <td className="py-3 px-2">
                          <div className="font-semibold text-slate-900">{emp.full_name}</div>
                          <div className="font-mono text-xs text-slate-500" dir="ltr">
                            {emp.email}
                          </div>
                        </td>
                        <td className="py-3 px-2 text-xs text-slate-700">
                          <div>{emp.department ?? "—"}</div>
                          <div className="text-slate-500">{emp.job_title ?? "—"}</div>
                        </td>
                        <td
                          className="whitespace-nowrap py-3 px-2 font-mono text-xs text-slate-700 tabular-nums"
                          dir="ltr"
                        >
                          {emp.shift_start} — {emp.shift_end}
                        </td>
                        <td className="whitespace-nowrap py-3 px-2 text-xs font-semibold">
                          {emp.is_active ? (
                            <span className="text-emerald-700">
                              {lang === "ar" ? "نشط" : "Active"}
                            </span>
                          ) : (
                            <span className="text-red-700">
                              {lang === "ar" ? "موقوف" : "Suspended"}
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap py-3 ps-2">
                          <button
                            type="button"
                            onClick={() => requestToggleEmployeeActive(emp)}
                            className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                          >
                            {emp.is_active
                              ? lang === "ar"
                                ? "إيقاف"
                                : "Suspend"
                              : lang === "ar"
                                ? "تفعيل"
                                : "Activate"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalEmployeesPages > 1 && (
                <div className="flex items-center justify-between border-t border-slate-100 pt-4 text-xs">
                  <button
                    type="button"
                    disabled={safeEmployeesPage <= 1}
                    onClick={() => setEmployeesPage((p) => Math.max(1, p - 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <ChevronRight className="h-3.5 w-3.5 rtl:rotate-0 ltr:rotate-180" aria-hidden="true" />
                    <span>{t.hrPrevPage}</span>
                  </button>
                  <span className="font-mono text-slate-600 tabular-nums">
                    {safeEmployeesPage} / {totalEmployeesPages}
                  </span>
                  <button
                    type="button"
                    disabled={safeEmployeesPage >= totalEmployeesPages}
                    onClick={() => setEmployeesPage((p) => Math.min(totalEmployeesPages, p + 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <span>{t.hrNextPage}</span>
                    <ChevronLeft className="h-3.5 w-3.5 rtl:rotate-0 ltr:rotate-180" aria-hidden="true" />
                  </button>
                </div>
              )}
            </>
          )}
        </section>
      )}

      {/* TAB 4: Company Geofence, Shift & Kiosk Settings */}
      {tab === "settings" && settingsDraft && (
        <div
          role="tabpanel"
          id="hr-panel-settings"
          aria-labelledby="hr-tab-settings"
          className="grid grid-cols-1 gap-6 lg:grid-cols-12"
        >
          <form
            onSubmit={handleSaveSettings}
            className="rounded-2xl border border-slate-200 bg-white p-6 space-y-6 lg:col-span-7"
          >
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
              <h2 className="text-base font-bold text-slate-900">
                {lang === "ar"
                  ? "إعدادات المقر والدوام والنطاق الجغرافي"
                  : "Company Shift & Geofence Settings"}
              </h2>
              <button
                type="button"
                onClick={handleFillCurrentGps}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap"
              >
                <MapPin className="h-3.5 w-3.5 text-sky-700" aria-hidden="true" />
                <span>{t.hrUseMyLocation}</span>
              </button>
            </div>

            {/* Section 1: Company & Branch */}
            <fieldset className="space-y-3">
              <legend className="text-xs font-bold text-slate-500">
                {lang === "ar" ? "بيانات الشركة والفرع" : "Organization & Branch"}
              </legend>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <label htmlFor="cfg-company" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "اسم الشركة" : "Company Name"}
                  </label>
                  <input
                    id="cfg-company"
                    type="text"
                    value={settingsDraft.company_name}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, company_name: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-branch" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "الفرع / المقر" : "Branch Name"}
                  </label>
                  <input
                    id="cfg-branch"
                    type="text"
                    value={settingsDraft.branch_name}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, branch_name: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                  />
                </div>
              </div>
            </fieldset>

            {/* Section 2: Geofence & Coordinates */}
            <fieldset className="space-y-3 border-t border-slate-100 pt-4">
              <legend className="text-xs font-bold text-slate-500">
                {lang === "ar" ? "الإحداثيات والنطاق الجغرافي" : "GPS Coordinates & Geofence"}
              </legend>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <label htmlFor="cfg-lat" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "خط العرض (Latitude)" : "Latitude"}
                  </label>
                  <input
                    id="cfg-lat"
                    type="number"
                    step="any"
                    dir="ltr"
                    value={settingsDraft.latitude}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, latitude: Number(e.target.value) })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-lng" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "خط الطول (Longitude)" : "Longitude"}
                  </label>
                  <input
                    id="cfg-lng"
                    type="number"
                    step="any"
                    dir="ltr"
                    value={settingsDraft.longitude}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, longitude: Number(e.target.value) })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-radius" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "نطاق السماح (متر)" : "Allowed Radius (m)"}
                  </label>
                  <input
                    id="cfg-radius"
                    type="number"
                    dir="ltr"
                    value={settingsDraft.allowed_radius_m}
                    onChange={(e) =>
                      setSettingsDraft({
                        ...settingsDraft,
                        allowed_radius_m: Number(e.target.value),
                      })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
              </div>

              <label
                htmlFor="cfg-enforce-geo"
                className="flex items-center justify-between gap-3 pt-1 text-sm"
              >
                <span className="font-medium text-slate-800">
                  {lang === "ar"
                    ? "تفعيل التحقق الجغرافي الصارم (منع التسجيل خارج نطاق المقر)"
                    : "Enforce strict GPS geofence boundary"}
                </span>
                <input
                  id="cfg-enforce-geo"
                  type="checkbox"
                  checked={settingsDraft.enforce_geofence}
                  onChange={(e) =>
                    setSettingsDraft({ ...settingsDraft, enforce_geofence: e.target.checked })
                  }
                  className="h-4 w-4 accent-slate-900"
                />
              </label>
            </fieldset>

            {/* Section 3: Shift & QR TTL */}
            <fieldset className="space-y-3 border-t border-slate-100 pt-4">
              <legend className="text-xs font-bold text-slate-500">
                {lang === "ar" ? "الوردية وإعدادات رمز QR" : "Shift Schedule & QR TTL"}
              </legend>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <label htmlFor="cfg-start" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "بداية الدوام الرسمي" : "Shift Start Time"}
                  </label>
                  <input
                    id="cfg-start"
                    type="time"
                    dir="ltr"
                    value={settingsDraft.work_start_time}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, work_start_time: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-grace" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "فترة السماح للتأخير (دقيقة)" : "Late Grace (min)"}
                  </label>
                  <input
                    id="cfg-grace"
                    type="number"
                    dir="ltr"
                    value={settingsDraft.late_grace_minutes}
                    onChange={(e) =>
                      setSettingsDraft({
                        ...settingsDraft,
                        late_grace_minutes: Number(e.target.value),
                      })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-ttl" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "صلاحية رمز QR (ثانية)" : "QR TTL (seconds)"}
                  </label>
                  <input
                    id="cfg-ttl"
                    type="number"
                    dir="ltr"
                    value={settingsDraft.qr_ttl_seconds}
                    onChange={(e) =>
                      setSettingsDraft({
                        ...settingsDraft,
                        qr_ttl_seconds: Number(e.target.value),
                      })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
              </div>

              <label
                htmlFor="cfg-enabled"
                className="flex items-center justify-between gap-3 pt-1 text-sm"
              >
                <span className="font-medium text-slate-800">
                  {lang === "ar"
                    ? "تشغيل خدمة تسجيل الحضور والانصراف"
                    : "Attendance service enabled"}
                </span>
                <input
                  id="cfg-enabled"
                  type="checkbox"
                  checked={settingsDraft.is_enabled}
                  onChange={(e) =>
                    setSettingsDraft({ ...settingsDraft, is_enabled: e.target.checked })
                  }
                  className="h-4 w-4 accent-slate-900"
                />
              </label>
            </fieldset>

            {/* Section 4: QR Capture Cutoff & Reappear Schedule */}
            <fieldset className="space-y-3 border-t border-slate-100 pt-4">
              <legend className="text-xs font-bold text-slate-500">
                {lang === "ar"
                  ? "جدولة التقاط وإخفاء رمز QR تلقائياً"
                  : "QR Capture Cutoff & Auto-Reappear Schedule"}
              </legend>

              <label
                htmlFor="cfg-qr-sched-enabled"
                className="flex items-center justify-between gap-3 text-sm"
              >
                <span className="font-medium text-slate-800">
                  {lang === "ar"
                    ? "تفعيل إخفاء الـ QR تلقائياً بعد آخر وقت للالتقاط وإعادته حسب الجدول"
                    : "Automatically hide QR after cutoff time and reappear at checkout window"}
                </span>
                <input
                  id="cfg-qr-sched-enabled"
                  type="checkbox"
                  checked={Boolean(settingsDraft.qr_schedule_enabled)}
                  onChange={(e) =>
                    setSettingsDraft({ ...settingsDraft, qr_schedule_enabled: e.target.checked })
                  }
                  className="h-4 w-4 accent-slate-900"
                />
              </label>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <label htmlFor="cfg-qr-start" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "بداية نافذة الصباح" : "Morning Open"}
                  </label>
                  <input
                    id="cfg-qr-start"
                    type="time"
                    dir="ltr"
                    disabled={!settingsDraft.qr_schedule_enabled}
                    value={settingsDraft.qr_window_start}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, qr_window_start: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm disabled:bg-slate-50 disabled:text-slate-400"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-qr-cutoff" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "آخر وقت للالتقاط (إخفاء)" : "Cutoff (Hide QR)"}
                  </label>
                  <input
                    id="cfg-qr-cutoff"
                    type="time"
                    dir="ltr"
                    disabled={!settingsDraft.qr_schedule_enabled}
                    value={settingsDraft.qr_cutoff_time}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, qr_cutoff_time: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm disabled:bg-slate-50 disabled:text-slate-400"
                  />
                </div>
                <div className="space-y-1">
                  <label
                    htmlFor="cfg-qr-reappear"
                    className="block text-xs font-semibold text-slate-700"
                  >
                    {lang === "ar" ? "وقت رجوع الظهور" : "Reappear Time"}
                  </label>
                  <input
                    id="cfg-qr-reappear"
                    type="time"
                    dir="ltr"
                    disabled={!settingsDraft.qr_schedule_enabled}
                    value={settingsDraft.qr_reappear_time}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, qr_reappear_time: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm disabled:bg-slate-50 disabled:text-slate-400"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="cfg-qr-end" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "إغلاق المساء" : "Evening Close"}
                  </label>
                  <input
                    id="cfg-qr-end"
                    type="time"
                    dir="ltr"
                    disabled={!settingsDraft.qr_schedule_enabled}
                    value={settingsDraft.qr_window_end}
                    onChange={(e) =>
                      setSettingsDraft({ ...settingsDraft, qr_window_end: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm disabled:bg-slate-50 disabled:text-slate-400"
                  />
                </div>
              </div>
              <p className="text-xs leading-relaxed text-slate-500">
                {lang === "ar"
                  ? "خارج هذه النوافذ، يُخفى رمز QR تلقائياً من جميع شاشات الاستقبال ويرفض الخادم أي محاولة تسجيل."
                  : "Outside these windows, QR codes automatically hide from kiosks and check-in/out scans are blocked server-side."}
              </p>
            </fieldset>

            {hasPerm("manage_settings") ? (
              <button
                type="submit"
                disabled={savingSettings}
                className="min-h-[44px] rounded-xl bg-slate-900 px-6 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-300"
              >
                {t.hrSaveSettings}
              </button>
            ) : (
              <p className="text-xs font-medium text-amber-800">{t.hrPermissionDeniedBanner}</p>
            )}
          </form>

          {/* Multi-Device Kiosk Terminals */}
          <div className="space-y-6 lg:col-span-5">
            <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <Monitor className="h-4 w-4 text-slate-700" aria-hidden="true" />
                  <h2 className="text-base font-bold text-slate-900">
                    {lang === "ar" ? "أجهزة شاشة الاستقبال (Kiosk)" : "Reception Kiosk Terminals"}
                  </h2>
                </div>
                {hasPerm("manage_kiosks") && (
                  <button
                    type="button"
                    onClick={() => setShowAddKioskModal(true)}
                    className="inline-flex min-h-[36px] items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 whitespace-nowrap"
                  >
                    <Plus className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    <span>{t.hrAddKioskBtn}</span>
                  </button>
                )}
              </div>

              {(data?.kiosk_devices ?? []).length === 0 ? (
                <p className="py-6 text-center text-xs text-slate-500">
                  {lang === "ar" ? "لا توجد أجهزة استقبال معتمدة." : "No kiosk terminals authorized."}
                </p>
              ) : (
                <div className="space-y-4">
                  {(data?.kiosk_devices ?? []).map((dev) => (
                    <div
                      key={dev.id}
                      className="rounded-xl border border-slate-200 bg-slate-50/60 p-4 space-y-3"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-bold text-slate-900">{dev.device_name}</p>
                          <p className="text-xs text-slate-600">{dev.branch_name}</p>
                          <p className="mt-0.5 font-mono text-[11px] text-slate-500 tabular-nums" dir="ltr">
                            {dev.auth_email ?? "—"} · {dev.last_seen_at ? formatClock(dev.last_seen_at) : "—"}
                          </p>
                        </div>
                        <span
                          className={`text-xs font-semibold shrink-0 ${
                            dev.is_active ? "text-emerald-700" : "text-red-700"
                          }`}
                        >
                          {dev.is_active
                            ? lang === "ar"
                              ? "مُعتمد ونشط"
                              : "Active"
                            : lang === "ar"
                              ? "موقوف"
                              : "Suspended"}
                        </span>
                      </div>

                      {hasPerm("manage_kiosks") && (
                        <div className="space-y-2 border-t border-slate-200/70 pt-3">
                          <label htmlFor={`kiosk-secret-${dev.id}`} className="sr-only">
                            {lang === "ar" ? "سر جديد للجهاز" : "New kiosk device secret"}
                          </label>
                          <input
                            id={`kiosk-secret-${dev.id}`}
                            type="password"
                            dir="ltr"
                            value={kioskSecretById[dev.id] ?? ""}
                            onChange={(e) =>
                              setKioskSecretById((prev) => ({ ...prev, [dev.id]: e.target.value }))
                            }
                            placeholder={
                              lang === "ar"
                                ? "سر جديد لتدوير الجهاز (اختياري، 8 أحرف+)"
                                : "Optional new device secret (8+ chars)"
                            }
                            className="min-h-[38px] w-full rounded-lg border border-slate-300 bg-white px-3 text-xs"
                          />
                          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                            <button
                              type="button"
                              onClick={() => requestToggleKioskActive(dev)}
                              className="inline-flex min-h-[38px] items-center justify-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100"
                            >
                              <Power className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                              <span>
                                {dev.is_active
                                  ? lang === "ar"
                                    ? "تعطيل الجهاز"
                                    : "Suspend Device"
                                  : lang === "ar"
                                    ? "إعادة تفعيل"
                                    : "Reactivate"}
                              </span>
                            </button>
                            <button
                              type="button"
                              onClick={() => requestRevokeKiosk(dev.id, dev.device_name)}
                              className="min-h-[38px] rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-800 hover:bg-red-100"
                            >
                              {lang === "ar" ? "إبطال وتدوير السر" : "Revoke & Rotate"}
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      )}

      {/* TAB 5: Security, Cloudflare Free WAF & Audit */}
      {tab === "security" && (
        <div
          role="tabpanel"
          id="hr-panel-security"
          aria-labelledby="hr-tab-security"
          className="grid grid-cols-1 gap-6 lg:grid-cols-12"
        >
          {/* Left Column: MFA, Cloudflare Free WAF Policy, Backup, Password & Kill Switch */}
          <div className="space-y-6 lg:col-span-5">
            <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
              <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-emerald-700" aria-hidden="true" />
                  <h2 className="text-base font-bold text-slate-900">
                    {lang === "ar"
                      ? "حماية البيانات والمصادقة (MFA)"
                      : "Data Protection & TOTP MFA"}
                  </h2>
                </div>
                <span className="font-mono text-xs font-semibold text-slate-700 tabular-nums" dir="ltr">
                  {data?.mfa_status?.enabled ? "TOTP · AAL2" : "AAL1"}
                </span>
              </div>

              <div className="space-y-2 text-xs leading-relaxed text-slate-700">
                <p>
                  {lang === "ar"
                    ? "النقل الموقّع (ECDSA P-256 + ECDH + AES-256-GCM) يعمل كطبقة مساندة فوق HTTPS/TLS لتغليف بيانات الموارد البشرية."
                    : "Signed ECDH + ECDSA P-256 + AES-256-GCM envelope complements mandatory HTTPS/TLS transport."}
                </p>
                <p>
                  {lang === "ar"
                    ? "عزل المفاتيح عبر KMS + مهلة خمول وعمر مطلق للجلسات + جدار حماية SQLi/XSS وRate Limiting موزع."
                    : "KMS key isolation, bounded session lifetimes, SQLi/XSS WAF, and distributed rate limiting."}
                </p>
              </div>

              {/* TOTP MFA Enrollment */}
              {!data?.mfa_status?.enabled && (
                <div className="border-t border-slate-100 pt-3 space-y-3">
                  {!mfaEnrollSecret ? (
                    <button
                      type="button"
                      disabled={mfaBusy}
                      onClick={() => void startMfaEnrollment()}
                      className="inline-flex min-h-[40px] w-full items-center justify-center gap-2 rounded-lg border border-sky-200 bg-sky-50 px-4 py-2 text-xs font-semibold text-sky-900 hover:bg-sky-100 whitespace-nowrap"
                    >
                      <QrCode className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                      <span>
                        {lang === "ar"
                          ? "تفعيل المصادقة الثنائية (TOTP MFA)"
                          : "Enable TOTP MFA (Authenticator App)"}
                      </span>
                    </button>
                  ) : (
                    <form
                      onSubmit={(e) => void handleActivateMfa(e, false)}
                      className="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-3.5"
                    >
                      {mfaEnrollQrUrl && (
                        <div className="flex justify-center">
                          <img
                            src={mfaEnrollQrUrl}
                            alt="TOTP Authenticator QR"
                            className="h-36 w-36 rounded-lg border border-slate-200 bg-white p-1.5"
                          />
                        </div>
                      )}
                      <p dir="ltr" className="text-center font-mono text-[11px] text-slate-700 select-all">
                        {mfaEnrollSecret}
                      </p>
                      <div className="flex gap-2">
                        <label htmlFor="mfa-inline-code" className="sr-only">
                          {lang === "ar" ? "رمز التحقق السداسي" : "6-digit TOTP code"}
                        </label>
                        <input
                          id="mfa-inline-code"
                          type="text"
                          inputMode="numeric"
                          pattern="\d{6}"
                          maxLength={6}
                          required
                          dir="ltr"
                          value={mfaActivateCode}
                          onChange={(e) =>
                            setMfaActivateCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                          }
                          placeholder="123456"
                          className="min-h-[38px] flex-1 rounded-lg border border-slate-300 bg-white px-3 text-center font-mono text-xs tracking-[0.2em]"
                        />
                        <button
                          type="submit"
                          disabled={mfaBusy || mfaActivateCode.length !== 6}
                          className="min-h-[38px] rounded-lg bg-slate-900 px-3.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400 whitespace-nowrap"
                        >
                          {lang === "ar" ? "تأكيد" : "Verify"}
                        </button>
                      </div>
                      {mfaError && <p className="text-xs font-medium text-red-700">{mfaError}</p>}
                    </form>
                  )}
                </div>
              )}

              {/* Isolated Encrypted Backup Export */}
              <form onSubmit={handleExportBackup} className="space-y-2 border-t border-slate-100 pt-3">
                <label
                  htmlFor="backup-passphrase"
                  className="block text-xs font-semibold text-slate-700"
                >
                  {lang === "ar"
                    ? "نسخة احتياطية مشفّرة ومعزولة (PBKDF2 + AES-256-GCM)"
                    : "Isolated Encrypted Backup (Passphrase 12+ chars)"}
                </label>
                <div className="flex gap-2">
                  <input
                    id="backup-passphrase"
                    type="password"
                    dir="ltr"
                    minLength={12}
                    value={backupPassphrase}
                    onChange={(e) => setBackupPassphrase(e.target.value)}
                    placeholder={lang === "ar" ? "عبارة مرور (12 حرفاً+)" : "Passphrase (12+ chars)"}
                    className="min-h-[38px] flex-1 rounded-lg border border-slate-300 px-3 text-xs"
                  />
                  <button
                    type="submit"
                    disabled={exportingBackup || backupPassphrase.trim().length < 12}
                    className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50 whitespace-nowrap"
                  >
                    <Archive className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    <span>{lang === "ar" ? "تصدير" : "Export"}</span>
                  </button>
                </div>
              </form>

              <div className="flex flex-col gap-2.5 border-t border-slate-100 pt-3">
                <button
                  type="button"
                  onClick={() => setShowPasswordModal(true)}
                  className="inline-flex min-h-[40px] w-full items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 whitespace-nowrap"
                >
                  <KeyRound className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{lang === "ar" ? "تغيير كلمة المرور" : "Change Password"}</span>
                </button>

                <button
                  type="button"
                  disabled={revokingSessions}
                  onClick={requestRevokeAllSessions}
                  className="inline-flex min-h-[40px] w-full items-center justify-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-xs font-semibold text-red-800 hover:bg-red-100 disabled:opacity-50 whitespace-nowrap"
                >
                  <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>
                    {lang === "ar"
                      ? "إنهاء جميع الجلسات النشطة فوراً"
                      : "Revoke All Active Sessions Now"}
                  </span>
                </button>
              </div>
            </section>

            {/* Cloudflare Free Protection & Global WAF Policy */}
            {policyDraft && (
              <form
                onSubmit={handleSaveSecurityPolicy}
                className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4"
              >
                <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
                  <Globe className="h-4 w-4 text-sky-700" aria-hidden="true" />
                  <h2 className="text-base font-bold text-slate-900">
                    {lang === "ar"
                      ? "حماية Cloudflare المجانية والجدار العالمي (WAF)"
                      : "Cloudflare Free Edge & WAF Policy"}
                  </h2>
                </div>

                <div className="space-y-2.5 text-xs">
                  <label htmlFor="pol-cf-enabled" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar" ? "تفعيل حماية Cloudflare Edge WAF" : "Enable Cloudflare Edge WAF"}
                    </span>
                    <input
                      id="pol-cf-enabled"
                      type="checkbox"
                      checked={policyDraft.cloudflare_enabled}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, cloudflare_enabled: e.target.checked })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>

                  <label htmlFor="pol-cf-headers" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar"
                        ? "اعتماد ترويسات CF-Connecting-IP و CF-Ray"
                        : "Trust Verified Cloudflare Proxy Headers"}
                    </span>
                    <input
                      id="pol-cf-headers"
                      type="checkbox"
                      checked={policyDraft.trust_cf_headers}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, trust_cf_headers: e.target.checked })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>

                  <label htmlFor="pol-turnstile" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar"
                        ? "تفعيل تحقق الروبوتات المجاني (Cloudflare Turnstile)"
                        : "Require Cloudflare Turnstile Bot Check on Login"}
                    </span>
                    <input
                      id="pol-turnstile"
                      type="checkbox"
                      checked={policyDraft.turnstile_enabled}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, turnstile_enabled: e.target.checked })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>

                  <label htmlFor="pol-ip-bind" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar"
                        ? "ربط القناة المشفّرة بعنوان IP الجلسة"
                        : "Strict E2EE Channel IP Binding"}
                    </span>
                    <input
                      id="pol-ip-bind"
                      type="checkbox"
                      checked={policyDraft.strict_ip_binding}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, strict_ip_binding: e.target.checked })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>

                  <label htmlFor="pol-method-ovr" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar"
                        ? "حظر ترويسات تزوير الطلبات (X-HTTP-Method-Override)"
                        : "Block HTTP Method-Override Headers"}
                    </span>
                    <input
                      id="pol-method-ovr"
                      type="checkbox"
                      checked={policyDraft.block_method_override}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, block_method_override: e.target.checked })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>

                  <label htmlFor="pol-json-ct" className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-800">
                      {lang === "ar"
                        ? "إلزام Content-Type: application/json لطلبات التعديل"
                        : "Enforce application/json Content-Type"}
                    </span>
                    <input
                      id="pol-json-ct"
                      type="checkbox"
                      checked={policyDraft.enforce_json_content_type}
                      onChange={(e) =>
                        setPolicyDraft({
                          ...policyDraft,
                          enforce_json_content_type: e.target.checked,
                        })
                      }
                      className="h-4 w-4 accent-slate-900"
                    />
                  </label>
                </div>

                <div className="grid grid-cols-1 gap-3 border-t border-slate-100 pt-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <label htmlFor="pol-countries" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "الدول المسموحة (ISO-2)" : "Allowed Countries (ISO-2)"}
                    </label>
                    <input
                      id="pol-countries"
                      type="text"
                      dir="ltr"
                      placeholder="SA, AE, EG"
                      value={countriesInput}
                      onChange={(e) => setCountriesInput(e.target.value)}
                      className="min-h-[38px] w-full rounded-lg border border-slate-300 px-3 font-mono text-xs"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="pol-threat" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "حد حظر CF-Threat-Score" : "Max CF Threat Score (1-100)"}
                    </label>
                    <input
                      id="pol-threat"
                      type="number"
                      min={1}
                      max={100}
                      dir="ltr"
                      value={policyDraft.max_cf_threat_score}
                      onChange={(e) =>
                        setPolicyDraft({
                          ...policyDraft,
                          max_cf_threat_score: Number(e.target.value) || 35,
                        })
                      }
                      className="min-h-[38px] w-full rounded-lg border border-slate-300 px-3 font-mono text-xs"
                    />
                  </div>
                  <div className="space-y-1 sm:col-span-2">
                    <label htmlFor="pol-sitekey" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar"
                        ? "مفتاح الموقع العام لـ Cloudflare Turnstile (Site Key)"
                        : "Cloudflare Turnstile Site Key (Public)"}
                    </label>
                    <input
                      id="pol-sitekey"
                      type="text"
                      dir="ltr"
                      placeholder="0x4AAAAAAA..."
                      value={policyDraft.turnstile_site_key}
                      onChange={(e) =>
                        setPolicyDraft({ ...policyDraft, turnstile_site_key: e.target.value })
                      }
                      className="min-h-[38px] w-full rounded-lg border border-slate-300 px-3 font-mono text-xs"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={savingPolicy}
                  className="min-h-[40px] w-full rounded-xl bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
                >
                  {savingPolicy
                    ? lang === "ar"
                      ? "جارٍ الحفظ..."
                      : "Saving..."
                    : lang === "ar"
                      ? "حفظ سياسة Cloudflare والحماية"
                      : "Save Cloudflare & WAF Policy"}
                </button>
              </form>
            )}
          </div>

          {/* Right Column: Active Sessions, Real-Time Security Alerts, Audit Log */}
          <div className="space-y-6 lg:col-span-7">
            <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h2 className="text-base font-bold text-slate-900">
                  {lang === "ar" ? "الجلسات النشطة" : "Active Sessions"}
                </h2>
                <span className="font-mono text-xs text-slate-500 tabular-nums">
                  {(data?.active_sessions ?? []).length}
                </span>
              </div>
              <div className="max-h-60 overflow-y-auto divide-y divide-slate-100">
                {(data?.active_sessions ?? []).length === 0 ? (
                  <p className="py-4 text-center text-xs text-slate-500">
                    {lang === "ar" ? "لا توجد جلسات نشطة حالياً." : "No active sessions."}
                  </p>
                ) : (
                  (data?.active_sessions ?? []).map((sess) => (
                    <div key={sess.jti} className="flex items-center justify-between gap-3 py-2.5 text-xs">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-slate-900">
                          {sess.user_name}{" "}
                          <span className="font-normal text-slate-500">
                            · {sess.role} · {sess.aal.toUpperCase()}
                            {sess.is_current ? (lang === "ar" ? " · الحالية" : " · Current") : ""}
                          </span>
                        </p>
                        <p className="font-mono text-slate-500 tabular-nums" dir="ltr">
                          {sess.email} · {formatClock(sess.last_active_at)}
                        </p>
                      </div>
                      {!sess.is_current && (
                        <button
                          type="button"
                          disabled={revokingJti === sess.jti}
                          onClick={() => void handleRevokeSingleSession(sess.jti)}
                          className="rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-800 hover:bg-red-100 whitespace-nowrap shrink-0"
                        >
                          {lang === "ar" ? "إنهاء" : "Revoke"}
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </section>

            {(data?.security_alerts ?? []).length > 0 && (
              <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-3">
                <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
                  <AlertTriangle className="h-4 w-4 text-amber-700" aria-hidden="true" />
                  <h2 className="text-base font-bold text-slate-900">
                    {lang === "ar" ? "التنبيهات الأمنية الفورية" : "Security Alerts"}
                  </h2>
                </div>
                <div className="max-h-48 overflow-y-auto divide-y divide-slate-100">
                  {(data?.security_alerts ?? []).slice(0, 10).map((alert) => (
                    <div key={alert.id} className="py-2 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`font-semibold ${
                            alert.severity === "critical"
                              ? "text-red-700"
                              : alert.severity === "high"
                                ? "text-amber-700"
                                : "text-slate-700"
                          }`}
                        >
                          {alert.severity.toUpperCase()} · {alert.event}
                        </span>
                        <span className="font-mono text-slate-500 tabular-nums">
                          {formatClock(alert.created_at)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-3">
              <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
                <Clock className="h-4 w-4 text-slate-600" aria-hidden="true" />
                <h2 className="text-base font-bold text-slate-900">
                  {lang === "ar" ? "سجل التدقيق الأمني" : "Security Audit Log"}
                </h2>
              </div>
              <div className="max-h-64 overflow-y-auto divide-y divide-slate-100">
                {(data?.security_logs ?? []).slice(0, 15).map((log) => (
                  <div key={log.id} className="py-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-slate-900">{log.user_name}</span>
                      <span className="font-mono text-slate-500 tabular-nums">
                        {formatClock(log.created_at)}
                      </span>
                    </div>
                    <p className="mt-0.5 font-mono text-slate-600" dir="ltr">
                      {log.event_type} · {log.reason_code ?? "OK"}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      )}

      {/* TAB 6: Database-Backed RBAC Roles & Staff Permissions */}
      {tab === "permissions" && hasPerm("manage_permissions") && (
        <div
          role="tabpanel"
          id="hr-panel-permissions"
          aria-labelledby="hr-tab-permissions"
          className="space-y-6"
        >
          {/* Role Permission Matrix */}
          <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <UserCog className="h-4 w-4 text-slate-800" aria-hidden="true" />
                <h2 className="text-base font-bold text-slate-900">
                  {lang === "ar"
                    ? "مصفوفة صلاحيات الأدوار الإدارية (متصلة بقاعدة البيانات)"
                    : "Database-Backed Admin Role Permission Matrix"}
                </h2>
              </div>
              <span className="font-mono text-xs text-slate-500">public.rbac_roles</span>
            </div>

            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              {Object.entries(rbacRoleDrafts).map(([roleKey, roleDef]) => (
                <article
                  key={roleKey}
                  className="rounded-xl border border-slate-200 bg-slate-50/50 p-4 space-y-4"
                >
                  <div className="flex items-center justify-between gap-2 border-b border-slate-200/70 pb-2.5">
                    <div>
                      <h3 className="text-sm font-bold text-slate-900">
                        {lang === "ar" ? roleDef.label_ar : roleDef.label_en}
                      </h3>
                      <p className="font-mono text-[11px] text-slate-500" dir="ltr">
                        {roleKey}
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={savingRoleKey === roleKey}
                      onClick={() => void handleSaveRbacRole(roleKey)}
                      className="min-h-[36px] rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
                    >
                      {savingRoleKey === roleKey
                        ? lang === "ar"
                          ? "جارٍ الحفظ..."
                          : "Saving..."
                        : lang === "ar"
                          ? "حفظ الصلاحيات"
                          : "Save Role"}
                    </button>
                  </div>

                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {PERMISSION_LABELS.map((pMeta) => {
                      const checked = roleDef.permissions.includes(pMeta.key);
                      const locked = roleKey === "super_admin" && pMeta.key === "manage_permissions";
                      return (
                        <label
                          key={pMeta.key}
                          className={`flex items-center gap-2 rounded-lg border px-2.5 py-2 text-xs ${
                            checked
                              ? "border-slate-300 bg-white font-semibold text-slate-900"
                              : "border-slate-200/80 bg-slate-50 text-slate-600"
                          }`}
                        >
                          <input
                            type="checkbox"
                            disabled={locked}
                            checked={checked}
                            onChange={() => handleToggleRolePerm(roleKey, pMeta.key)}
                            className="h-4 w-4 accent-slate-900 shrink-0"
                          />
                          <span>{lang === "ar" ? pMeta.ar : pMeta.en}</span>
                        </label>
                      );
                    })}
                  </div>
                </article>
              ))}
            </div>
          </section>

          {/* Staff Access & Role Assignment */}
          <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <h2 className="text-base font-bold text-slate-900">
                {lang === "ar"
                  ? "تعيين الأدوار والصلاحيات للموظفين والمشرفين"
                  : "Staff Role Assignment (DB Synchronized)"}
              </h2>
              <span className="font-mono text-xs text-slate-500">public.user_permissions</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-start text-xs sm:text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                    <th className="py-3 pe-3 text-start">{t.hrEmployeeCol}</th>
                    <th className="py-3 px-2 text-start">{t.departmentLabel}</th>
                    <th className="py-3 px-2 text-start">
                      {lang === "ar" ? "الصلاحية الحالية" : "Current Role"}
                    </th>
                    <th className="py-3 ps-2 text-start">
                      {lang === "ar" ? "تعديل الصلاحية" : "Assign Role"}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(data?.staff_users ?? []).map((su) => (
                    <tr key={su.id} className="hover:bg-slate-50/70">
                      <td className="py-3 pe-3">
                        <div className="font-semibold text-slate-900">{su.full_name}</div>
                        <div className="font-mono text-xs text-slate-500" dir="ltr">
                          {su.email}
                        </div>
                      </td>
                      <td className="py-3 px-2 text-xs text-slate-600">{su.department ?? "—"}</td>
                      <td className="py-3 px-2 font-mono text-xs font-semibold text-slate-800" dir="ltr">
                        {su.role === "admin" ? su.admin_role_key || "super_admin" : "employee"}
                      </td>
                      <td className="py-3 ps-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <select
                            aria-label={su.full_name}
                            value={userRoleSelection[su.id] ?? "employee"}
                            onChange={(e) =>
                              setUserRoleSelection((prev) => ({
                                ...prev,
                                [su.id]: e.target.value,
                              }))
                            }
                            className="min-h-[36px] rounded-lg border border-slate-300 bg-white px-2.5 text-xs text-slate-900"
                          >
                            <option value="employee">
                              {lang === "ar" ? "موظف قياسي (Employee)" : "Standard Employee"}
                            </option>
                            {Object.entries(rbacRoleDrafts).map(([rKey, rDef]) => (
                              <option key={rKey} value={rKey}>
                                {lang === "ar" ? rDef.label_ar : rDef.label_en} ({rKey})
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            disabled={savingUserId === su.id}
                            onClick={() => requestAssignUserRbac(su)}
                            className="min-h-[36px] rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50"
                          >
                            {lang === "ar" ? "تطبيق" : "Apply"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}

      {/* TAB 7: Enterprise Setup & Deployment Catalog */}
      {tab === "catalog" && (
        <section
          role="tabpanel"
          id="hr-panel-catalog"
          aria-labelledby="hr-tab-catalog"
          className="rounded-2xl border border-slate-200 bg-white p-6 space-y-6"
        >
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div className="flex items-center gap-2.5">
              <BookOpen className="h-5 w-5 text-slate-800" aria-hidden="true" />
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  {lang === "ar"
                    ? "كتالوج التسطيب والتشغيل داخل المؤسسات — نظام ان سايت"
                    : "InSight Enterprise Installation & Deployment Catalog"}
                </h2>
                <p className="text-xs text-slate-600">
                  {lang === "ar"
                    ? "المرجع المعتمد لإدارات تقنية المعلومات وأمن المعلومات عند نشر النظام في بيئة الإنتاج."
                    : "Standard IT & InfoSec runbook for on-premise or cloud deployment."}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 print:hidden">
              <button
                type="button"
                onClick={handleDownloadCatalogMd}
                className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50"
              >
                <Download className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{lang === "ar" ? "تحميل الكتالوج (.md)" : "Download Catalog (.md)"}</span>
              </button>
              <button
                type="button"
                onClick={() => window.print()}
                className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
              >
                <Printer className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{lang === "ar" ? "طباعة الدليل" : "Print Guide"}</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <article className="rounded-xl border border-slate-200 bg-slate-50/50 p-5 space-y-2.5 text-xs leading-relaxed text-slate-700">
              <h3 className="text-sm font-bold text-slate-900">
                1. {lang === "ar" ? "البيئة والخادم وإدارة المفاتيح (KMS)" : "Runtime & KMS Secrets"}
              </h3>
              <ul className="list-disc space-y-1.5 ps-5">
                <li>Node.js v22 LTS + Reverse Proxy (Nginx/Caddy) مع HTTPS إجباري (TLS 1.2/1.3).</li>
                <li>
                  تفعيل <code className="font-mono text-slate-900" dir="ltr">STRICT_PROD_SECRETS=true</code>{" "}
                  و <code className="font-mono text-slate-900" dir="ltr">REQUIRE_ADMIN_MFA=true</code>.
                </li>
                <li>
                  تعيين <code className="font-mono text-slate-900" dir="ltr">DATA_ENCRYPTION_KEY</code>{" "}
                  (64 خانة Hex عبر KMS) وعدم حفظ الأسرار في الشيفرة المصدرية.
                </li>
              </ul>
            </article>

            <article className="rounded-xl border border-slate-200 bg-slate-50/50 p-5 space-y-2.5 text-xs leading-relaxed text-slate-700">
              <h3 className="text-sm font-bold text-slate-900">
                2. {lang === "ar" ? "بناء النظام وتشغيله كخدمة" : "Production Build & Service"}
              </h3>
              <pre
                dir="ltr"
                className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-900 p-3 font-mono text-[11px] text-slate-100"
              >
                {`npm ci && npx tsc --noEmit\nnpm run build && npm test\nNODE_ENV=production npm start`}
              </pre>
            </article>

            <article className="rounded-xl border border-slate-200 bg-slate-50/50 p-5 space-y-2.5 text-xs leading-relaxed text-slate-700">
              <h3 className="text-sm font-bold text-slate-900">
                3. {lang === "ar" ? "ربط حماية Cloudflare المجانية + Turnstile" : "Cloudflare Free WAF & Turnstile"}
              </h3>
              <ul className="list-disc space-y-1.5 ps-5">
                <li>ضبط DNS على السحابة البرتقالية (Proxied) ووضع SSL/TLS على <strong>Full (Strict)</strong>.</li>
                <li>تفعيل Bot Fight Mode و قواعد WAF لحدود الدول ودرجة التهديد.</li>
                <li>
                  تمرير ترويسات <code className="font-mono" dir="ltr">CF-Connecting-IP</code>,{" "}
                  <code className="font-mono" dir="ltr">CF-IPCountry</code>,{" "}
                  <code className="font-mono" dir="ltr">CF-Threat-Score</code>,{" "}
                  <code className="font-mono" dir="ltr">CF-Ray</code> من البروكسي ثم تفعيلها في تبويب الأمان.
                </li>
                <li>إضافة Turnstile Site Key في لوحة التحكم و <code className="font-mono" dir="ltr">TURNSTILE_SECRET_KEY</code> على الخادم.</li>
              </ul>
            </article>

            <article className="rounded-xl border border-slate-200 bg-slate-50/50 p-5 space-y-2.5 text-xs leading-relaxed text-slate-700">
              <h3 className="text-sm font-bold text-slate-900">
                4. {lang === "ar" ? "أجهزة الاستقبال المتعددة وجدول الـ QR" : "Multi-Kiosk & QR Windows"}
              </h3>
              <ul className="list-disc space-y-1.5 ps-5">
                <li>اعتماد جهاز مستقل وحساب وسر منفصل لكل بوابة استقبال أو فرع.</li>
                <li>تحديد أوقات الإخفاء وعودة الظهور للـ QR من تبويب (الفروع والدوام).</li>
                <li>تشغيل الشاشات في وضع Kiosk الدائم عبر متصفح مقفل وبسياسة أمان مقيدة.</li>
                <li>تطبيق الترحيلات من 0001 إلى 0007 لربط جداول <code className="font-mono" dir="ltr">rbac_roles</code> و <code className="font-mono" dir="ltr">user_permissions</code> بقاعدة البيانات.</li>
              </ul>
            </article>
          </div>
        </section>
      )}

      {/* Add Employee Modal */}
      {showAddModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
          onClick={() => !creatingEmployee && setShowAddModal(false)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-emp-modal-title"
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-6 space-y-5 max-h-[92vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h2 id="add-emp-modal-title" className="text-lg font-bold text-slate-900">
                {t.hrAddEmployee}
              </h2>
              <button
                type="button"
                aria-label={t.hrCancelAction}
                onClick={() => setShowAddModal(false)}
                className="rounded-lg p-1 text-slate-500 hover:bg-slate-100"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleCreateEmployee} className="space-y-5">
              {/* Group 1: Identity & Department */}
              <fieldset className="space-y-3">
                <legend className="text-xs font-bold text-slate-500">
                  {lang === "ar" ? "البيانات الوظيفية" : "Employee Profile"}
                </legend>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1 sm:col-span-2">
                    <label htmlFor="new-emp-name" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "الاسم الكامل" : "Full Name"}
                    </label>
                    <input
                      id="new-emp-name"
                      required
                      value={newEmpForm.full_name}
                      onChange={(e) => setNewEmpForm({ ...newEmpForm, full_name: e.target.value })}
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="new-emp-num" className="block text-xs font-semibold text-slate-700">
                      {t.employeeNumberLabel}
                    </label>
                    <input
                      id="new-emp-num"
                      required
                      dir="ltr"
                      placeholder="EMP-1006"
                      value={newEmpForm.employee_number}
                      onChange={(e) =>
                        setNewEmpForm({ ...newEmpForm, employee_number: e.target.value })
                      }
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="new-emp-dept" className="block text-xs font-semibold text-slate-700">
                      {t.departmentLabel}
                    </label>
                    <input
                      id="new-emp-dept"
                      value={newEmpForm.department}
                      onChange={(e) => setNewEmpForm({ ...newEmpForm, department: e.target.value })}
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                    />
                  </div>
                  <div className="space-y-1 sm:col-span-2">
                    <label htmlFor="new-emp-title" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "المسمى الوظيفي" : "Job Title"}
                    </label>
                    <input
                      id="new-emp-title"
                      value={newEmpForm.job_title}
                      onChange={(e) => setNewEmpForm({ ...newEmpForm, job_title: e.target.value })}
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                    />
                  </div>
                </div>
              </fieldset>

              {/* Group 2: Credentials & Shift */}
              <fieldset className="space-y-3 border-t border-slate-100 pt-4">
                <legend className="text-xs font-bold text-slate-500">
                  {lang === "ar" ? "بيانات الدخول والوردية" : "Credentials & Shift"}
                </legend>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <label htmlFor="new-emp-email" className="block text-xs font-semibold text-slate-700">
                      {t.emailLabel}
                    </label>
                    <input
                      id="new-emp-email"
                      type="email"
                      required
                      dir="ltr"
                      value={newEmpForm.email}
                      onChange={(e) => setNewEmpForm({ ...newEmpForm, email: e.target.value })}
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="new-emp-pass" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar"
                        ? `${t.passwordLabel} (8 أحرف+ حروف وأرقام)`
                        : `${t.passwordLabel} (8+ chars, letters & numbers)`}
                    </label>
                    <div className="relative">
                      <input
                        id="new-emp-pass"
                        type={showNewEmpPassword ? "text" : "password"}
                        required
                        minLength={8}
                        dir="ltr"
                        value={newEmpForm.password}
                        onChange={(e) => setNewEmpForm({ ...newEmpForm, password: e.target.value })}
                        className="min-h-[42px] w-full rounded-lg border border-slate-300 ps-3 pe-10 text-sm"
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewEmpPassword((v) => !v)}
                        aria-label={showNewEmpPassword ? t.hidePasswordLabel : t.showPasswordLabel}
                        className="absolute inset-y-0 end-0 flex w-10 items-center justify-center text-slate-500 hover:text-slate-800"
                      >
                        {showNewEmpPassword ? (
                          <EyeOff className="h-4 w-4" aria-hidden="true" />
                        ) : (
                          <Eye className="h-4 w-4" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="new-emp-start" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "بداية الوردية" : "Shift Start"}
                    </label>
                    <input
                      id="new-emp-start"
                      type="time"
                      dir="ltr"
                      value={newEmpForm.shift_start}
                      onChange={(e) =>
                        setNewEmpForm({ ...newEmpForm, shift_start: e.target.value })
                      }
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-xs"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="new-emp-end" className="block text-xs font-semibold text-slate-700">
                      {lang === "ar" ? "نهاية الوردية" : "Shift End"}
                    </label>
                    <input
                      id="new-emp-end"
                      type="time"
                      dir="ltr"
                      value={newEmpForm.shift_end}
                      onChange={(e) =>
                        setNewEmpForm({ ...newEmpForm, shift_end: e.target.value })
                      }
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-xs"
                    />
                  </div>
                </div>
              </fieldset>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="min-h-[42px] rounded-lg border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700"
                >
                  {t.hrCancelAction}
                </button>
                <button
                  type="submit"
                  disabled={creatingEmployee}
                  className="min-h-[42px] rounded-lg bg-slate-900 px-5 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
                >
                  {lang === "ar" ? "حفظ الموظف" : "Create Employee"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Kiosk Modal */}
      {showAddKioskModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
          onClick={() => !creatingKiosk && setShowAddKioskModal(false)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-kiosk-modal-title"
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-6 space-y-5 max-h-[92vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h2 id="add-kiosk-modal-title" className="text-lg font-bold text-slate-900">
                {t.hrAddKioskBtn}
              </h2>
              <button
                type="button"
                aria-label={t.hrCancelAction}
                onClick={() => setShowAddKioskModal(false)}
                className="rounded-lg p-1 text-slate-500 hover:bg-slate-100"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleCreateKiosk} className="space-y-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <label htmlFor="new-kiosk-name" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "اسم الجهاز / البوابة" : "Device Name"}
                  </label>
                  <input
                    id="new-kiosk-name"
                    required
                    value={newKioskForm.device_name}
                    onChange={(e) =>
                      setNewKioskForm({ ...newKioskForm, device_name: e.target.value })
                    }
                    placeholder={lang === "ar" ? "استقبال البوابة الشرقية" : "East Lobby Kiosk"}
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="new-kiosk-branch" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "الفرع" : "Branch Name"}
                  </label>
                  <input
                    id="new-kiosk-branch"
                    required
                    value={newKioskForm.branch_name}
                    onChange={(e) =>
                      setNewKioskForm({ ...newKioskForm, branch_name: e.target.value })
                    }
                    placeholder={settingsDraft?.branch_name ?? "الفرع الرئيسي"}
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                  />
                </div>
                <div className="space-y-1 sm:col-span-2">
                  <label htmlFor="new-kiosk-email" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "البريد الإلكتروني الخاص بالشاشة" : "Kiosk Account Email"}
                  </label>
                  <input
                    id="new-kiosk-email"
                    type="email"
                    dir="ltr"
                    required
                    value={newKioskForm.email}
                    onChange={(e) => setNewKioskForm({ ...newKioskForm, email: e.target.value })}
                    placeholder="kiosk-east@company.com"
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="new-kiosk-pass" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "كلمة المرور (8 أحرف+)" : "Password (8+ chars)"}
                  </label>
                  <div className="relative">
                    <input
                      id="new-kiosk-pass"
                      type={showNewKioskPass ? "text" : "password"}
                      dir="ltr"
                      minLength={8}
                      required
                      value={newKioskForm.password}
                      onChange={(e) =>
                        setNewKioskForm({ ...newKioskForm, password: e.target.value })
                      }
                      className="min-h-[42px] w-full rounded-lg border border-slate-300 ps-3 pe-10 text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewKioskPass((v) => !v)}
                      aria-label={showNewKioskPass ? t.hidePasswordLabel : t.showPasswordLabel}
                      className="absolute inset-y-0 end-0 flex w-10 items-center justify-center text-slate-500 hover:text-slate-800"
                    >
                      {showNewKioskPass ? (
                        <EyeOff className="h-4 w-4" aria-hidden="true" />
                      ) : (
                        <Eye className="h-4 w-4" aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </div>
                <div className="space-y-1">
                  <label htmlFor="new-kiosk-sec" className="block text-xs font-semibold text-slate-700">
                    {lang === "ar" ? "سر اعتماد الجهاز (8 أحرف+)" : "Device Secret (8+ chars)"}
                  </label>
                  <input
                    id="new-kiosk-sec"
                    type="password"
                    dir="ltr"
                    minLength={8}
                    required
                    value={newKioskForm.device_secret}
                    onChange={(e) =>
                      setNewKioskForm({ ...newKioskForm, device_secret: e.target.value })
                    }
                    className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddKioskModal(false)}
                  className="min-h-[42px] rounded-lg border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700"
                >
                  {t.hrCancelAction}
                </button>
                <button
                  type="submit"
                  disabled={creatingKiosk}
                  className="min-h-[42px] rounded-lg bg-slate-900 px-5 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
                >
                  {creatingKiosk
                    ? lang === "ar"
                      ? "جارٍ الاعتماد..."
                      : "Authorizing..."
                    : lang === "ar"
                      ? "اعتماد الشاشة"
                      : "Authorize Kiosk"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Excuse Modal */}
      {excuseTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
          onClick={() => !savingExcuse && setExcuseTarget(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="excuse-modal-title"
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h2 id="excuse-modal-title" className="text-lg font-bold text-slate-900">
                {t.hrMarkExcuse}
              </h2>
              <button
                type="button"
                aria-label={t.hrCancelAction}
                onClick={() => setExcuseTarget(null)}
                className="rounded-lg p-1 text-slate-500 hover:bg-slate-100"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleSaveExcuse} className="space-y-4">
              <div className="space-y-1">
                <label htmlFor="excuse-employee" className="block text-xs font-semibold text-slate-700">
                  {t.hrEmployeeCol}
                </label>
                <select
                  id="excuse-employee"
                  value={excuseTarget.employee_id}
                  onChange={(e) =>
                    setExcuseTarget({ ...excuseTarget, employee_id: e.target.value })
                  }
                  className="min-h-[42px] w-full rounded-lg border border-slate-300 bg-white px-3 text-sm"
                >
                  {(data?.employees ?? []).map((emp) => (
                    <option key={emp.id} value={emp.id}>
                      {emp.full_name} ({emp.employee_number})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label htmlFor="excuse-date" className="block text-xs font-semibold text-slate-700">
                  {t.dateCol}
                </label>
                <input
                  id="excuse-date"
                  type="date"
                  required
                  value={excuseTarget.attendance_date}
                  onChange={(e) =>
                    setExcuseTarget({ ...excuseTarget, attendance_date: e.target.value })
                  }
                  className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 font-mono text-sm"
                />
              </div>

              <div className="space-y-1">
                <label htmlFor="excuse-notes" className="block text-xs font-semibold text-slate-700">
                  {lang === "ar" ? "سبب العذر / الإجازة" : "Excuse Note"}
                </label>
                <input
                  id="excuse-notes"
                  type="text"
                  required
                  value={excuseTarget.notes}
                  onChange={(e) => setExcuseTarget({ ...excuseTarget, notes: e.target.value })}
                  className="min-h-[42px] w-full rounded-lg border border-slate-300 px-3 text-sm"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setExcuseTarget(null)}
                  className="min-h-[42px] rounded-lg border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700"
                >
                  {t.hrCancelAction}
                </button>
                <button
                  type="submit"
                  disabled={savingExcuse}
                  className="min-h-[42px] rounded-lg bg-slate-900 px-5 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-400"
                >
                  {lang === "ar" ? "اعتماد العذر" : "Save Excuse"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Dialog for High-Impact Actions */}
      {confirmState && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
          onClick={() => !confirmBusy && setConfirmState(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-modal-title"
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 space-y-4"
          >
            <div className="flex items-start gap-3">
              <div
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${
                  confirmState.danger ? "bg-red-50 text-red-700" : "bg-slate-100 text-slate-800"
                }`}
              >
                <AlertTriangle className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="space-y-1">
                <h2 id="confirm-modal-title" className="text-base font-bold text-slate-900">
                  {confirmState.title}
                </h2>
                <p className="text-xs leading-relaxed text-slate-600">{confirmState.description}</p>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                disabled={confirmBusy}
                onClick={() => setConfirmState(null)}
                className="min-h-[40px] rounded-lg border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              >
                {t.hrCancelAction}
              </button>
              <button
                type="button"
                disabled={confirmBusy}
                onClick={() => void executeConfirm()}
                className={`min-h-[40px] rounded-lg px-4 py-2 text-xs font-semibold text-white disabled:opacity-50 ${
                  confirmState.danger
                    ? "bg-red-700 hover:bg-red-800"
                    : "bg-slate-900 hover:bg-slate-800"
                }`}
              >
                {confirmState.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}

      <ChangePasswordModal
        open={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
        onSuccess={() =>
          setFeedback({
            type: "ok",
            text:
              lang === "ar"
                ? "تم تحديث كلمة المرور وإنهاء جميع الجلسات السابقة."
                : "Password updated and all previous sessions revoked.",
          })
        }
      />
    </main>
  );
}
