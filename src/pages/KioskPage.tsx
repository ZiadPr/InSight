import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import {
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Lock,
  Maximize2,
  Minimize2,
  RefreshCw,
  Wifi,
  WifiOff,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";
import { isValidEmail } from "../lib/validation";
import { getKioskTokenStatus, issueKioskToken } from "../services/kioskService";

type KioskPhase = "loading" | "active" | "consumed_cooldown" | "scheduled_hidden" | "offline";

const KIOSK_REVOKED_ERRORS = new Set([
  "KIOSK_SESSION_REVOKED",
  "DEVICE_SECRET_INVALID",
  "DEVICE_SECRET_REQUIRED",
  "DEVICE_SECRET_NOT_CONFIGURED",
  "KIOSK_NOT_AUTHORIZED",
  "UNAUTHORIZED",
  "FORBIDDEN",
]);

export function KioskPage() {
  const { user, profile, loading, signIn, signOut } = useAuth();
  const { lang, t } = useI18n();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [deviceSecret, setDeviceSecret] = useState("");
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [authErr, setAuthErr] = useState<string | null>(null);
  const [offlineErrorCode, setOfflineErrorCode] = useState<string | null>(null);

  const [phase, setPhase] = useState<KioskPhase>("loading");
  const [isRotating, setIsRotating] = useState<boolean>(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [liveRawToken, setLiveRawToken] = useState<string | null>(null);
  const [manualCode, setManualCode] = useState<string | null>(null);
  const [isLocalDemo, setIsLocalDemo] = useState<boolean>(false);
  const [copiedToken, setCopiedToken] = useState<boolean>(false);
  const [copiedManualCode, setCopiedManualCode] = useState<boolean>(false);
  const [consumedAction, setConsumedAction] = useState<"check_in" | "check_out" | null>(null);

  const [companyName, setCompanyName] = useState<string>("ان سايت");
  const [branchName, setBranchName] = useState<string>("المقر الرئيسي — الرياض");
  const [ttlSeconds, setTtlSeconds] = useState<number>(20);
  const [remainingSeconds, setRemainingSeconds] = useState<number>(20);
  const [progressPct, setProgressPct] = useState<number>(100);
  const [cooldownSeconds, setCooldownSeconds] = useState<number>(3);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string | null>(null);
  const [scheduledNextTime, setScheduledNextTime] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const [liveClock, setLiveClock] = useState<string>("");

  const phaseRef = useRef<KioskPhase>("loading");
  const tokenIdRef = useRef<string | null>(null);
  const issuedAtMsRef = useRef<number>(0);
  const expiresAtMsRef = useRef<number>(0);
  const cooldownEndsAtMsRef = useRef<number>(0);
  const lastSchedulePollRef = useRef<number>(0);
  const issuingRef = useRef<boolean>(false);
  const mountedRef = useRef<boolean>(true);
  const deviceSecretRef = useRef<string>("");
  const signingOutRef = useRef<boolean>(false);

  deviceSecretRef.current = deviceSecret;
  phaseRef.current = phase;

  const hasSecretInMemory = deviceSecret.trim().length > 0;
  const isKioskAuthorized = Boolean(
    user && profile?.role === "kiosk" && profile.is_active && hasSecretInMemory,
  );

  useEffect(() => {
    const updateClock = () => {
      setLiveClock(
        new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }).format(new Date()),
      );
    };
    updateClock();
    const id = window.setInterval(updateClock, 1000);
    return () => window.clearInterval(id);
  }, [lang]);

  const formatKioskError = useCallback(
    (code?: string): string => {
      switch (code) {
        case "DEVICE_SECRET_INVALID":
          return lang === "ar"
            ? "رمز اعتماد الجهاز غير مطابق."
            : "Device secret does not match.";
        case "DEVICE_SECRET_REQUIRED":
          return t.kioskSecretRequiredError;
        case "KIOSK_NOT_AUTHORIZED":
        case "KIOSK_INACTIVE":
          return lang === "ar"
            ? "هذا الحساب غير مرتبط بجهاز استقبال فعّال."
            : "No active kiosk device linked to this account.";
        case "KIOSK_SESSION_REVOKED":
          return t.kioskSessionRevokedError;
        case "SERVICE_DISABLED":
        case "CAMPUS_DISABLED":
          return lang === "ar"
            ? "تسجيل الحضور معطّل حالياً من إعدادات الموارد البشرية."
            : "Attendance service is currently disabled.";
        default:
          return code ? `${t.kioskSessionRevokedError} (${code})` : t.kioskSessionRevokedError;
      }
    },
    [lang, t.kioskSecretRequiredError, t.kioskSessionRevokedError],
  );

  useEffect(() => {
    if (
      !loading &&
      !authSubmitting &&
      !signingOutRef.current &&
      user &&
      profile?.role === "kiosk" &&
      !hasSecretInMemory
    ) {
      signingOutRef.current = true;
      setAuthErr(
        (prev) =>
          prev ??
          (lang === "ar"
            ? "لتشغيل شاشة الاستقبال يجب إدخال بيانات الحساب وسر الجهاز في هذه الصفحة."
            : "Enter Kiosk credentials and device secret on this page."),
      );
      void signOut().finally(() => {
        signingOutRef.current = false;
      });
    }
  }, [authSubmitting, hasSecretInMemory, lang, loading, profile?.role, signOut, user]);

  useEffect(() => {
    if (!isKioskAuthorized) return;
    const handleUnload = () => {
      setDeviceSecret("");
      tokenIdRef.current = null;
      setQrDataUrl(null);
      setLiveRawToken(null);
      setManualCode(null);
    };
    window.addEventListener("pagehide", handleUnload);
    return () => window.removeEventListener("pagehide", handleUnload);
  }, [isKioskAuthorized]);

  const handleRevokedOrInvalidAuth = useCallback(
    async (errorCode?: string) => {
      if (signingOutRef.current) return;
      signingOutRef.current = true;
      tokenIdRef.current = null;
      setQrDataUrl(null);
      setLiveRawToken(null);
      setManualCode(null);
      setDeviceSecret("");
      setAuthErr(formatKioskError(errorCode));
      try {
        await signOut();
      } finally {
        signingOutRef.current = false;
      }
    },
    [formatKioskError, signOut],
  );

  const requestNewToken = useCallback(async () => {
    if (!mountedRef.current || issuingRef.current || !isKioskAuthorized) return;
    issuingRef.current = true;
    setIsRotating(true);

    try {
      const res = await issueKioskToken(deviceSecretRef.current);
      if (!mountedRef.current) return;

      if (!res.ok || !res.token || !res.token_id || !res.expires_at) {
        if (res.error === "QR_WINDOW_CLOSED" || res.schedule_status === "closed") {
          tokenIdRef.current = null;
          setQrDataUrl(null);
          setLiveRawToken(null);
          setManualCode(null);
          setOfflineErrorCode(null);
          if (res.company_name) setCompanyName(res.company_name);
          if (res.branch_name) setBranchName(res.branch_name);
          setScheduledNextTime(res.next_reappear_time ?? null);
          setLastUpdatedAt(new Date().toISOString());
          lastSchedulePollRef.current = Date.now();
          phaseRef.current = "scheduled_hidden";
          setPhase("scheduled_hidden");
          return;
        }
        if (res.error && KIOSK_REVOKED_ERRORS.has(res.error)) {
          await handleRevokedOrInvalidAuth(res.error);
          return;
        }
        tokenIdRef.current = null;
        setQrDataUrl(null);
        setLiveRawToken(null);
        setManualCode(null);
        setOfflineErrorCode(res.error ?? "NETWORK_ERROR");
        phaseRef.current = "offline";
        setPhase("offline");
        return;
      }

      setOfflineErrorCode(null);
      setScheduledNextTime(null);

      const dataUrl = await QRCode.toDataURL(res.token, {
        width: 380,
        margin: 2,
        errorCorrectionLevel: "M",
        color: {
          dark: "#0F172A",
          light: "#FFFFFF",
        },
      });

      if (!mountedRef.current) return;

      const nowMs = Date.now();
      const serverExpMs = new Date(res.expires_at).getTime();
      const serverIssuedMs = res.issued_at ? new Date(res.issued_at).getTime() : nowMs;
      const effectiveTtl =
        res.ttl_seconds && res.ttl_seconds > 0
          ? res.ttl_seconds
          : Math.max(5, Math.round((serverExpMs - serverIssuedMs) / 1000));

      // Anchor countdown using local clock + exact TTL to prevent client/server clock skew freezes
      issuedAtMsRef.current = nowMs;
      expiresAtMsRef.current = nowMs + effectiveTtl * 1000;
      tokenIdRef.current = res.token_id;

      if (res.company_name) setCompanyName(res.company_name);
      if (res.branch_name) setBranchName(res.branch_name);
      setIsLocalDemo(Boolean(res.is_local_demo));
      setTtlSeconds(effectiveTtl);
      setRemainingSeconds(effectiveTtl);
      setProgressPct(100);
      setLiveRawToken(res.token);
      setManualCode(res.manual_code ?? null);
      setCopiedToken(false);
      setCopiedManualCode(false);
      setQrDataUrl(dataUrl);
      setLastUpdatedAt(new Date().toISOString());
      phaseRef.current = "active";
      setPhase("active");
    } catch {
      if (!mountedRef.current) return;
      tokenIdRef.current = null;
      setQrDataUrl(null);
      setLiveRawToken(null);
      setManualCode(null);
      phaseRef.current = "offline";
      setPhase("offline");
    } finally {
      issuingRef.current = false;
      if (mountedRef.current) {
        setIsRotating(false);
      }
    }
  }, [handleRevokedOrInvalidAuth, isKioskAuthorized]);

  useEffect(() => {
    mountedRef.current = true;
    if (isKioskAuthorized) {
      phaseRef.current = "loading";
      setPhase("loading");
      void requestNewToken();
    } else {
      tokenIdRef.current = null;
      setQrDataUrl(null);
      setLiveRawToken(null);
      setManualCode(null);
    }
    return () => {
      mountedRef.current = false;
    };
  }, [isKioskAuthorized, requestNewToken]);

  // Smooth 250ms UI ticker: never clears QR to null on expiry, never restarts on phase flip
  useEffect(() => {
    if (!isKioskAuthorized) return;

    const timer = window.setInterval(() => {
      const currentPhase = phaseRef.current;
      const now = Date.now();

      if (currentPhase === "active") {
        const totalMs = Math.max(1000, expiresAtMsRef.current - issuedAtMsRef.current);
        const remMs = Math.max(0, expiresAtMsRef.current - now);
        const secs = Math.ceil(remMs / 1000);
        const pct = Math.max(0, Math.min(100, (remMs / totalMs) * 100));

        setRemainingSeconds(secs);
        setProgressPct(pct);

        if (remMs === 0 && !issuingRef.current) {
          void requestNewToken();
        }
      } else if (currentPhase === "consumed_cooldown") {
        const remMs = Math.max(0, cooldownEndsAtMsRef.current - now);
        const secs = Math.ceil(remMs / 1000);
        setCooldownSeconds(secs);

        if (remMs === 0 && !issuingRef.current) {
          void requestNewToken();
        }
      }
    }, 250);

    return () => window.clearInterval(timer);
  }, [isKioskAuthorized, requestNewToken]);

  // Background status poller: checks whether QR was scanned or kiosk revoked
  useEffect(() => {
    if (!isKioskAuthorized) return;

    const pollInterval = window.setInterval(async () => {
      const currentPhase = phaseRef.current;

      if (currentPhase === "active" && tokenIdRef.current && !issuingRef.current) {
        // Let the local expiry ticker perform smooth rotation near t=0 without racing
        if (Date.now() >= expiresAtMsRef.current - 400) return;

        const res = await getKioskTokenStatus(tokenIdRef.current, deviceSecretRef.current);
        if (!mountedRef.current) return;

        if (!res.ok) {
          if (res.error && KIOSK_REVOKED_ERRORS.has(res.error)) {
            await handleRevokedOrInvalidAuth(res.error);
            return;
          }
          tokenIdRef.current = null;
          setQrDataUrl(null);
          setLiveRawToken(null);
          setManualCode(null);
          setOfflineErrorCode(res.error ?? "NETWORK_ERROR");
          phaseRef.current = "offline";
          setPhase("offline");
          return;
        }

        if (res.schedule_status === "closed") {
          tokenIdRef.current = null;
          setQrDataUrl(null);
          setLiveRawToken(null);
          setManualCode(null);
          setScheduledNextTime(res.next_reappear_time ?? null);
          setLastUpdatedAt(new Date().toISOString());
          lastSchedulePollRef.current = Date.now();
          phaseRef.current = "scheduled_hidden";
          setPhase("scheduled_hidden");
          return;
        }

        if (res.status === "consumed") {
          tokenIdRef.current = null;
          setQrDataUrl(null);
          setLiveRawToken(null);
          setManualCode(null);
          setConsumedAction(res.consumed_action ?? "check_in");
          cooldownEndsAtMsRef.current = Date.now() + 3000;
          setCooldownSeconds(3);
          setLastUpdatedAt(new Date().toISOString());
          phaseRef.current = "consumed_cooldown";
          setPhase("consumed_cooldown");
          return;
        }

        if ((res.status === "expired" || res.status === "revoked") && !issuingRef.current) {
          void requestNewToken();
        }
      } else if (currentPhase === "scheduled_hidden" && !issuingRef.current) {
        const nowMs = Date.now();
        if (nowMs - lastSchedulePollRef.current >= 10_000) {
          lastSchedulePollRef.current = nowMs;
          void requestNewToken();
        }
      } else if (currentPhase === "offline" && !issuingRef.current) {
        void requestNewToken();
      }
    }, 1200);

    return () => window.clearInterval(pollInterval);
  }, [handleRevokedOrInvalidAuth, isKioskAuthorized, requestNewToken]);

  useEffect(() => {
    const onFsChange = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  const toggleFullscreen = async () => {
    try {
      if (!document.fullscreenElement) {
        await document.documentElement.requestFullscreen();
      } else {
        await document.exitFullscreen();
      }
    } catch {
      // Ignore fullscreen denial
    }
  };

  async function handleKioskLogin(e: FormEvent) {
    e.preventDefault();
    setAuthErr(null);

    if (!isValidEmail(email)) {
      setAuthErr(t.invalidEmailFormat);
      return;
    }
    if (password.length === 0) {
      setAuthErr(t.emptyPasswordError);
      return;
    }
    if (deviceSecret.trim().length === 0) {
      setAuthErr(t.kioskSecretRequiredError);
      return;
    }

    setAuthSubmitting(true);
    const res = await signIn(email, password);
    setAuthSubmitting(false);

    if (!res.ok) {
      setAuthErr(t.invalidCredentials);
    }
  }

  const fillDemoKiosk = () => {
    if (!import.meta.env.DEV) return;
    setEmail("kiosk@company.com");
    setPassword("Kiosk@2026");
    setDeviceSecret("KIOSK-HQ-2026");
    setAuthErr(null);
  };

  const handleCopyToken = async () => {
    if (!liveRawToken) return;
    try {
      await navigator.clipboard.writeText(liveRawToken);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } catch {
      // Ignore clipboard failure
    }
  };

  const handleCopyManualCode = async () => {
    if (!manualCode) return;
    try {
      await navigator.clipboard.writeText(manualCode);
      setCopiedManualCode(true);
      setTimeout(() => setCopiedManualCode(false), 2000);
    } catch {
      // Ignore clipboard failure
    }
  };

  if (loading) {
    return (
      <main className="mx-auto max-w-3xl px-4 py-16 text-center text-sm text-slate-600">
        {t.loadingText}
      </main>
    );
  }

  if (user && profile && profile.role !== "kiosk") {
    return (
      <main className="mx-auto max-w-xl px-4 py-12 sm:px-6">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
          <h1 className="text-lg font-bold text-slate-900">{t.roleMismatchTitle}</h1>
          <p className="text-sm text-slate-600">{t.roleMismatchDesc}</p>
          <button
            type="button"
            onClick={() => void signOut()}
            className="min-h-[44px] rounded-lg bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800"
          >
            {t.signOut}
          </button>
        </div>
      </main>
    );
  }

  if (!isKioskAuthorized) {
    return (
      <main className="mx-auto max-w-lg px-4 py-6 sm:px-6 sm:py-10">
        <section className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8">
          <h1 className="text-xl font-bold text-slate-900">{t.kioskAuthTitle}</h1>
          <p className="mt-1.5 text-sm text-slate-600">{t.kioskAuthSubtitle}</p>

          <form onSubmit={handleKioskLogin} className="mt-6 space-y-4" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="kiosk-email" className="block text-sm font-semibold text-slate-800">
                {t.emailLabel}
              </label>
              <input
                id="kiosk-email"
                type="email"
                dir="ltr"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="terminal@company.com"
                className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="kiosk-password"
                className="block text-sm font-semibold text-slate-800"
              >
                {t.passwordLabel}
              </label>
              <input
                id="kiosk-password"
                type="password"
                dir="ltr"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="kiosk-secret" className="block text-sm font-semibold text-slate-800">
                {t.kioskSecretLabel}
              </label>
              <input
                id="kiosk-secret"
                type="password"
                dir="ltr"
                required
                value={deviceSecret}
                onChange={(e) => setDeviceSecret(e.target.value)}
                placeholder={t.kioskSecretPlaceholder}
                className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
              />
            </div>

            {authErr && (
              <div
                role="alert"
                className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-800"
              >
                {authErr}
              </div>
            )}

            <button
              type="submit"
              disabled={authSubmitting}
              className="inline-flex min-h-[48px] w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-300"
            >
              <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{authSubmitting ? t.signingIn : t.signInBtn}</span>
            </button>
          </form>

          {import.meta.env.DEV && (
            <div className="mt-5 border-t border-slate-100 pt-4">
              <button
                type="button"
                onClick={fillDemoKiosk}
                className="min-h-[40px] w-full rounded-lg border border-slate-200 bg-slate-50 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100"
              >
                {t.kioskFillDemoBtn}
              </button>
            </div>
          )}
        </section>
      </main>
    );
  }

  const formattedLastUpdate = lastUpdatedAt
    ? new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }).format(new Date(lastUpdatedAt))
    : "—";

  const isConnected = phase !== "offline";

  return (
    <main className="mx-auto flex min-h-[calc(100dvh-4rem)] max-w-5xl flex-col justify-between px-4 py-6 sm:px-6 sm:py-8">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <p className="text-xs font-semibold text-slate-500">
            {companyName} · {branchName}
          </p>
          <h1 className="text-lg font-bold text-slate-900 sm:text-2xl">{t.kioskTitle}</h1>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-lg font-bold text-slate-900 tabular-nums">{liveClock}</span>

          <div
            className={`inline-flex items-center gap-1.5 text-sm font-semibold ${
              isConnected ? "text-emerald-700" : "text-red-700"
            }`}
          >
            {isConnected ? (
              <Wifi className="h-4 w-4 shrink-0" aria-hidden="true" />
            ) : (
              <WifiOff className="h-4 w-4 shrink-0" aria-hidden="true" />
            )}
            <span>{isConnected ? t.kioskConnected : t.kioskDisconnected}</span>
          </div>

          <button
            type="button"
            disabled={isRotating}
            onClick={() => void requestNewToken()}
            aria-label={t.kioskRefreshBtn}
            className="inline-flex min-h-[40px] items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-60 whitespace-nowrap shrink-0"
          >
            <RefreshCw
              className={`h-4 w-4 shrink-0 ${isRotating ? "animate-spin text-sky-700" : ""}`}
              aria-hidden="true"
            />
            <span>{t.kioskRefreshBtn}</span>
          </button>

          <button
            type="button"
            onClick={() => void toggleFullscreen()}
            className="inline-flex min-h-[40px] items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 whitespace-nowrap shrink-0"
          >
            {isFullscreen ? (
              <Minimize2 className="h-4 w-4 shrink-0" aria-hidden="true" />
            ) : (
              <Maximize2 className="h-4 w-4 shrink-0" aria-hidden="true" />
            )}
            <span>{isFullscreen ? t.kioskExitFullscreen : t.kioskFullscreen}</span>
          </button>
        </div>
      </div>

      <section className="my-6 flex flex-1 flex-col items-center justify-center">
        <div className="w-full max-w-xl rounded-3xl border border-slate-200 bg-white p-6 text-center sm:p-10">
          {phase === "loading" && (
            <div className="flex min-h-[420px] flex-col items-center justify-center space-y-4">
              <RefreshCw className="h-10 w-10 animate-spin text-sky-800" aria-hidden="true" />
              <p className="text-base font-semibold text-slate-700">{t.loadingText}</p>
            </div>
          )}

          {phase === "active" && qrDataUrl && (
            <div className="flex flex-col items-center space-y-5">
              <p className="text-base font-bold text-slate-900 sm:text-lg">
                {t.kioskScanInstruction}
              </p>

              <div className="relative rounded-2xl border-2 border-slate-200 bg-white p-4 sm:p-5">
                <img
                  src={qrDataUrl}
                  alt={t.kioskTitle}
                  className={`h-64 w-64 select-none transition-opacity duration-150 sm:h-80 sm:w-80 ${
                    isRotating ? "opacity-75" : "opacity-100"
                  }`}
                  draggable={false}
                />
              </div>

              {manualCode && (
                <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-slate-50 px-4 py-3.5 space-y-2">
                  <p className="text-xs font-semibold text-slate-600">{t.kioskManualCodeLabel}</p>
                  <div className="flex flex-wrap items-center justify-center gap-3">
                    <p
                      dir="ltr"
                      className="font-mono text-2xl font-bold tracking-[0.22em] text-slate-950 tabular-nums select-all sm:text-3xl"
                    >
                      {manualCode}
                    </p>
                    {import.meta.env.DEV && (
                      <button
                        type="button"
                        onClick={() => void handleCopyManualCode()}
                        aria-label={t.kioskCopyManualCodeBtn}
                        className="inline-flex min-h-[34px] items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-100 whitespace-nowrap"
                      >
                        {copiedManualCode ? (
                          <Check className="h-3.5 w-3.5 text-emerald-700" aria-hidden="true" />
                        ) : (
                          <Copy className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
                        )}
                        <span>{copiedManualCode ? t.kioskCopiedToken : t.kioskCopyManualCodeBtn}</span>
                      </button>
                    )}
                  </div>
                </div>
              )}

              <div className="w-full max-w-sm space-y-2">
                <div className="flex items-center justify-between text-xs font-medium text-slate-600">
                  <span>{isRotating ? t.kioskRefreshingLabel : t.kioskRemaining}</span>
                  <span className="font-mono font-bold text-slate-950 tabular-nums">
                    {remainingSeconds} / {ttlSeconds} {t.secondsUnit}
                  </span>
                </div>
                <div
                  className="h-2 w-full overflow-hidden rounded-full bg-slate-100"
                  role="progressbar"
                  aria-valuenow={remainingSeconds}
                  aria-valuemin={0}
                  aria-valuemax={ttlSeconds}
                >
                  <div
                    className={`h-full transition-[width] duration-200 ease-linear ${
                      remainingSeconds <= 5 ? "bg-amber-600" : "bg-slate-900"
                    }`}
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
              </div>

              <p className="text-xs text-slate-500">{t.kioskSingleUseNote}</p>

              {import.meta.env.DEV && isLocalDemo && liveRawToken && (
                <button
                  type="button"
                  onClick={() => void handleCopyToken()}
                  className="inline-flex min-h-[38px] items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                >
                  {copiedToken ? (
                    <Check className="h-3.5 w-3.5 text-emerald-700" aria-hidden="true" />
                  ) : (
                    <Copy className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
                  )}
                  <span>{copiedToken ? t.kioskCopiedToken : t.kioskCopyTokenBtn}</span>
                </button>
              )}
            </div>
          )}

          {phase === "consumed_cooldown" && (
            <div
              role="status"
              aria-live="polite"
              className="flex min-h-[420px] flex-col items-center justify-center space-y-4"
            >
              <CheckCircle2 className="h-16 w-16 text-emerald-700" aria-hidden="true" />
              <h2 className="text-2xl font-bold text-slate-900 sm:text-3xl">
                {consumedAction === "check_out" ? t.kioskWaitingCheckOut : t.kioskWaitingCheckIn}
              </h2>
              <p className="text-base font-semibold text-slate-700">
                {t.kioskCooldownPrefix}{" "}
                <span className="font-mono text-2xl font-bold text-slate-950 tabular-nums">
                  {cooldownSeconds}
                </span>{" "}
                {t.secondsUnit}
              </p>
            </div>
          )}

          {phase === "scheduled_hidden" && (
            <div
              role="status"
              aria-live="polite"
              className="flex min-h-[420px] flex-col items-center justify-center space-y-5"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-amber-200 bg-amber-50 text-amber-700">
                <Clock className="h-8 w-8" aria-hidden="true" />
              </div>
              <div className="space-y-2">
                <h2 className="text-xl font-bold text-slate-950 sm:text-2xl">
                  {t.kioskScheduledTitle}
                </h2>
                <p className="max-w-md text-sm leading-relaxed text-slate-600">
                  {t.kioskScheduledDesc}
                </p>
              </div>
              {scheduledNextTime && (
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-5 py-3">
                  <span className="text-xs font-semibold text-slate-600">
                    {t.kioskScheduledNextPrefix}{" "}
                  </span>
                  <span
                    dir="ltr"
                    className="font-mono text-lg font-bold text-slate-950 tabular-nums"
                  >
                    {scheduledNextTime}
                  </span>
                </div>
              )}
            </div>
          )}

          {phase === "offline" && (
            <div
              role="alert"
              aria-live="polite"
              className="flex min-h-[420px] flex-col items-center justify-center space-y-4"
            >
              <WifiOff className="h-14 w-14 text-red-700" aria-hidden="true" />
              <h2 className="text-xl font-bold text-slate-950 sm:text-2xl">
                {t.kioskContactReception}
              </h2>
              <p className="max-w-md text-sm leading-relaxed text-slate-700">
                {offlineErrorCode ? formatKioskError(offlineErrorCode) : t.kioskOfflineWarning}
              </p>
            </div>
          )}
        </div>
      </section>

      <footer className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-200 pt-4 text-xs text-slate-500">
        <span>
          {t.lastUpdatedLabel}:{" "}
          <span className="font-mono font-semibold text-slate-700 tabular-nums">
            {formattedLastUpdate}
          </span>
        </span>
        <span>{t.kioskSingleUseNote}</span>
      </footer>
    </main>
  );
}
