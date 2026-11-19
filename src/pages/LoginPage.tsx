import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";
import { Building2, Eye, EyeOff, HelpCircle, Lock, Monitor, ShieldCheck, UserCheck } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";
import { isValidEmail } from "../lib/validation";

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement,
        opts: { sitekey: string; callback: (token: string) => void; "expired-callback"?: () => void },
      ) => string;
      reset: (widgetId?: string) => void;
    };
  }
}

export function LoginPage() {
  const { user, profile, loading, signIn } = useAuth();
  const { lang, t } = useI18n();
  const errorId = useId();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [turnstileSiteKey, setTurnstileSiteKey] = useState<string>("");
  const [turnstileToken, setTurnstileToken] = useState<string>("");
  const turnstileRef = useRef<HTMLDivElement | null>(null);
  const widgetIdRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    let active = true;
    void fetch("/api/auth/public-config")
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg: { ok?: boolean; turnstile_enabled?: boolean; turnstile_site_key?: string } | null) => {
        if (!active || !cfg?.ok || !cfg.turnstile_enabled || !cfg.turnstile_site_key) return;
        setTurnstileSiteKey(cfg.turnstile_site_key);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!turnstileSiteKey || !turnstileRef.current) return;
    const renderWidget = () => {
      if (!window.turnstile || !turnstileRef.current) return;
      turnstileRef.current.innerHTML = "";
      widgetIdRef.current = window.turnstile.render(turnstileRef.current, {
        sitekey: turnstileSiteKey,
        callback: (tok) => setTurnstileToken(tok),
        "expired-callback": () => setTurnstileToken(""),
      });
    };
    if (window.turnstile) {
      renderWidget();
      return;
    }
    const existing = document.querySelector<HTMLScriptElement>(
      'script[src^="https://challenges.cloudflare.com/turnstile/"]',
    );
    if (!existing) {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.defer = true;
      script.onload = renderWidget;
      document.head.appendChild(script);
    } else {
      existing.addEventListener("load", renderWidget, { once: true });
    }
  }, [turnstileSiteKey]);

  if (!loading && user && profile) {
    if (profile.role === "admin") {
      return <Navigate to="/hr" replace />;
    }
    if (profile.role === "kiosk") {
      return <Navigate to="/kiosk" replace />;
    }
    if (profile.role === "employee") {
      return <Navigate to="/employee" replace />;
    }
  }

  async function executeSignIn(targetEmail: string, targetPassword: string) {
    setErrorMsg(null);
    if (!isValidEmail(targetEmail)) {
      setErrorMsg(t.invalidEmailFormat);
      return;
    }
    if (targetPassword.length === 0) {
      setErrorMsg(t.emptyPasswordError);
      return;
    }

    if (turnstileSiteKey && !turnstileToken) {
      setErrorMsg(
        lang === "ar"
          ? "يرجى إتمام التحقق الأمني (Cloudflare Turnstile) قبل تسجيل الدخول."
          : "Please complete the Cloudflare Turnstile verification check.",
      );
      return;
    }

    setSubmitting(true);
    const res = await signIn(targetEmail, targetPassword, turnstileToken || undefined);
    setSubmitting(false);

    if (!res.ok) {
      if (window.turnstile && widgetIdRef.current) {
        window.turnstile.reset(widgetIdRef.current);
        setTurnstileToken("");
      }
      switch (res.error) {
        case "RATE_LIMITED":
          setErrorMsg(t.errorMessages.RATE_LIMITED);
          break;
        case "CAPTCHA_REQUIRED":
        case "CAPTCHA_FAILED":
          setErrorMsg(
            lang === "ar"
              ? "فشل التحقق الأمني ضد البوتات (Cloudflare Turnstile). أعد المحاولة."
              : "Bot verification challenge failed. Please try again.",
          );
          break;
        case "ACCOUNT_UNAVAILABLE":
          setErrorMsg(t.accountInactive);
          break;
        case "EMAIL_NOT_CONFIRMED":
          setErrorMsg(t.emailNotConfirmed);
          break;
        case "NETWORK_ERROR":
          setErrorMsg(t.serverConnectionFailed);
          break;
        case "PROFILE_NOT_FOUND":
          setErrorMsg(t.profileNotFoundDesc);
          break;
        default:
          setErrorMsg(t.invalidCredentials);
      }
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await executeSignIn(email, password);
  }

  const handleQuickDemo = (demoEmail: string, demoPassword: string) => {
    if (!import.meta.env.DEV) return;
    setEmail(demoEmail);
    setPassword(demoPassword);
    void executeSignIn(demoEmail, demoPassword);
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-10 lg:py-14">
      <div className="grid grid-cols-1 items-stretch gap-6 sm:gap-8 lg:grid-cols-12">
        {/* Focused Institutional Welcome Panel */}
        <section className="order-2 flex flex-col justify-between rounded-2xl border border-slate-200 bg-slate-900 p-6 text-slate-50 sm:p-8 lg:order-1 lg:col-span-5 lg:p-10">
          <div className="space-y-5">
            <div className="inline-flex items-center gap-2 text-xs font-semibold text-sky-300">
              <Building2 className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{t.brandName}</span>
            </div>

            <h1 className="text-2xl font-bold leading-snug text-white sm:text-3xl text-balance">
              {lang === "ar"
                ? "تسجيل حضور وانصراف سريع وآمن لموظفي المؤسسة"
                : "Fast, Reliable Employee Attendance & Shift Tracking"}
            </h1>

            <p className="text-sm leading-relaxed text-slate-300">
              {lang === "ar"
                ? "بعد تسجيل الدخول يمكنك متابعة حالة دوامك اليومي، تسجيل الحضور والانصراف عبر رمز الاستقبال، ومراجعة ساعات عملك بوضوح."
                : "Sign in to view today's shift status, record check-in and check-out at reception, and review your attendance history."}
            </p>
          </div>

          <div className="mt-8 border-t border-slate-800 pt-5 text-xs leading-relaxed text-slate-300 space-y-2">
            <p className="font-semibold text-white">
              {lang === "ar" ? "موظف جديد؟" : "New Employee?"}
            </p>
            <p>{t.noSelfSignupNotice}</p>
          </div>
        </section>

        {/* Sign-In Form Column */}
        <section className="order-1 flex flex-col justify-center rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 lg:order-2 lg:col-span-7 lg:p-10">
          <div className="space-y-1.5">
            <h2 className="text-xl font-bold text-slate-900 sm:text-2xl">{t.loginTitle}</h2>
            <p className="text-sm text-slate-600">{t.loginSubtitle}</p>
          </div>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4" noValidate>
            <div className="space-y-1.5">
              <label
                htmlFor="login-email"
                className="block text-sm font-semibold text-slate-800"
              >
                {t.emailLabel}
              </label>
              <input
                id="login-email"
                name="email"
                type="email"
                autoComplete="email"
                dir="ltr"
                required
                disabled={submitting}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                aria-invalid={Boolean(errorMsg)}
                aria-describedby={errorMsg ? errorId : undefined}
                placeholder="name@company.com"
                className="min-h-[46px] w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-base text-slate-900 placeholder:text-slate-400 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20 disabled:bg-slate-100 sm:min-h-[44px] sm:text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="login-password"
                className="block text-sm font-semibold text-slate-800"
              >
                {t.passwordLabel}
              </label>
              <div className="relative flex items-center">
                <input
                  id="login-password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  dir="ltr"
                  required
                  disabled={submitting}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  aria-invalid={Boolean(errorMsg)}
                  aria-describedby={errorMsg ? errorId : undefined}
                  className="min-h-[46px] w-full rounded-lg border border-slate-300 bg-white px-3.5 pe-12 py-2.5 text-base text-slate-900 placeholder:text-slate-400 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20 disabled:bg-slate-100 sm:min-h-[44px] sm:text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? t.hidePasswordLabel : t.showPasswordLabel}
                  className="absolute end-1 inline-flex min-h-[40px] min-w-[40px] items-center justify-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-2 focus-visible:outline-sky-800"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            {turnstileSiteKey && (
              <div className="pt-1">
                <div ref={turnstileRef} />
              </div>
            )}

            {errorMsg && (
              <div
                id={errorId}
                role="alert"
                aria-live="polite"
                className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-800"
              >
                {errorMsg}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="inline-flex min-h-[48px] w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-800"
            >
              <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{submitting ? t.signingIn : t.signInBtn}</span>
            </button>
          </form>

          <div className="mt-5 flex items-start gap-2 border-t border-slate-100 pt-4 text-xs leading-relaxed text-slate-600">
            <HelpCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
            <p>{t.forgotPasswordHelp}</p>
          </div>

          {/* Development-only Demo Role Accounts (tree-shaken in production builds) */}
          {import.meta.env.DEV && (
            <div className="mt-6 border-t border-slate-200 pt-5 space-y-3">
              <p className="text-xs font-semibold text-slate-600">{t.quickDemoTitle}</p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => handleQuickDemo("ahmed@company.com", "Emp@2026")}
                  className="inline-flex min-h-[42px] items-center justify-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-100 hover:border-slate-300 whitespace-nowrap"
                >
                  <UserCheck className="h-4 w-4 shrink-0 text-sky-700" aria-hidden="true" />
                  <span>{t.quickDemoEmployee}</span>
                </button>

                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => handleQuickDemo("hr@company.com", "Admin@2026")}
                  className="inline-flex min-h-[42px] items-center justify-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-100 hover:border-slate-300 whitespace-nowrap"
                >
                  <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-700" aria-hidden="true" />
                  <span>{t.quickDemoHr}</span>
                </button>
              </div>

              <Link
                to="/kiosk"
                className="inline-flex min-h-[40px] w-full items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-50"
              >
                <Monitor className="h-4 w-4 shrink-0 text-slate-600" aria-hidden="true" />
                <span>{t.quickDemoKiosk}</span>
              </Link>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
