import { Link, useLocation } from "react-router-dom";
import { LogOut } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";

export function TopBar() {
  const { lang, setLang, t } = useI18n();
  const { user, profile, signOut } = useAuth();
  const location = useLocation();

  const isKioskRoute = location.pathname.startsWith("/kiosk");
  const isEmployeeRoute =
    location.pathname.startsWith("/employee") || location.pathname.startsWith("/student");
  const isHrRoute = location.pathname.startsWith("/hr");

  // Only show Kiosk link to dedicated Kiosk sessions or while explicitly on /kiosk
  const showKioskNav = profile?.role === "kiosk" || isKioskRoute;

  const homePath =
    profile?.role === "admin"
      ? "/hr"
      : profile?.role === "kiosk"
        ? "/kiosk"
        : profile?.role === "employee"
          ? "/employee"
          : "/login";

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-sm">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between gap-4 px-4 sm:gap-8 sm:px-6">
        {/* Zone 1: Single-line Brand Wordmark */}
        <Link
          to={homePath}
          className="whitespace-nowrap shrink-0 text-sm font-bold tracking-tight text-slate-900 sm:text-base focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800"
        >
          {t.brandName}
        </Link>

        {/* Zone 2: Role-scoped single-line text navigation links */}
        <nav
          aria-label={lang === "ar" ? "التنقل الرئيسي" : "Main navigation"}
          className="hidden sm:flex items-center gap-6 text-sm font-medium text-slate-600"
        >
          {!user && (
            <Link
              to="/login"
              aria-current={location.pathname === "/login" ? "page" : undefined}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800 ${
                location.pathname === "/login"
                  ? "text-slate-900 underline decoration-sky-800 decoration-2 underline-offset-8"
                  : ""
              }`}
            >
              {t.signInNav}
            </Link>
          )}

          {profile?.role === "employee" && (
            <>
              <Link
                to="/employee"
                aria-current={isEmployeeRoute && !location.pathname.includes("/scan") ? "page" : undefined}
                className={`whitespace-nowrap shrink-0 py-1 transition-colors hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800 ${
                  isEmployeeRoute && !location.pathname.includes("/scan")
                    ? "text-slate-900 underline decoration-sky-800 decoration-2 underline-offset-8"
                    : ""
                }`}
              >
                {t.employeePortal}
              </Link>
              <Link
                to="/employee/scan"
                aria-current={location.pathname.includes("/scan") ? "page" : undefined}
                className={`whitespace-nowrap shrink-0 py-1 transition-colors hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800 ${
                  location.pathname.includes("/scan")
                    ? "text-slate-900 underline decoration-sky-800 decoration-2 underline-offset-8"
                    : ""
                }`}
              >
                {t.scannerTitle}
              </Link>
            </>
          )}

          {profile?.role === "admin" && (
            <Link
              to="/hr"
              aria-current={isHrRoute ? "page" : undefined}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800 ${
                isHrRoute
                  ? "text-slate-900 underline decoration-sky-800 decoration-2 underline-offset-8"
                  : ""
              }`}
            >
              {t.hrConsole}
            </Link>
          )}

          {showKioskNav && (
            <Link
              to="/kiosk"
              aria-current={isKioskRoute ? "page" : undefined}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-800 ${
                isKioskRoute
                  ? "text-slate-900 underline decoration-sky-800 decoration-2 underline-offset-8"
                  : ""
              }`}
            >
              {t.kioskScreen}
            </Link>
          )}
        </nav>

        {/* Zone 3: Language toggle & Sign Out */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setLang(lang === "ar" ? "en" : "ar")}
            className="min-h-[40px] rounded-lg px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 hover:text-slate-950 transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-800"
          >
            {t.switchLang}
          </button>

          {user && (
            <button
              type="button"
              onClick={() => void signOut()}
              className="inline-flex min-h-[40px] items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-slate-800 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-800"
            >
              <LogOut className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>{t.signOut}</span>
            </button>
          )}
        </div>
      </div>

      {/* Role-scoped mobile navigation row (only shown when employee has two destinations) */}
      {profile?.role === "employee" && (
        <nav
          aria-label={lang === "ar" ? "تنقل الموظف على الهاتف" : "Mobile employee navigation"}
          className="flex items-center justify-around border-t border-slate-100 bg-slate-50/70 px-3 sm:hidden"
        >
          <Link
            to="/employee"
            aria-current={isEmployeeRoute && !location.pathname.includes("/scan") ? "page" : undefined}
            className={`flex min-h-[40px] flex-1 items-center justify-center text-xs font-semibold transition-colors whitespace-nowrap ${
              isEmployeeRoute && !location.pathname.includes("/scan")
                ? "border-b-2 border-sky-800 text-slate-950"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            {t.employeePortal}
          </Link>
          <Link
            to="/employee/scan"
            aria-current={location.pathname.includes("/scan") ? "page" : undefined}
            className={`flex min-h-[40px] flex-1 items-center justify-center text-xs font-semibold transition-colors whitespace-nowrap ${
              location.pathname.includes("/scan")
                ? "border-b-2 border-sky-800 text-slate-950"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            {t.scannerTitle}
          </Link>
        </nav>
      )}
    </header>
  );
}
