import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { useI18n } from "../lib/i18n";
import type { UserRole } from "../types/attendance";

interface ProtectedRouteProps {
  allowedRoles: UserRole[];
  children: ReactNode;
}

export function ProtectedRoute({ allowedRoles, children }: ProtectedRouteProps) {
  const { user, profile, loading, signOut } = useAuth();
  const { t } = useI18n();

  if (loading) {
    return (
      <main className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <div className="mx-auto max-w-md space-y-4">
          <div className="h-6 w-40 animate-pulse rounded bg-slate-200" />
          <div className="h-28 w-full animate-pulse rounded-xl bg-slate-200" />
        </div>
      </main>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (!profile || !allowedRoles.includes(profile.role)) {
    return (
      <main className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
        <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-4">
          <h1 className="text-lg font-bold text-slate-900">{t.roleMismatchTitle}</h1>
          <p className="text-sm text-slate-600">{t.roleMismatchDesc}</p>
          <button
            type="button"
            onClick={() => void signOut()}
            className="min-h-[44px] rounded-lg bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 transition-colors"
          >
            {t.signOut}
          </button>
        </div>
      </main>
    );
  }

  return <>{children}</>;
}
