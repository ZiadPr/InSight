import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { TopBar } from "./components/TopBar";
import { AuthProvider } from "./hooks/useAuth";
import { I18nContext, translations } from "./lib/i18n";
import { AttendanceScannerPage } from "./pages/AttendanceScannerPage";
import { EmployeeDashboard } from "./pages/EmployeeDashboard";
import { HrDashboardPage } from "./pages/HrDashboardPage";
import { KioskPage } from "./pages/KioskPage";
import { LoginPage } from "./pages/LoginPage";
import type { AppLanguage } from "./types/attendance";

export default function App() {
  const [lang, setLang] = useState<AppLanguage>("ar");

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  }, [lang]);

  const i18nValue = useMemo(
    () => ({
      lang,
      setLang,
      t: translations[lang],
    }),
    [lang],
  );

  return (
    <I18nContext.Provider value={i18nValue}>
      <AuthProvider>
        <BrowserRouter>
          <div className="min-h-screen bg-slate-50 text-slate-900">
            <TopBar />
            <Routes>
              <Route path="/" element={<Navigate to="/login" replace />} />
              <Route path="/login" element={<LoginPage />} />
              <Route
                path="/employee"
                element={
                  <ProtectedRoute allowedRoles={["employee"]}>
                    <EmployeeDashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/employee/scan"
                element={
                  <ProtectedRoute allowedRoles={["employee"]}>
                    <AttendanceScannerPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/hr"
                element={
                  <ProtectedRoute allowedRoles={["admin"]}>
                    <HrDashboardPage />
                  </ProtectedRoute>
                }
              />
              <Route path="/kiosk" element={<KioskPage />} />
              <Route path="/student" element={<Navigate to="/employee" replace />} />
              <Route path="/student/scan" element={<Navigate to="/employee/scan" replace />} />
              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </div>
        </BrowserRouter>
      </AuthProvider>
    </I18nContext.Provider>
  );
}
