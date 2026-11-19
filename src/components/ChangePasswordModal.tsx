import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Eye, EyeOff, KeyRound, X } from "lucide-react";
import { setStoredSessionToken } from "../lib/authStorage";
import { useI18n } from "../lib/i18n";
import { changeOwnPassword } from "../services/hrService";

interface ChangePasswordModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export function ChangePasswordModal({ open, onClose, onSuccess }: ChangePasswordModalProps) {
  const { lang, t } = useI18n();
  const titleId = useId();
  const errorId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstInputRef = useRef<HTMLInputElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    previousFocusRef.current = document.activeElement as HTMLElement | null;
    requestAnimationFrame(() => firstInputRef.current?.focus());

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === "Tab" && dialogRef.current) {
        const focusables = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
          ),
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previousFocusRef.current?.focus?.();
    };
  }, [onClose, open]);

  if (!open) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      setErrorMsg(
        lang === "ar"
          ? "يجب أن تتكون كلمة المرور الجديدة من 8 أحرف على الأقل وتحتوي على حروف وأرقام."
          : "New password must be at least 8 characters and include letters and numbers.",
      );
      return;
    }

    if (newPassword !== confirmPassword) {
      setErrorMsg(
        lang === "ar" ? "كلمة المرور الجديدة وتأكيدها غير متطابقين." : "Passwords do not match.",
      );
      return;
    }

    setSubmitting(true);
    const res = await changeOwnPassword({
      current_password: currentPassword,
      new_password: newPassword,
    });
    setSubmitting(false);

    if (!res.ok) {
      setErrorMsg(
        res.error === "INVALID_CURRENT_PASSWORD"
          ? lang === "ar"
            ? "كلمة المرور الحالية غير صحيحة."
            : "Current password is incorrect."
          : lang === "ar"
            ? "تعذر تحديث كلمة المرور. تأكد من قوة كلمة المرور الجديدة."
            : "Unable to update password.",
      );
      return;
    }

    if (res.token) {
      setStoredSessionToken(res.token);
    }
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    onSuccess?.();
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-[1px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 space-y-5 shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-slate-700" aria-hidden="true" />
            <h2 id={titleId} className="text-base font-bold text-slate-900">
              {lang === "ar" ? "تغيير كلمة المرور" : "Change Password"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t.hrCancelAction}
            className="min-h-[36px] min-w-[36px] inline-flex items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-sky-800"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label htmlFor="cp-current" className="block text-xs font-semibold text-slate-700">
              {lang === "ar" ? "كلمة المرور الحالية *" : "Current Password *"}
            </label>
            <div className="relative flex items-center">
              <input
                ref={firstInputRef}
                id="cp-current"
                type={showCurrent ? "text" : "password"}
                required
                dir="ltr"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                aria-describedby={errorMsg ? errorId : undefined}
                className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3 pe-10 text-sm focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
              />
              <button
                type="button"
                onClick={() => setShowCurrent((v) => !v)}
                aria-label={showCurrent ? t.hidePasswordLabel : t.showPasswordLabel}
                className="absolute end-1.5 inline-flex min-h-[36px] min-w-[36px] items-center justify-center rounded text-slate-500 hover:text-slate-800"
              >
                {showCurrent ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              </button>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="cp-new" className="block text-xs font-semibold text-slate-700">
              {lang === "ar"
                ? "كلمة المرور الجديدة (8 أحرف على الأقل مع حروف وأرقام) *"
                : "New Password (8+ chars, letters & numbers) *"}
            </label>
            <div className="relative flex items-center">
              <input
                id="cp-new"
                type={showNew ? "text" : "password"}
                required
                minLength={8}
                dir="ltr"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                aria-describedby={errorMsg ? errorId : undefined}
                className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3 pe-10 text-sm focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
              />
              <button
                type="button"
                onClick={() => setShowNew((v) => !v)}
                aria-label={showNew ? t.hidePasswordLabel : t.showPasswordLabel}
                className="absolute end-1.5 inline-flex min-h-[36px] min-w-[36px] items-center justify-center rounded text-slate-500 hover:text-slate-800"
              >
                {showNew ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              </button>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="cp-confirm" className="block text-xs font-semibold text-slate-700">
              {lang === "ar" ? "تأكيد كلمة المرور الجديدة *" : "Confirm New Password *"}
            </label>
            <input
              id="cp-confirm"
              type={showNew ? "text" : "password"}
              required
              minLength={8}
              dir="ltr"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              aria-describedby={errorMsg ? errorId : undefined}
              className="min-h-[44px] w-full rounded-lg border border-slate-300 px-3 text-sm focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
            />
          </div>

          {errorMsg && (
            <div
              id={errorId}
              role="alert"
              className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-xs font-medium text-red-800"
            >
              {errorMsg}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="min-h-[42px] rounded-lg border border-slate-300 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
            >
              {lang === "ar" ? "إلغاء" : "Cancel"}
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="min-h-[42px] rounded-lg bg-slate-900 px-5 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:bg-slate-300"
            >
              {lang === "ar" ? "تحديث وإنهاء الجلسات السابقة" : "Update Password"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
