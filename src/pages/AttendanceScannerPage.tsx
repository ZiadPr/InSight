import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import jsQR from "jsqr";
import {
  ArrowRight,
  Camera,
  CheckCircle2,
  ClipboardPaste,
  KeyRound,
  Loader2,
  MapPin,
  WifiOff,
  X,
  XCircle,
} from "lucide-react";
import { useI18n } from "../lib/i18n";
import { isValidGpsCoordinates, isValidQrOrManualInput } from "../lib/validation";
import { submitAttendanceCheckIn } from "../services/attendanceService";

type ScanPhase =
  | "idle"
  | "acquiring"
  | "scanning"
  | "verifying"
  | "success"
  | "rejected"
  | "connection_error";

interface BarcodeDetectorInstance {
  detect: (source: ImageBitmapSource) => Promise<Array<{ rawValue?: string }>>;
}

declare global {
  interface Window {
    BarcodeDetector?: new (options?: { formats?: string[] }) => BarcodeDetectorInstance;
  }
}

export function AttendanceScannerPage() {
  const { lang, t } = useI18n();
  const navigate = useNavigate();
  const manualErrorId = useId();
  const [searchParams] = useSearchParams();
  const modeParam = searchParams.get("mode");
  const actionMode: "auto" | "check_in" | "check_out" =
    modeParam === "check_in" || modeParam === "check_out" ? modeParam : "auto";

  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [message, setMessage] = useState<string>("");
  const [resultAction, setResultAction] = useState<"check_in" | "check_out">("check_in");
  const [resultTimestamp, setResultTimestamp] = useState<string | null>(null);
  const [workedMinutes, setWorkedMinutes] = useState<number | null>(null);
  const [lateMinutes, setLateMinutes] = useState<number>(0);

  const [showManual, setShowManual] = useState<boolean>(false);
  const [manualToken, setManualToken] = useState<string>("");
  const [manualError, setManualError] = useState<string | null>(null);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const manualInputRef = useRef<HTMLInputElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const scanLockedRef = useRef<boolean>(false);

  // Brief auto-return after confirmed check-in / check-out
  useEffect(() => {
    if (phase !== "success") return;
    const timer = window.setTimeout(() => {
      navigate("/employee", { replace: true });
    }, 5000);
    return () => window.clearTimeout(timer);
  }, [navigate, phase]);

  const stopCamera = useCallback(() => {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) {
        track.stop();
      }
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  const acquireGpsBestEffort = useCallback(async () => {
    if (!("geolocation" in navigator)) {
      return {
        latitude: null,
        longitude: null,
        accuracy: null,
        capturedAt: new Date().toISOString(),
      };
    }

    try {
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 7000,
          maximumAge: 0,
        });
      });

      const latitude = position.coords.latitude;
      const longitude = position.coords.longitude;
      const accuracy = position.coords.accuracy;

      if (!isValidGpsCoordinates(latitude, longitude, accuracy)) {
        return {
          latitude: null,
          longitude: null,
          accuracy: null,
          capturedAt: new Date().toISOString(),
        };
      }

      return {
        latitude,
        longitude,
        accuracy,
        capturedAt: new Date(position.timestamp || Date.now()).toISOString(),
      };
    } catch {
      // Server enforces geofence if company_settings.enforce_geofence is enabled.
      return {
        latitude: null,
        longitude: null,
        accuracy: null,
        capturedAt: new Date().toISOString(),
      };
    }
  }, []);

  const handleTokenDetected = useCallback(
    async (rawToken: string) => {
      if (scanLockedRef.current) return;
      const trimmed = rawToken.trim();
      if (!isValidQrOrManualInput(trimmed)) {
        return;
      }

      setManualError(null);
      scanLockedRef.current = true;
      stopCamera();
      setPhase("verifying");
      setMessage(t.acquiringLocationAfterScan);

      let coords: {
        latitude: number | null;
        longitude: number | null;
        accuracy: number | null;
        capturedAt: string;
      };
      try {
        coords = await acquireGpsBestEffort();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "";
        setPhase("rejected");
        setMessage(msg === "LOCATION_DENIED" ? t.locationDenied : t.locationUnavailable);
        scanLockedRef.current = false;
        return;
      }

      setMessage(t.verifyingState);

      const idempotencyKey =
        typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(36).slice(2)}`;

      const result = await submitAttendanceCheckIn({
        qr_token: trimmed,
        action: actionMode,
        latitude: coords.latitude,
        longitude: coords.longitude,
        accuracy: coords.accuracy,
        client_captured_at: coords.capturedAt,
        idempotency_key: idempotencyKey,
      });

      if (result.ok) {
        const resolvedAct = result.action ?? (actionMode === "check_out" ? "check_out" : "check_in");
        setResultAction(resolvedAct);
        setResultTimestamp(
          resolvedAct === "check_out"
            ? (result.checked_out_at ?? new Date().toISOString())
            : (result.checked_in_at ?? new Date().toISOString()),
        );
        setWorkedMinutes(result.worked_minutes ?? null);
        setLateMinutes(result.late_minutes ?? 0);
        setPhase("success");
        setMessage(t.successSubtitle);
        return;
      }

      scanLockedRef.current = false;
      if (result.error === "NETWORK_ERROR") {
        setPhase("connection_error");
        setMessage(t.connectionErrorDesc);
        return;
      }

      const errKey = result.error ?? "DEFAULT";
      setPhase("rejected");
      setMessage(t.errorMessages[errKey] ?? t.errorMessages.DEFAULT);
    },
    [acquireGpsBestEffort, actionMode, stopCamera, t],
  );

  const startScannerLoop = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;

    const detector =
      typeof window !== "undefined" && window.BarcodeDetector
        ? new window.BarcodeDetector({ formats: ["qr_code"] })
        : null;

    let lastDetectMs = 0;

    const tick = async (timestamp: number) => {
      if (scanLockedRef.current || !streamRef.current) return;

      if (video.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA && timestamp - lastDetectMs >= 160) {
        lastDetectMs = timestamp;

        if (detector) {
          try {
            const barcodes = await detector.detect(video);
            if (barcodes.length > 0 && barcodes[0]?.rawValue) {
              void handleTokenDetected(barcodes[0].rawValue);
              return;
            }
          } catch {
            // Fall through to jsQR
          }
        }

        const canvas = canvasRef.current;
        if (canvas && video.videoWidth > 0 && video.videoHeight > 0) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          const ctx = canvas.getContext("2d", { willReadFrequently: true });
          if (ctx) {
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
              inversionAttempts: "dontInvert",
            });
            if (code?.data) {
              void handleTokenDetected(code.data);
              return;
            }
          }
        }
      }

      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);
  }, [handleTokenDetected]);

  const beginCheckInFlow = useCallback(async () => {
    scanLockedRef.current = false;
    setResultTimestamp(null);
    setMessage(t.gettingPermissions);
    setPhase("acquiring");

    if (!navigator.mediaDevices?.getUserMedia) {
      setPhase("rejected");
      setShowManual(true);
      setMessage(t.cameraDenied);
      requestAnimationFrame(() => manualInputRef.current?.focus());
      return;
    }

    let mediaStream: MediaStream;
    try {
      mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
    } catch {
      setPhase("rejected");
      setShowManual(true);
      setMessage(t.cameraDenied);
      requestAnimationFrame(() => manualInputRef.current?.focus());
      return;
    }

    streamRef.current = mediaStream;
    setPhase("scanning");
    setMessage(t.readyToScan);

    requestAnimationFrame(() => {
      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
        void videoRef.current.play().then(() => {
          startScannerLoop();
        });
      }
    });
  }, [startScannerLoop, t]);

  const handleManualSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = manualToken.trim();
    if (!isValidQrOrManualInput(trimmed)) {
      setManualError(t.manualInputInvalid);
      manualInputRef.current?.focus();
      return;
    }
    setManualError(null);
    void handleTokenDetected(trimmed);
  };

  const handlePasteManual = async () => {
    try {
      const clipText = await navigator.clipboard.readText();
      if (clipText) {
        setManualToken(clipText.trim());
        setManualError(null);
      }
      manualInputRef.current?.focus();
    } catch {
      manualInputRef.current?.focus();
    }
  };

  return (
    <main className="mx-auto max-w-3xl px-4 py-6 sm:px-6 sm:py-10 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs font-semibold text-slate-500">
            {actionMode === "check_out"
              ? t.scannerModeCheckOut
              : actionMode === "check_in"
                ? t.scannerModeCheckIn
                : t.scannerTitle}
          </p>
          <h1 className="text-lg font-bold text-slate-900 sm:text-2xl">{t.scannerTitle}</h1>
        </div>
        <Link
          to="/employee"
          onClick={() => stopCamera()}
          className="inline-flex min-h-[40px] items-center gap-1.5 text-sm font-semibold text-slate-700 hover:text-slate-950 whitespace-nowrap shrink-0"
        >
          <ArrowRight
            className={`h-4 w-4 ${lang === "en" ? "rotate-180" : ""}`}
            aria-hidden="true"
          />
          <span>{t.scannerBack}</span>
        </Link>
      </div>

      <section className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 space-y-6">
        {phase === "idle" && (
          <div className="space-y-6">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-slate-900">{t.scannerIntroTitle}</h2>
              <p className="text-sm leading-relaxed text-slate-600">{t.scannerIntroBody}</p>
            </div>

            <div className="grid grid-cols-1 gap-4 border-y border-slate-100 py-5 sm:grid-cols-2">
              <div className="flex items-start gap-3">
                <Camera className="mt-0.5 h-5 w-5 shrink-0 text-sky-800" aria-hidden="true" />
                <div className="text-sm text-slate-700">
                  {lang === "ar"
                    ? "تُستخدم الكاميرا لقراءة رمز QR المعروض عند مدخل الشركة وتُغلق فوراً."
                    : "Camera reads the reception QR code and closes immediately."}
                </div>
              </div>
              <div className="flex items-start gap-3">
                <MapPin className="mt-0.5 h-5 w-5 shrink-0 text-sky-800" aria-hidden="true" />
                <div className="text-sm text-slate-700">
                  {lang === "ar"
                    ? "يتم التحقق من الموقع الجغرافي لمقر الشركة لحظة المسح فقط."
                    : "Office GPS geofence is verified only at scan time."}
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => void beginCheckInFlow()}
              className="inline-flex min-h-[48px] w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-6 py-3.5 text-base font-semibold text-white transition-colors hover:bg-slate-800"
            >
              <Camera className="h-5 w-5 shrink-0" aria-hidden="true" />
              <span>{t.startScanBtn}</span>
            </button>
          </div>
        )}

        {phase === "acquiring" && (
          <div className="flex flex-col items-center justify-center py-12 text-center space-y-4">
            <Loader2 className="h-9 w-9 animate-spin text-sky-800" aria-hidden="true" />
            <p className="text-sm font-semibold text-slate-800">{message}</p>
          </div>
        )}

        {phase === "scanning" && (
          <div className="space-y-5">
            <p className="text-sm font-semibold text-slate-800">{message}</p>

            <div className="relative aspect-square overflow-hidden rounded-xl border border-slate-200 bg-slate-950 sm:aspect-video">
              <video
                ref={videoRef}
                playsInline
                muted
                className="h-full w-full object-cover"
              />
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0 flex items-center justify-center"
              >
                <div className="h-48 w-48 rounded-2xl border-2 border-white/80 shadow-[0_0_0_9999px_rgba(15,23,42,0.45)] sm:h-56 sm:w-56" />
              </div>
              <canvas ref={canvasRef} className="hidden" />
            </div>

            <button
              type="button"
              onClick={() => {
                stopCamera();
                setPhase("idle");
              }}
              className="inline-flex min-h-[44px] w-full items-center justify-center rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 hover:bg-slate-50"
            >
              {t.stopScanBtn}
            </button>
          </div>
        )}

        {phase === "verifying" && (
          <div role="status" aria-live="polite" className="flex flex-col items-center justify-center py-12 text-center space-y-4">
            <Loader2 className="h-10 w-10 animate-spin text-sky-800" aria-hidden="true" />
            <p className="text-base font-semibold text-slate-900">{message || t.verifyingState}</p>
          </div>
        )}

        {phase === "success" && (
          <div role="status" aria-live="polite" className="flex flex-col items-center justify-center py-8 text-center space-y-4">
            <CheckCircle2 className="h-12 w-12 text-emerald-700" aria-hidden="true" />
            <h2 className="text-xl font-bold text-slate-900">
              {resultAction === "check_out" ? t.successCheckOutTitle : t.successCheckInTitle}
            </h2>
            <p className="max-w-md text-sm text-slate-600">{message}</p>
            {resultTimestamp && (
              <div className="flex flex-wrap items-center justify-center gap-3 text-sm text-slate-700">
                <span className="font-mono font-semibold text-slate-900 tabular-nums">
                  {new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn" : "en-GB", {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false,
                  }).format(new Date(resultTimestamp))}
                </span>
                {resultAction === "check_in" && lateMinutes > 0 && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="font-semibold text-amber-700">
                      {t.lateByLabel} {lateMinutes} {t.minutesUnit}
                    </span>
                  </>
                )}
                {resultAction === "check_out" && workedMinutes !== null && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono font-semibold text-slate-900 tabular-nums">
                      {Math.floor(workedMinutes / 60)}:{String(workedMinutes % 60).padStart(2, "0")}{" "}
                      {t.hoursUnit}
                    </span>
                  </>
                )}
              </div>
            )}
            <Link
              to="/employee"
              className="mt-2 inline-flex min-h-[48px] items-center justify-center rounded-xl bg-slate-900 px-8 py-3 text-sm font-semibold text-white hover:bg-slate-800"
            >
              {t.scannerBack}
            </Link>
          </div>
        )}

        {(phase === "rejected" || phase === "connection_error") && (
          <div role="alert" aria-live="polite" className="flex flex-col items-center justify-center py-8 text-center space-y-4">
            {phase === "connection_error" ? (
              <WifiOff className="h-12 w-12 text-amber-700" aria-hidden="true" />
            ) : (
              <XCircle className="h-12 w-12 text-red-700" aria-hidden="true" />
            )}
            <h2 className="text-xl font-bold text-slate-900">
              {phase === "connection_error" ? t.connectionErrorTitle : t.rejectedTitle}
            </h2>
            <p className="max-w-md text-sm leading-relaxed text-slate-700">{message}</p>
            <div className="mt-2 flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center sm:justify-center">
              <button
                type="button"
                onClick={() => void beginCheckInFlow()}
                className="inline-flex min-h-[48px] w-full items-center justify-center rounded-xl bg-slate-900 px-6 py-3 text-sm font-semibold text-white hover:bg-slate-800 sm:w-auto"
              >
                {t.scanAgainBtn}
              </button>
              <Link
                to="/employee"
                className="inline-flex min-h-[48px] w-full items-center justify-center rounded-xl border border-slate-300 bg-white px-6 py-3 text-sm font-semibold text-slate-800 hover:bg-slate-50 sm:w-auto"
              >
                {t.scannerBack}
              </Link>
            </div>
          </div>
        )}

        {/* Secondary Fallback: Manual QR / 8-char code entry when camera is unavailable */}
        {phase !== "success" && phase !== "verifying" && (
          <div className="border-t border-slate-200 pt-5 space-y-3">
            <button
              type="button"
              onClick={() => setShowManual((prev) => !prev)}
              aria-expanded={showManual}
              className="inline-flex min-h-[40px] items-center gap-2 text-xs font-semibold text-slate-700 hover:text-sky-900"
            >
              <KeyRound className="h-4 w-4 shrink-0 text-sky-800" aria-hidden="true" />
              <span>{t.manualTokenToggle}</span>
            </button>

            {showManual && (
              <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 space-y-3">
                <p className="text-xs leading-relaxed text-slate-600">{t.manualInputHint}</p>
                <form onSubmit={handleManualSubmit} className="flex flex-col gap-2 sm:flex-row">
                  <div className="relative flex flex-1 items-center">
                    <input
                      ref={manualInputRef}
                      type="text"
                      dir="ltr"
                      autoComplete="off"
                      spellCheck={false}
                      aria-label={t.manualTokenToggle}
                      aria-describedby={manualError ? manualErrorId : undefined}
                      value={manualToken}
                      onChange={(e) => {
                        setManualToken(e.target.value);
                        if (manualError) setManualError(null);
                      }}
                      placeholder={t.manualTokenPlaceholder}
                      className="min-h-[44px] w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-xs placeholder:text-slate-400 focus:border-sky-800 focus:outline-none focus:ring-2 focus:ring-sky-800/20"
                    />
                    {manualToken.length > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          setManualToken("");
                          setManualError(null);
                          manualInputRef.current?.focus();
                        }}
                        aria-label={t.manualClearBtn}
                        className="absolute right-2 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                      >
                        <X className="h-4 w-4" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => void handlePasteManual()}
                      className="inline-flex min-h-[44px] items-center justify-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0"
                    >
                      <ClipboardPaste className="h-4 w-4 text-slate-600" aria-hidden="true" />
                      <span>{t.manualPasteBtn}</span>
                    </button>
                    <button
                      type="submit"
                      className="inline-flex min-h-[44px] flex-1 items-center justify-center rounded-lg bg-sky-800 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-700 whitespace-nowrap shrink-0 sm:flex-initial"
                    >
                      {t.manualTokenSubmit}
                    </button>
                  </div>
                </form>

                {manualError && (
                  <p id={manualErrorId} role="alert" className="text-xs font-semibold text-red-700">
                    {manualError}
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </section>
    </main>
  );
}
