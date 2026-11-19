-- Migration 0001: Initial Schema for University QR Attendance System
-- Designed for idempotent / careful re-execution in PostgreSQL (Supabase).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Profiles linked to Supabase Auth users (provisioned by administrators only)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL CHECK (char_length(trim(full_name)) >= 2),
  student_number TEXT UNIQUE,
  role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'kiosk', 'admin')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Campus settings (single active campus configuration)
CREATE TABLE IF NOT EXISTS public.campus_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campus_name TEXT NOT NULL CHECK (char_length(trim(campus_name)) >= 2),
  latitude DOUBLE PRECISION NOT NULL CHECK (latitude BETWEEN -90 AND 90),
  longitude DOUBLE PRECISION NOT NULL CHECK (longitude BETWEEN -180 AND 180),
  allowed_radius_m INTEGER NOT NULL CHECK (allowed_radius_m > 0 AND allowed_radius_m <= 10000),
  max_gps_accuracy_m INTEGER NOT NULL CHECK (max_gps_accuracy_m > 0 AND max_gps_accuracy_m <= 500),
  qr_ttl_seconds INTEGER NOT NULL DEFAULT 20 CHECK (qr_ttl_seconds BETWEEN 5 AND 120),
  timezone TEXT NOT NULL DEFAULT 'Asia/Riyadh',
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. Approved Kiosk display devices
CREATE TABLE IF NOT EXISTS public.kiosk_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_name TEXT NOT NULL CHECK (char_length(trim(device_name)) >= 2),
  auth_user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
  secret_hash TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. Official study calendar for accurate absence reporting
CREATE TABLE IF NOT EXISTS public.study_calendar (
  study_date DATE PRIMARY KEY,
  is_study_day BOOLEAN NOT NULL DEFAULT TRUE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. Short-lived single-use QR tokens (only SHA-256 hash stored, never raw token)
CREATE TABLE IF NOT EXISTS public.qr_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT NOT NULL UNIQUE,
  kiosk_device_id UUID NOT NULL REFERENCES public.kiosk_devices(id) ON DELETE RESTRICT,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  consumed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'consumed', 'expired', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT qr_expires_after_issue CHECK (expires_at > issued_at)
);

-- Guarantee at most ONE active QR token per kiosk device at any instant
CREATE UNIQUE INDEX IF NOT EXISTS one_active_qr_per_kiosk
  ON public.qr_tokens (kiosk_device_id)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_qr_tokens_kiosk_issued
  ON public.qr_tokens (kiosk_device_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_qr_tokens_expires_at
  ON public.qr_tokens (expires_at)
  WHERE status = 'active';

-- 6. Attendance records with hard daily uniqueness per student
CREATE TABLE IF NOT EXISTS public.attendance_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  attendance_date DATE NOT NULL,
  checked_in_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  qr_token_id UUID NOT NULL UNIQUE REFERENCES public.qr_tokens(id) ON DELETE RESTRICT,
  latitude DOUBLE PRECISION CHECK (latitude IS NULL OR (latitude BETWEEN -90 AND 90)),
  longitude DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180)),
  gps_accuracy_m DOUBLE PRECISION CHECK (gps_accuracy_m IS NULL OR gps_accuracy_m > 0),
  status TEXT NOT NULL DEFAULT 'present' CHECK (status IN ('present', 'excused')),
  idempotency_key TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT one_attendance_per_student_per_day UNIQUE (student_id, attendance_date)
);

CREATE INDEX IF NOT EXISTS idx_attendance_student_date
  ON public.attendance_records (student_id, attendance_date DESC);

CREATE INDEX IF NOT EXISTS idx_attendance_date
  ON public.attendance_records (attendance_date DESC);

-- 7. Security & audit logs (never store raw tokens, JWTs, or passwords)
CREATE TABLE IF NOT EXISTS public.security_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  reason_code TEXT,
  qr_token_id UUID REFERENCES public.qr_tokens(id) ON DELETE SET NULL,
  ip_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_security_logs_created_at
  ON public.security_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_logs_user_created
  ON public.security_logs (user_id, created_at DESC);

-- 8. Server-side rate limiting state
CREATE TABLE IF NOT EXISTS public.rate_limits (
  key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  blocked_until TIMESTAMPTZ
);

-- Updated_at trigger helper
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_campus_settings_updated_at ON public.campus_settings;
CREATE TRIGGER trg_campus_settings_updated_at
  BEFORE UPDATE ON public.campus_settings
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- Prevent privilege escalation or tampering with protected profile columns from client sessions
CREATE OR REPLACE FUNCTION public.prevent_profile_privilege_escalation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF COALESCE(current_setting('request.jwt.claim.role', true), '') NOT IN ('service_role', '') THEN
    IF NEW.role IS DISTINCT FROM OLD.role
       OR NEW.is_active IS DISTINCT FROM OLD.is_active
       OR NEW.student_number IS DISTINCT FROM OLD.student_number
       OR NEW.id IS DISTINCT FROM OLD.id THEN
      RAISE EXCEPTION 'Protected profile fields cannot be modified from client context';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_profile_escalation ON public.profiles;
CREATE TRIGGER trg_prevent_profile_escalation
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_profile_privilege_escalation();
