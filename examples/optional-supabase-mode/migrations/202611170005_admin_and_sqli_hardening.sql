-- Migration 0005: Admin Step-Up Protection, SQLi Input Guards, and Encrypted Audit Hardening
-- Aligns PostgreSQL schema with InSight (ان سايت) zero-compromise data protection controls.

-- 1. Strict text sanitization / SQLi meta-sequence check function
CREATE OR REPLACE FUNCTION public.assert_safe_text(
  p_value TEXT,
  p_max_length INTEGER DEFAULT 500
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_clean TEXT;
BEGIN
  IF p_value IS NULL THEN
    RETURN NULL;
  END IF;

  IF char_length(p_value) > GREATEST(1, p_max_length) THEN
    RAISE EXCEPTION 'Input exceeds maximum allowed length (%)', p_max_length;
  END IF;

  -- Reject NUL bytes and ASCII control characters (except standard tab/newline)
  IF p_value ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
    RAISE EXCEPTION 'Unsafe control characters rejected';
  END IF;

  -- Reject high-confidence SQL injection patterns in stored text fields
  IF p_value ~* '(\bunion\b\s+\bselect\b|;\s*(drop|delete|truncate|alter|exec)\b|--\s*$|/\*|\*/|\bpg_sleep\s*\()' THEN
    RAISE EXCEPTION 'Unsafe SQL meta-sequence rejected';
  END IF;

  v_clean := btrim(p_value);
  RETURN v_clean;
END;
$$;

REVOKE ALL ON FUNCTION public.assert_safe_text(TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.assert_safe_text(TEXT, INTEGER) TO service_role;

-- 2. Extend profiles and attendance records safely for InSight HR workforce support
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS department TEXT,
  ADD COLUMN IF NOT EXISTS job_title TEXT,
  ADD COLUMN IF NOT EXISTS shift_start TEXT NOT NULL DEFAULT '09:00',
  ADD COLUMN IF NOT EXISTS shift_end TEXT NOT NULL DEFAULT '17:00',
  ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE public.attendance_records
  ADD COLUMN IF NOT EXISTS checked_out_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS worked_minutes INTEGER CHECK (worked_minutes IS NULL OR worked_minutes >= 0),
  ADD COLUMN IF NOT EXISTS late_minutes INTEGER NOT NULL DEFAULT 0 CHECK (late_minutes >= 0),
  ADD COLUMN IF NOT EXISTS notes TEXT;

-- 3. Admin Step-Up Verification Sessions (tracks server-side HR elevation + UA binding)
CREATE TABLE IF NOT EXISTS public.admin_step_up_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  ua_hash TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CONSTRAINT admin_step_up_valid_window CHECK (expires_at > verified_at)
);

CREATE INDEX IF NOT EXISTS idx_admin_step_up_user_exp
  ON public.admin_step_up_sessions (admin_user_id, expires_at DESC);

-- 4. Dedicated Admin Access & Export Audit Ledger (append-only from service_role)
CREATE TABLE IF NOT EXISTS public.admin_access_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  action_name TEXT NOT NULL CHECK (char_length(trim(action_name)) >= 2),
  target_resource TEXT NOT NULL,
  ip_hash TEXT,
  ua_hash TEXT,
  encrypted_channel_used BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_admin_access_audit_created
  ON public.admin_access_audit (created_at DESC);

-- 5. Enable strict Row Level Security on every newly added table (no permissive policies)
ALTER TABLE public.admin_step_up_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_access_audit ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.admin_step_up_sessions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.admin_access_audit FROM PUBLIC, anon, authenticated;

-- Admin can read own audit ledger via RLS; writes restricted strictly to service_role
GRANT SELECT ON public.admin_access_audit TO authenticated;

DROP POLICY IF EXISTS "admin_access_audit_select_admin" ON public.admin_access_audit;
CREATE POLICY "admin_access_audit_select_admin"
  ON public.admin_access_audit
  FOR SELECT
  TO authenticated
  USING (public.is_admin() AND admin_user_id = auth.uid());

-- 6. Trigger to validate safe text on attendance_records.notes & profiles text columns
CREATE OR REPLACE FUNCTION public.enforce_safe_attendance_and_profile_text()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_TABLE_NAME = 'profiles' THEN
    NEW.full_name := public.assert_safe_text(NEW.full_name, 160);
    NEW.department := public.assert_safe_text(NEW.department, 120);
    NEW.job_title := public.assert_safe_text(NEW.job_title, 120);
  ELSIF TG_TABLE_NAME = 'attendance_records' THEN
    NEW.notes := public.assert_safe_text(NEW.notes, 300);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_safe_profile_text ON public.profiles;
CREATE TRIGGER trg_safe_profile_text
  BEFORE INSERT OR UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.enforce_safe_attendance_and_profile_text();

DROP TRIGGER IF EXISTS trg_safe_attendance_notes ON public.attendance_records;
CREATE TRIGGER trg_safe_attendance_notes
  BEFORE INSERT OR UPDATE ON public.attendance_records
  FOR EACH ROW
  EXECUTE FUNCTION public.enforce_safe_attendance_and_profile_text();

-- 7. Update retention cleanup function to also prune expired admin step-up sessions & old audit entries
CREATE OR REPLACE FUNCTION public.cleanup_security_and_expired_data(
  p_retention_days INTEGER DEFAULT 90
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_retention_cutoff TIMESTAMPTZ := v_now - make_interval(days => GREATEST(30, p_retention_days));
  v_qr_cutoff TIMESTAMPTZ := v_now - interval '30 days';
  v_expired_marked INTEGER := 0;
  v_qr_deleted INTEGER := 0;
  v_rate_limits_deleted INTEGER := 0;
  v_logs_deleted INTEGER := 0;
  v_gps_scrubbed INTEGER := 0;
  v_stepup_deleted INTEGER := 0;
BEGIN
  UPDATE public.qr_tokens
  SET status = 'expired'
  WHERE status = 'active'
    AND expires_at <= v_now;
  GET DIAGNOSTICS v_expired_marked = ROW_COUNT;

  DELETE FROM public.qr_tokens q
  WHERE q.status IN ('expired', 'revoked')
    AND q.created_at < v_qr_cutoff
    AND NOT EXISTS (
      SELECT 1 FROM public.attendance_records ar WHERE ar.qr_token_id = q.id
    );
  GET DIAGNOSTICS v_qr_deleted = ROW_COUNT;

  DELETE FROM public.rate_limits
  WHERE window_started_at < v_now - interval '1 day'
    AND (blocked_until IS NULL OR blocked_until < v_now);
  GET DIAGNOSTICS v_rate_limits_deleted = ROW_COUNT;

  DELETE FROM public.security_logs
  WHERE created_at < v_retention_cutoff;
  GET DIAGNOSTICS v_logs_deleted = ROW_COUNT;

  DELETE FROM public.admin_step_up_sessions
  WHERE expires_at < v_now - interval '1 day';
  GET DIAGNOSTICS v_stepup_deleted = ROW_COUNT;

  DELETE FROM public.admin_access_audit
  WHERE created_at < v_retention_cutoff;

  UPDATE public.attendance_records
  SET latitude = NULL,
      longitude = NULL,
      gps_accuracy_m = NULL
  WHERE created_at < v_retention_cutoff
    AND (latitude IS NOT NULL OR longitude IS NOT NULL OR gps_accuracy_m IS NOT NULL);
  GET DIAGNOSTICS v_gps_scrubbed = ROW_COUNT;

  RETURN jsonb_build_object(
    'ok', true,
    'expired_marked', v_expired_marked,
    'qr_deleted', v_qr_deleted,
    'rate_limits_deleted', v_rate_limits_deleted,
    'logs_deleted', v_logs_deleted,
    'stepup_deleted', v_stepup_deleted,
    'gps_scrubbed', v_gps_scrubbed
  );
END;
$$;

REVOKE ALL ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) TO service_role;
