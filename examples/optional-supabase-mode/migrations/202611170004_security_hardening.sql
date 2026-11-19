-- Migration 0004: High-Priority Security Hardening
-- 1. Default privileges lockdown for future tables/functions/sequences
-- 2. Strengthened profiles anti-escalation trigger
-- 3. Disable unconfigured placeholder campus coordinates
-- 4. Mandatory kiosk secret & remote session revocation support
-- 5. Automated retention cleanup function & optional pg_cron schedule

-- 1. Lock down default privileges for any future objects created in public schema
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;

-- 2. Disable default placeholder campus row if still using unmodified sample coordinates
UPDATE public.campus_settings
SET is_enabled = FALSE
WHERE latitude = 24.7136
  AND longitude = 46.6753
  AND campus_name LIKE '%الجامعة%';

-- 3. Strengthen profiles protection trigger (check actual current_user + JWT claim role)
CREATE OR REPLACE FUNCTION public.prevent_profile_privilege_escalation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_current_user TEXT := current_user;
  v_jwt_role TEXT := COALESCE(current_setting('request.jwt.claim.role', true), '');
BEGIN
  IF v_current_user NOT IN ('service_role', 'postgres', 'supabase_admin')
     OR (v_jwt_role <> '' AND v_jwt_role NOT IN ('service_role', 'postgres', 'supabase_admin')) THEN
    IF NEW.role IS DISTINCT FROM OLD.role
       OR NEW.is_active IS DISTINCT FROM OLD.is_active
       OR NEW.student_number IS DISTINCT FROM OLD.student_number
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'Protected profile fields cannot be modified from client context';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- 4. Kiosk remote session revocation support & mandatory secret enforcement
ALTER TABLE public.kiosk_devices
  ADD COLUMN IF NOT EXISTS revoked_before TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION public.revoke_kiosk_sessions(
  p_kiosk_device_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
BEGIN
  UPDATE public.kiosk_devices
  SET revoked_before = v_now
  WHERE id = p_kiosk_device_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'KIOSK_NOT_FOUND');
  END IF;

  UPDATE public.qr_tokens
  SET status = 'revoked'
  WHERE kiosk_device_id = p_kiosk_device_id
    AND status = 'active';

  INSERT INTO public.security_logs (event_type, reason_code, metadata)
  VALUES (
    'kiosk_session_revoked',
    'ADMIN_REVOKED',
    jsonb_build_object('kiosk_device_id', p_kiosk_device_id, 'revoked_before', v_now)
  );

  RETURN jsonb_build_object('ok', true, 'revoked_before', v_now);
END;
$$;

REVOKE ALL ON FUNCTION public.revoke_kiosk_sessions(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_kiosk_sessions(UUID) TO service_role;

-- Update issue_kiosk_qr_token to require secret_hash to be configured on kiosk_devices
CREATE OR REPLACE FUNCTION public.issue_kiosk_qr_token(
  p_kiosk_device_id UUID,
  p_token_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_device public.kiosk_devices%ROWTYPE;
  v_campus public.campus_settings%ROWTYPE;
  v_token_id UUID;
  v_expires_at TIMESTAMPTZ;
BEGIN
  SELECT * INTO v_device
  FROM public.kiosk_devices
  WHERE id = p_kiosk_device_id
  FOR UPDATE;

  IF NOT FOUND OR v_device.is_active IS NOT TRUE THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'KIOSK_INACTIVE');
  END IF;

  IF v_device.secret_hash IS NULL OR char_length(trim(v_device.secret_hash)) < 32 THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'DEVICE_SECRET_NOT_CONFIGURED');
  END IF;

  SELECT * INTO v_campus
  FROM public.campus_settings
  WHERE is_enabled = TRUE
  ORDER BY created_at ASC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'CAMPUS_DISABLED');
  END IF;

  UPDATE public.qr_tokens
  SET status = CASE WHEN expires_at <= v_now THEN 'expired' ELSE 'revoked' END
  WHERE kiosk_device_id = p_kiosk_device_id
    AND status = 'active';

  v_expires_at := v_now + make_interval(secs => COALESCE(v_campus.qr_ttl_seconds, 20));

  INSERT INTO public.qr_tokens (token_hash, kiosk_device_id, issued_at, expires_at, status)
  VALUES (p_token_hash, p_kiosk_device_id, v_now, v_expires_at, 'active')
  RETURNING id INTO v_token_id;

  UPDATE public.kiosk_devices
  SET last_seen_at = v_now
  WHERE id = p_kiosk_device_id;

  RETURN jsonb_build_object(
    'ok', true,
    'token_id', v_token_id,
    'issued_at', v_now,
    'expires_at', v_expires_at,
    'ttl_seconds', COALESCE(v_campus.qr_ttl_seconds, 20),
    'campus_name', v_campus.campus_name
  );
END;
$$;

REVOKE ALL ON FUNCTION public.issue_kiosk_qr_token(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_kiosk_qr_token(UUID, TEXT) TO service_role;

-- 5. Automated retention & cleanup function for expired QR tokens, rate_limits, security_logs, and old GPS coordinates
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
BEGIN
  -- Mark overdue active QR tokens as expired
  UPDATE public.qr_tokens
  SET status = 'expired'
  WHERE status = 'active'
    AND expires_at <= v_now;
  GET DIAGNOSTICS v_expired_marked = ROW_COUNT;

  -- Delete old unreferenced expired/revoked QR tokens
  DELETE FROM public.qr_tokens q
  WHERE q.status IN ('expired', 'revoked')
    AND q.created_at < v_qr_cutoff
    AND NOT EXISTS (
      SELECT 1 FROM public.attendance_records ar WHERE ar.qr_token_id = q.id
    );
  GET DIAGNOSTICS v_qr_deleted = ROW_COUNT;

  -- Clean stale rate-limit windows
  DELETE FROM public.rate_limits
  WHERE window_started_at < v_now - interval '1 day'
    AND (blocked_until IS NULL OR blocked_until < v_now);
  GET DIAGNOSTICS v_rate_limits_deleted = ROW_COUNT;

  -- Clean aged security logs beyond retention window
  DELETE FROM public.security_logs
  WHERE created_at < v_retention_cutoff;
  GET DIAGNOSTICS v_logs_deleted = ROW_COUNT;

  -- Scrub raw GPS coordinates from aged attendance records while keeping attendance status/date
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
    'gps_scrubbed', v_gps_scrubbed
  );
END;
$$;

REVOKE ALL ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) TO service_role;

-- Register nightly pg_cron cleanup if pg_cron extension is enabled in the Supabase project
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.unschedule('attendance_nightly_cleanup')
    WHERE EXISTS (
      SELECT 1 FROM cron.job WHERE jobname = 'attendance_nightly_cleanup'
    );

    PERFORM cron.schedule(
      'attendance_nightly_cleanup',
      '15 2 * * *',
      $cron$SELECT public.cleanup_security_and_expired_data(90);$cron$
    );
  END IF;
EXCEPTION
  WHEN OTHERS THEN
    -- Ignore if pg_cron schema privileges are not granted in current environment
    NULL;
END $$;
