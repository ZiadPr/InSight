-- Migration 0002: Strict Row Level Security (RLS) and Atomic RPC Functions

-- 1. Enable RLS on EVERY table in public schema
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.campus_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kiosk_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.study_calendar ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qr_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- 2. Revoke default broad privileges from anon and authenticated roles
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated;

-- Grant minimal read privileges only where RLS restricts rows cleanly
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT ON public.profiles TO authenticated;
GRANT SELECT ON public.attendance_records TO authenticated;
GRANT SELECT ON public.campus_settings TO authenticated;
GRANT SELECT ON public.study_calendar TO authenticated;
GRANT SELECT ON public.security_logs TO authenticated;

-- 3. Trusted admin check helper (uses active profile role or verified app_metadata)
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role = 'admin'
      AND p.is_active = TRUE
  );
$$;

REVOKE ALL ON FUNCTION public.is_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, service_role;

-- 4. RLS Policies

-- profiles: student reads own profile only; admin reads all profiles
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (id = auth.uid());

DROP POLICY IF EXISTS "profiles_select_admin" ON public.profiles;
CREATE POLICY "profiles_select_admin"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

-- attendance_records: student reads own records only; admin reads all records
-- NO INSERT / UPDATE / DELETE policies for authenticated or anon!
DROP POLICY IF EXISTS "attendance_select_own" ON public.attendance_records;
CREATE POLICY "attendance_select_own"
  ON public.attendance_records
  FOR SELECT
  TO authenticated
  USING (student_id = auth.uid());

DROP POLICY IF EXISTS "attendance_select_admin" ON public.attendance_records;
CREATE POLICY "attendance_select_admin"
  ON public.attendance_records
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

-- campus_settings: admin read-only via RLS (kiosk/student get safe values via Edge Functions)
DROP POLICY IF EXISTS "campus_settings_select_admin" ON public.campus_settings;
CREATE POLICY "campus_settings_select_admin"
  ON public.campus_settings
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

-- study_calendar: admin read-only via RLS
DROP POLICY IF EXISTS "study_calendar_select_admin" ON public.study_calendar;
CREATE POLICY "study_calendar_select_admin"
  ON public.study_calendar
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

-- security_logs: admin read-only via RLS
DROP POLICY IF EXISTS "security_logs_select_admin" ON public.security_logs;
CREATE POLICY "security_logs_select_admin"
  ON public.security_logs
  FOR SELECT
  TO authenticated
  USING (public.is_admin());

-- kiosk_devices, qr_tokens, rate_limits: zero policies for anon/authenticated (service_role only)

-- 5. Server-side Haversine distance function (returns distance in meters)
CREATE OR REPLACE FUNCTION public.haversine_distance_m(
  lat1 DOUBLE PRECISION,
  lon1 DOUBLE PRECISION,
  lat2 DOUBLE PRECISION,
  lon2 DOUBLE PRECISION
)
RETURNS DOUBLE PRECISION
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  r CONSTANT DOUBLE PRECISION := 6371000.0;
  dlat DOUBLE PRECISION := radians(lat2 - lat1);
  dlon DOUBLE PRECISION := radians(lon2 - lon1);
  a DOUBLE PRECISION;
  c DOUBLE PRECISION;
BEGIN
  a := sin(dlat / 2.0) ^ 2 + cos(radians(lat1)) * cos(radians(lat2)) * (sin(dlon / 2.0) ^ 2);
  c := 2.0 * atan2(sqrt(a), sqrt(GREATEST(0.0, 1.0 - a)));
  RETURN r * c;
END;
$$;

-- 6. Atomic rate limiting RPC (service_role only)
CREATE OR REPLACE FUNCTION public.check_rate_limit(
  p_key TEXT,
  p_max_attempts INTEGER,
  p_window_seconds INTEGER,
  p_block_seconds INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_row public.rate_limits%ROWTYPE;
BEGIN
  INSERT INTO public.rate_limits (key, attempts, window_started_at, blocked_until)
  VALUES (p_key, 0, v_now, NULL)
  ON CONFLICT (key) DO NOTHING;

  SELECT * INTO v_row
  FROM public.rate_limits
  WHERE key = p_key
  FOR UPDATE;

  IF v_row.blocked_until IS NOT NULL AND v_row.blocked_until > v_now THEN
    RETURN jsonb_build_object(
      'allowed', false,
      'retry_after_seconds', CEIL(EXTRACT(EPOCH FROM (v_row.blocked_until - v_now)))::INTEGER
    );
  END IF;

  IF v_row.window_started_at + make_interval(secs => p_window_seconds) <= v_now THEN
    UPDATE public.rate_limits
    SET attempts = 1,
        window_started_at = v_now,
        blocked_until = NULL
    WHERE key = p_key;

    RETURN jsonb_build_object('allowed', true, 'remaining', GREATEST(0, p_max_attempts - 1));
  END IF;

  IF v_row.attempts + 1 > p_max_attempts THEN
    UPDATE public.rate_limits
    SET attempts = v_row.attempts + 1,
        blocked_until = v_now + make_interval(secs => p_block_seconds)
    WHERE key = p_key;

    RETURN jsonb_build_object(
      'allowed', false,
      'retry_after_seconds', p_block_seconds
    );
  END IF;

  UPDATE public.rate_limits
  SET attempts = v_row.attempts + 1
  WHERE key = p_key;

  RETURN jsonb_build_object('allowed', true, 'remaining', GREATEST(0, p_max_attempts - (v_row.attempts + 1)));
END;
$$;

REVOKE ALL ON FUNCTION public.check_rate_limit(TEXT, INTEGER, INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.check_rate_limit(TEXT, INTEGER, INTEGER, INTEGER) TO service_role;

-- 7. Atomic Kiosk QR token issuance RPC (revokes previous active tokens, guarantees max 1 active)
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

  SELECT * INTO v_campus
  FROM public.campus_settings
  WHERE is_enabled = TRUE
  ORDER BY created_at ASC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'CAMPUS_DISABLED');
  END IF;

  -- Revoke any prior active tokens for this kiosk before issuing the next one
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

-- 8. Kiosk token status lookup RPC (no student PII exposed)
CREATE OR REPLACE FUNCTION public.get_kiosk_token_status(
  p_kiosk_device_id UUID,
  p_token_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_token public.qr_tokens%ROWTYPE;
  v_device public.kiosk_devices%ROWTYPE;
BEGIN
  SELECT * INTO v_device
  FROM public.kiosk_devices
  WHERE id = p_kiosk_device_id;

  IF NOT FOUND OR v_device.is_active IS NOT TRUE THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'KIOSK_INACTIVE');
  END IF;

  UPDATE public.kiosk_devices
  SET last_seen_at = v_now
  WHERE id = p_kiosk_device_id;

  SELECT * INTO v_token
  FROM public.qr_tokens
  WHERE id = p_token_id
    AND kiosk_device_id = p_kiosk_device_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error_code', 'TOKEN_NOT_FOUND');
  END IF;

  IF v_token.status = 'active' AND v_token.expires_at <= v_now THEN
    UPDATE public.qr_tokens
    SET status = 'expired'
    WHERE id = v_token.id;
    v_token.status := 'expired';
  END IF;

  RETURN jsonb_build_object(
    'ok', true,
    'status', v_token.status,
    'expires_at', v_token.expires_at,
    'consumed_at', v_token.consumed_at,
    'server_now', v_now
  );
END;
$$;

REVOKE ALL ON FUNCTION public.get_kiosk_token_status(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_kiosk_token_status(UUID, UUID) TO service_role;

-- 9. Atomic attendance check-in RPC (single transaction, row lock, daily uniqueness, GPS check)
CREATE OR REPLACE FUNCTION public.process_attendance_check_in(
  p_student_id UUID,
  p_token_hash TEXT,
  p_latitude DOUBLE PRECISION,
  p_longitude DOUBLE PRECISION,
  p_accuracy_m DOUBLE PRECISION,
  p_idempotency_key TEXT DEFAULT NULL,
  p_ip_hash TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_profile public.profiles%ROWTYPE;
  v_campus public.campus_settings%ROWTYPE;
  v_token public.qr_tokens%ROWTYPE;
  v_device public.kiosk_devices%ROWTYPE;
  v_attendance_date DATE;
  v_distance_m DOUBLE PRECISION;
  v_record_id UUID;
BEGIN
  -- Validate student account & role
  SELECT * INTO v_profile
  FROM public.profiles
  WHERE id = p_student_id;

  IF NOT FOUND OR v_profile.role <> 'student' OR v_profile.is_active IS NOT TRUE THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'ACCOUNT_INACTIVE_OR_INVALID', p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'ACCOUNT_UNAVAILABLE');
  END IF;

  -- Load active campus settings
  SELECT * INTO v_campus
  FROM public.campus_settings
  WHERE is_enabled = TRUE
  ORDER BY created_at ASC
  LIMIT 1;

  IF NOT FOUND THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'CAMPUS_DISABLED', p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'SERVICE_DISABLED');
  END IF;

  -- Server-authoritative date in university timezone
  v_attendance_date := (v_now AT TIME ZONE v_campus.timezone)::DATE;

  -- Lock matching QR token row to serialize concurrent scans
  SELECT * INTO v_token
  FROM public.qr_tokens
  WHERE token_hash = p_token_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'QR_UNKNOWN', p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'QR_INVALID');
  END IF;

  -- Verify associated Kiosk device is active
  SELECT * INTO v_device
  FROM public.kiosk_devices
  WHERE id = v_token.kiosk_device_id;

  IF NOT FOUND OR v_device.is_active IS NOT TRUE THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'KIOSK_INACTIVE', v_token.id, p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'QR_INVALID');
  END IF;

  -- Check QR status and expiration
  IF v_token.status <> 'active' THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'QR_NOT_ACTIVE_' || upper(v_token.status), v_token.id, p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'QR_INVALID');
  END IF;

  IF v_token.expires_at <= v_now THEN
    UPDATE public.qr_tokens
    SET status = 'expired'
    WHERE id = v_token.id;

    INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'QR_EXPIRED', v_token.id, p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'QR_EXPIRED');
  END IF;

  -- Check if student already checked in today (server date)
  IF EXISTS (
    SELECT 1
    FROM public.attendance_records
    WHERE student_id = p_student_id
      AND attendance_date = v_attendance_date
  ) THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'ALREADY_CHECKED_IN_TODAY', v_token.id, p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'ALREADY_CHECKED_IN');
  END IF;

  -- Validate GPS coordinates & accuracy strictly on server
  IF p_latitude IS NULL OR p_longitude IS NULL OR p_accuracy_m IS NULL
     OR p_latitude < -90 OR p_latitude > 90
     OR p_longitude < -180 OR p_longitude > 180
     OR p_accuracy_m <= 0 THEN
    INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
    VALUES (p_student_id, 'check_in_rejected', 'GPS_INVALID_COORDS', v_token.id, p_ip_hash);
    RETURN jsonb_build_object('ok', false, 'error_code', 'LOCATION_INVALID');
  END IF;

  IF p_accuracy_m > v_campus.max_gps_accuracy_m THEN
    INSERT INTO public.security_logs (
      user_id, event_type, reason_code, qr_token_id, ip_hash, metadata
    )
    VALUES (
      p_student_id,
      'check_in_rejected',
      'GPS_POOR_ACCURACY',
      v_token.id,
      p_ip_hash,
      jsonb_build_object('accuracy_m', round(p_accuracy_m::numeric, 2))
    );
    RETURN jsonb_build_object('ok', false, 'error_code', 'GPS_POOR_ACCURACY');
  END IF;

  v_distance_m := public.haversine_distance_m(
    p_latitude,
    p_longitude,
    v_campus.latitude,
    v_campus.longitude
  );

  IF v_distance_m > v_campus.allowed_radius_m THEN
    INSERT INTO public.security_logs (
      user_id, event_type, reason_code, qr_token_id, ip_hash, metadata
    )
    VALUES (
      p_student_id,
      'check_in_rejected',
      'OUTSIDE_CAMPUS_RADIUS',
      v_token.id,
      p_ip_hash,
      jsonb_build_object('distance_m', round(v_distance_m::numeric, 2))
    );
    RETURN jsonb_build_object('ok', false, 'error_code', 'OUTSIDE_CAMPUS');
  END IF;

  -- Atomic write: insert attendance record AND mark QR consumed
  BEGIN
    INSERT INTO public.attendance_records (
      student_id,
      attendance_date,
      checked_in_at,
      qr_token_id,
      latitude,
      longitude,
      gps_accuracy_m,
      status,
      idempotency_key
    )
    VALUES (
      p_student_id,
      v_attendance_date,
      v_now,
      v_token.id,
      p_latitude,
      p_longitude,
      p_accuracy_m,
      'present',
      p_idempotency_key
    )
    RETURNING id INTO v_record_id;
  EXCEPTION
    WHEN unique_violation THEN
      INSERT INTO public.security_logs (user_id, event_type, reason_code, qr_token_id, ip_hash)
      VALUES (p_student_id, 'check_in_rejected', 'UNIQUE_CONSTRAINT_CONFLICT', v_token.id, p_ip_hash);
      RETURN jsonb_build_object('ok', false, 'error_code', 'ALREADY_CHECKED_IN');
  END;

  UPDATE public.qr_tokens
  SET status = 'consumed',
      consumed_at = v_now,
      consumed_by = p_student_id
  WHERE id = v_token.id;

  INSERT INTO public.security_logs (
    user_id, event_type, reason_code, qr_token_id, ip_hash, metadata
  )
  VALUES (
    p_student_id,
    'check_in_succeeded',
    'OK',
    v_token.id,
    p_ip_hash,
    jsonb_build_object('attendance_date', v_attendance_date)
  );

  RETURN jsonb_build_object(
    'ok', true,
    'record_id', v_record_id,
    'attendance_date', v_attendance_date,
    'checked_in_at', v_now,
    'status', 'present'
  );
END;
$$;

REVOKE ALL ON FUNCTION public.process_attendance_check_in(UUID, TEXT, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.process_attendance_check_in(UUID, TEXT, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, TEXT, TEXT) TO service_role;
