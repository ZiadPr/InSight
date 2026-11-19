-- Migration 0006: Production Hardening — AAL2 MFA Guard, Immutable Audit Archive, & Session Registry
-- Addresses security audit P1/P2 requirements for InSight (ان سايت).

-- 1. Enforce AAL2 MFA helper at the PostgreSQL layer
CREATE OR REPLACE FUNCTION public.is_aal2_mfa()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE((auth.jwt() ->> 'aal') = 'aal2', FALSE);
$$;

REVOKE ALL ON FUNCTION public.is_aal2_mfa() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_aal2_mfa() TO authenticated, service_role;

-- 2. Restrict admin_access_audit reads strictly to own ledger + verified AAL2 MFA
DROP POLICY IF EXISTS "admin_access_audit_select_admin" ON public.admin_access_audit;
CREATE POLICY "admin_access_audit_select_admin"
  ON public.admin_access_audit
  FOR SELECT
  TO authenticated
  USING (
    public.is_admin()
    AND admin_user_id = auth.uid()
    AND public.is_aal2_mfa()
  );

-- 3. Immutable Audit Archive table (append-only retention before pruning)
CREATE TABLE IF NOT EXISTS public.security_audit_archive (
  archive_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_table TEXT NOT NULL CHECK (source_table IN ('security_logs', 'admin_access_audit')),
  original_id UUID NOT NULL,
  actor_user_id UUID,
  event_or_action TEXT NOT NULL,
  reason_or_target TEXT,
  ip_hash TEXT,
  original_created_at TIMESTAMPTZ NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE public.security_audit_archive ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.security_audit_archive FROM PUBLIC, anon, authenticated;

-- 4. Append-only immutability trigger preventing tampering on security_logs & admin_access_audit
CREATE OR REPLACE FUNCTION public.prevent_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('app.allow_audit_prune', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'Audit logs are append-only and cannot be modified or deleted directly';
END;
$$;

REVOKE ALL ON FUNCTION public.prevent_audit_mutation() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS trg_immutable_security_logs ON public.security_logs;
CREATE TRIGGER trg_immutable_security_logs
  BEFORE UPDATE OR DELETE ON public.security_logs
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_immutable_admin_audit ON public.admin_access_audit;
CREATE TRIGGER trg_immutable_admin_audit
  BEFORE UPDATE OR DELETE ON public.admin_access_audit
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_immutable_audit_archive ON public.security_audit_archive;
CREATE TRIGGER trg_immutable_audit_archive
  BEFORE UPDATE OR DELETE ON public.security_audit_archive
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_audit_mutation();

-- 5. Server-side Session Lifecycle Registry (idle timeout, absolute max age, revocation)
CREATE TABLE IF NOT EXISTS public.user_sessions (
  jti UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  aal TEXT NOT NULL DEFAULT 'aal1',
  ua_hash TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active
  ON public.user_sessions (user_id, revoked_at, absolute_expires_at DESC);

ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.user_sessions FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.revoke_user_sessions(p_user_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_count INTEGER := 0;
BEGIN
  IF auth.uid() IS NULL AND current_setting('role', true) <> 'service_role' THEN
    RAISE EXCEPTION 'Unauthorized session revocation';
  END IF;
  IF current_setting('role', true) <> 'service_role' AND NOT public.is_admin() AND auth.uid() <> p_user_id THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  UPDATE public.user_sessions
  SET revoked_at = now()
  WHERE user_id = p_user_id
    AND revoked_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;

  UPDATE public.profiles
  SET token_version = token_version + 1,
      updated_at = now()
  WHERE id = p_user_id;

  RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION public.revoke_user_sessions(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.revoke_user_sessions(UUID) TO authenticated, service_role;

-- 6. Upgrade cleanup function to archive aged audit entries before pruning
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
  v_logs_archived INTEGER := 0;
  v_admin_audit_archived INTEGER := 0;
  v_gps_scrubbed INTEGER := 0;
  v_stepup_deleted INTEGER := 0;
  v_sessions_deleted INTEGER := 0;
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

  DELETE FROM public.admin_step_up_sessions
  WHERE expires_at < v_now - interval '1 day';
  GET DIAGNOSTICS v_stepup_deleted = ROW_COUNT;

  DELETE FROM public.user_sessions
  WHERE absolute_expires_at < v_now - interval '1 day'
     OR (revoked_at IS NOT NULL AND revoked_at < v_now - interval '7 days');
  GET DIAGNOSTICS v_sessions_deleted = ROW_COUNT;

  -- Archive before pruning aged security logs & admin audit ledger
  INSERT INTO public.security_audit_archive (
    source_table, original_id, actor_user_id, event_or_action, reason_or_target, ip_hash, original_created_at, metadata
  )
  SELECT 'security_logs', id, user_id, event_type, reason_code, ip_hash, created_at, metadata
  FROM public.security_logs
  WHERE created_at < v_retention_cutoff;
  GET DIAGNOSTICS v_logs_archived = ROW_COUNT;

  INSERT INTO public.security_audit_archive (
    source_table, original_id, actor_user_id, event_or_action, reason_or_target, ip_hash, original_created_at, metadata
  )
  SELECT 'admin_access_audit', id, admin_user_id, action_name, target_resource, ip_hash, created_at, metadata
  FROM public.admin_access_audit
  WHERE created_at < v_retention_cutoff;
  GET DIAGNOSTICS v_admin_audit_archived = ROW_COUNT;

  PERFORM set_config('app.allow_audit_prune', 'on', true);

  DELETE FROM public.security_logs WHERE created_at < v_retention_cutoff;
  DELETE FROM public.admin_access_audit WHERE created_at < v_retention_cutoff;

  PERFORM set_config('app.allow_audit_prune', 'off', true);

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
    'logs_archived', v_logs_archived,
    'admin_audit_archived', v_admin_audit_archived,
    'stepup_deleted', v_stepup_deleted,
    'sessions_deleted', v_sessions_deleted,
    'gps_scrubbed', v_gps_scrubbed
  );
END;
$$;

REVOKE ALL ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_security_and_expired_data(INTEGER) TO service_role;
