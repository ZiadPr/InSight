-- Migration 0007: QR Capture Cutoff/Reappear Schedule, Cloudflare/WAF Policy, and DB-Backed Granular RBAC
-- Strictly enforces AAL2 + permission-scoped RLS with zero permissive boolean-true clauses.

ALTER TABLE public.company_settings
  ADD COLUMN IF NOT EXISTS qr_schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS qr_window_start TEXT NOT NULL DEFAULT '07:30' CHECK (qr_window_start ~ '^\d{2}:\d{2}$'),
  ADD COLUMN IF NOT EXISTS qr_cutoff_time TEXT NOT NULL DEFAULT '11:00' CHECK (qr_cutoff_time ~ '^\d{2}:\d{2}$'),
  ADD COLUMN IF NOT EXISTS qr_reappear_time TEXT NOT NULL DEFAULT '15:30' CHECK (qr_reappear_time ~ '^\d{2}:\d{2}$'),
  ADD COLUMN IF NOT EXISTS qr_window_end TEXT NOT NULL DEFAULT '19:00' CHECK (qr_window_end ~ '^\d{2}:\d{2}$'),
  ADD COLUMN IF NOT EXISTS cloudflare_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS trust_cf_headers BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS allowed_countries TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS max_cf_threat_score INTEGER NOT NULL DEFAULT 25 CHECK (max_cf_threat_score BETWEEN 1 AND 100),
  ADD COLUMN IF NOT EXISTS turnstile_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS turnstile_site_key TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS strict_ip_binding BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS block_method_override BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS enforce_json_content_type BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS public.rbac_roles (
  role_key TEXT PRIMARY KEY,
  label_ar TEXT NOT NULL,
  label_en TEXT NOT NULL,
  permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.user_permissions (
  user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  admin_role_key TEXT REFERENCES public.rbac_roles(role_key) ON DELETE SET NULL,
  custom_permissions TEXT[] DEFAULT NULL,
  updated_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.rbac_roles (role_key, label_ar, label_en, permissions)
VALUES
  (
    'super_admin',
    'مدير النظام الأعلى',
    'Super Administrator',
    ARRAY[
      'view_overview',
      'view_records',
      'export_reports',
      'manage_excuses',
      'manage_employees',
      'manage_kiosks',
      'manage_settings',
      'manage_security',
      'manage_permissions'
    ]
  ),
  (
    'hr_manager',
    'مدير الموارد البشرية',
    'HR Manager',
    ARRAY[
      'view_overview',
      'view_records',
      'export_reports',
      'manage_excuses',
      'manage_employees',
      'manage_kiosks',
      'manage_settings'
    ]
  ),
  (
    'attendance_supervisor',
    'مشرف الحضور والانصراف',
    'Attendance Supervisor',
    ARRAY['view_overview', 'view_records', 'export_reports', 'manage_excuses']
  ),
  (
    'security_auditor',
    'مدقق الأمن السيبراني',
    'Security Auditor',
    ARRAY['view_overview', 'manage_security', 'manage_kiosks']
  )
ON CONFLICT (role_key) DO NOTHING;

CREATE OR REPLACE FUNCTION public.has_hr_permission(required_permission TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  caller_role TEXT;
  caller_active BOOLEAN;
  assigned_role_key TEXT;
  custom_perms TEXT[];
  role_perms TEXT[];
BEGIN
  SELECT role, is_active INTO caller_role, caller_active
  FROM public.profiles
  WHERE id = auth.uid();

  IF caller_role IS DISTINCT FROM 'admin' OR caller_active IS NOT TRUE THEN
    RETURN FALSE;
  END IF;

  SELECT admin_role_key, custom_permissions
  INTO assigned_role_key, custom_perms
  FROM public.user_permissions
  WHERE user_id = auth.uid();

  IF custom_perms IS NOT NULL AND array_length(custom_perms, 1) > 0 THEN
    RETURN required_permission = ANY(custom_perms);
  END IF;

  SELECT permissions INTO role_perms
  FROM public.rbac_roles
  WHERE role_key = COALESCE(assigned_role_key, 'super_admin');

  IF role_perms IS NULL THEN
    RETURN COALESCE(assigned_role_key, 'super_admin') = 'super_admin';
  END IF;

  RETURN required_permission = ANY(role_perms);
END;
$$;

CREATE OR REPLACE FUNCTION public.is_within_qr_capture_window(check_ts TIMESTAMPTZ DEFAULT NOW())
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  cfg RECORD;
  local_time TIME;
BEGIN
  SELECT
    qr_schedule_enabled,
    timezone,
    qr_window_start::TIME AS win_start,
    qr_cutoff_time::TIME AS win_cutoff,
    qr_reappear_time::TIME AS win_reappear,
    qr_window_end::TIME AS win_end
  INTO cfg
  FROM public.company_settings
  LIMIT 1;

  IF cfg IS NULL OR cfg.qr_schedule_enabled IS NOT TRUE THEN
    RETURN TRUE;
  END IF;

  local_time := (check_ts AT TIME ZONE COALESCE(cfg.timezone, 'Asia/Riyadh'))::TIME;
  RETURN (local_time BETWEEN cfg.win_start AND cfg.win_cutoff)
      OR (local_time BETWEEN cfg.win_reappear AND cfg.win_end);
END;
$$;

ALTER TABLE public.rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_permissions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.rbac_roles FROM PUBLIC, anon;
REVOKE ALL ON TABLE public.user_permissions FROM PUBLIC, anon;

CREATE POLICY rbac_roles_select_admin ON public.rbac_roles
  FOR SELECT TO authenticated
  USING (public.is_aal2_mfa() AND public.has_hr_permission('view_overview'));

CREATE POLICY rbac_roles_manage_admin ON public.rbac_roles
  FOR ALL TO authenticated
  USING (public.is_aal2_mfa() AND public.has_hr_permission('manage_permissions'))
  WITH CHECK (public.is_aal2_mfa() AND public.has_hr_permission('manage_permissions'));

CREATE POLICY user_permissions_select_self_or_admin ON public.user_permissions
  FOR SELECT TO authenticated
  USING (
    user_id = auth.uid()
    OR (public.is_aal2_mfa() AND public.has_hr_permission('manage_permissions'))
  );

CREATE POLICY user_permissions_manage_admin ON public.user_permissions
  FOR ALL TO authenticated
  USING (public.is_aal2_mfa() AND public.has_hr_permission('manage_permissions'))
  WITH CHECK (public.is_aal2_mfa() AND public.has_hr_permission('manage_permissions'));
