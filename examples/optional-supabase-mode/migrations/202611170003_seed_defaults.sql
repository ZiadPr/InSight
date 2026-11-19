-- Migration 0003: Initial Campus Settings Template (DISABLED BY DEFAULT)
-- SECURITY: is_enabled starts as FALSE so the system NEVER operates with placeholder coordinates.
-- Update latitude, longitude, allowed_radius_m, campus_name, and timezone, then set is_enabled = TRUE.

INSERT INTO public.campus_settings (
  campus_name,
  latitude,
  longitude,
  allowed_radius_m,
  max_gps_accuracy_m,
  qr_ttl_seconds,
  timezone,
  is_enabled
)
SELECT
  'الجامعة — يرجى ضبط الإحداثيات قبل التفعيل',
  24.7136,
  46.6753,
  250,
  80,
  20,
  'Asia/Riyadh',
  FALSE
WHERE NOT EXISTS (SELECT 1 FROM public.campus_settings);

-- Example: Populate official study days via Supabase SQL Editor before exporting reports:
-- INSERT INTO public.study_calendar (study_date, is_study_day, notes)
-- SELECT d::date, EXTRACT(ISODOW FROM d) NOT IN (5, 6), 'Academic Term'
-- FROM generate_series('2026-09-01'::date, '2026-12-31'::date, '1 day') AS d
-- ON CONFLICT (study_date) DO NOTHING;
