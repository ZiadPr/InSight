CREATE TABLE "active_sessions" (
	"jti" text PRIMARY KEY,
	"user_id" text NOT NULL,
	"role" text NOT NULL,
	"aal" text NOT NULL,
	"ua_hash" text NOT NULL,
	"ip_hash" text NOT NULL,
	"created_at" text NOT NULL,
	"last_active_at" text NOT NULL,
	"idle_expires_at" text NOT NULL,
	"absolute_expires_at" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "attendance_records" (
	"id" text PRIMARY KEY,
	"employee_id" text NOT NULL,
	"attendance_date" text NOT NULL,
	"checked_in_at" text,
	"checked_out_at" text,
	"worked_minutes" integer,
	"late_minutes" integer DEFAULT 0 NOT NULL,
	"status" text NOT NULL,
	"qr_token_id" text UNIQUE,
	"idempotency_key" text,
	"distance_m" integer,
	"gps_meta_enc" text,
	"notes" text,
	"created_at" text NOT NULL,
	CONSTRAINT "attendance_records_status_check" CHECK (status IN ('present', 'late', 'excused'))
);
--> statement-breakpoint
CREATE TABLE "company_settings" (
	"id" text PRIMARY KEY,
	"company_name" text NOT NULL,
	"branch_name" text NOT NULL,
	"latitude" double precision NOT NULL,
	"longitude" double precision NOT NULL,
	"allowed_radius_m" integer NOT NULL,
	"max_gps_accuracy_m" integer NOT NULL,
	"qr_ttl_seconds" integer NOT NULL,
	"timezone" text NOT NULL,
	"work_start_time" text NOT NULL,
	"work_end_time" text NOT NULL,
	"late_grace_minutes" integer NOT NULL,
	"enforce_geofence" integer NOT NULL,
	"is_enabled" integer NOT NULL,
	"qr_schedule_enabled" integer DEFAULT 0 NOT NULL,
	"qr_window_start" text DEFAULT '07:30' NOT NULL,
	"qr_cutoff_time" text DEFAULT '11:00' NOT NULL,
	"qr_reappear_time" text DEFAULT '15:30' NOT NULL,
	"qr_window_end" text DEFAULT '19:00' NOT NULL,
	"updated_at" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kiosk_devices" (
	"id" text PRIMARY KEY,
	"device_name" text NOT NULL,
	"branch_name" text NOT NULL,
	"auth_user_id" text NOT NULL UNIQUE,
	"secret_hash" text NOT NULL,
	"is_active" integer DEFAULT 1 NOT NULL,
	"last_seen_at" text,
	"revoked_before" text,
	"created_at" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "qr_tokens" (
	"id" text PRIMARY KEY,
	"token_hash" text NOT NULL UNIQUE,
	"manual_code_hash" text,
	"kiosk_device_id" text NOT NULL,
	"issued_at" text NOT NULL,
	"expires_at" text NOT NULL,
	"consumed_at" text,
	"consumed_by" text,
	"consumed_action" text,
	"status" text NOT NULL,
	CONSTRAINT "qr_tokens_consumed_action_check" CHECK (consumed_action IN ('check_in', 'check_out') OR consumed_action IS NULL),
	CONSTRAINT "qr_tokens_status_check" CHECK (status IN ('active', 'consumed', 'expired', 'revoked'))
);
--> statement-breakpoint
CREATE TABLE "rbac_roles" (
	"role_key" text PRIMARY KEY,
	"label_ar" text NOT NULL,
	"label_en" text NOT NULL,
	"permissions_json" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "revoked_jtis" (
	"jti" text PRIMARY KEY,
	"exp_ms" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_alerts" (
	"id" text PRIMARY KEY,
	"severity" text NOT NULL,
	"event" text NOT NULL,
	"request_id" text,
	"ip_hash" text,
	"created_at" text NOT NULL,
	"details_json" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_logs" (
	"id" text PRIMARY KEY,
	"user_id" text,
	"event_type" text NOT NULL,
	"reason_code" text,
	"ip_hash" text,
	"created_at" text NOT NULL,
	"metadata_json" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_policy" (
	"id" integer PRIMARY KEY,
	"cloudflare_enabled" integer DEFAULT 0 NOT NULL,
	"trust_cf_headers" integer DEFAULT 0 NOT NULL,
	"allowed_countries_json" text DEFAULT '[]' NOT NULL,
	"max_cf_threat_score" integer DEFAULT 25 NOT NULL,
	"turnstile_enabled" integer DEFAULT 0 NOT NULL,
	"turnstile_site_key" text DEFAULT '' NOT NULL,
	"strict_ip_binding" integer DEFAULT 0 NOT NULL,
	"block_method_override" integer DEFAULT 1 NOT NULL,
	"enforce_json_content_type" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "security_policy_id_check" CHECK (id = 1)
);
--> statement-breakpoint
CREATE TABLE "system_secrets" (
	"key" text PRIMARY KEY,
	"value" text NOT NULL,
	"is_encrypted" integer DEFAULT 1 NOT NULL,
	"updated_at" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY,
	"email" text NOT NULL UNIQUE,
	"password_salt" text NOT NULL,
	"password_hash" text NOT NULL,
	"token_version" integer DEFAULT 1 NOT NULL,
	"full_name" text NOT NULL,
	"employee_number" text UNIQUE,
	"department" text,
	"job_title" text,
	"shift_start" text DEFAULT '09:00' NOT NULL,
	"shift_end" text DEFAULT '17:00' NOT NULL,
	"role" text NOT NULL,
	"admin_role_key" text,
	"permissions_json" text,
	"is_active" integer DEFAULT 1 NOT NULL,
	"mfa_enabled" integer DEFAULT 0 NOT NULL,
	"mfa_secret_enc" text,
	"last_used_totp_step" integer,
	"must_change_password" integer DEFAULT 0 NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL,
	CONSTRAINT "users_role_check" CHECK (role IN ('employee', 'kiosk', 'admin'))
);
--> statement-breakpoint
CREATE INDEX "idx_active_sessions_user" ON "active_sessions" ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_attendance_emp_date" ON "attendance_records" ("employee_id","attendance_date");--> statement-breakpoint
CREATE INDEX "idx_attendance_date" ON "attendance_records" ("attendance_date");--> statement-breakpoint
CREATE INDEX "idx_attendance_emp_idempotency" ON "attendance_records" ("employee_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "idx_qr_tokens_kiosk_status" ON "qr_tokens" ("kiosk_device_id","status");--> statement-breakpoint
CREATE INDEX "idx_qr_tokens_manual" ON "qr_tokens" ("manual_code_hash");--> statement-breakpoint
CREATE INDEX "idx_qr_tokens_issued" ON "qr_tokens" ("issued_at");--> statement-breakpoint
CREATE INDEX "idx_revoked_jtis_exp" ON "revoked_jtis" ("exp_ms");--> statement-breakpoint
CREATE INDEX "idx_security_alerts_created" ON "security_alerts" ("created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_security_logs_created" ON "security_logs" ("created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_security_logs_anomaly" ON "security_logs" ("event_type","ip_hash","created_at");--> statement-breakpoint
CREATE INDEX "idx_users_role_active" ON "users" ("role","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_users_email_lower" ON "users" (lower("email"));--> statement-breakpoint
ALTER TABLE "active_sessions" ADD CONSTRAINT "active_sessions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "attendance_records" ADD CONSTRAINT "attendance_records_employee_id_users_id_fkey" FOREIGN KEY ("employee_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "kiosk_devices" ADD CONSTRAINT "kiosk_devices_auth_user_id_users_id_fkey" FOREIGN KEY ("auth_user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "qr_tokens" ADD CONSTRAINT "qr_tokens_kiosk_device_id_kiosk_devices_id_fkey" FOREIGN KEY ("kiosk_device_id") REFERENCES "kiosk_devices"("id") ON DELETE CASCADE;