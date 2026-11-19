CREATE TABLE "rate_limits" (
	"key" text PRIMARY KEY,
	"attempts" integer NOT NULL,
	"window_start" bigint NOT NULL,
	"blocked_until" bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX "idx_rate_limits_window_start" ON "rate_limits" ("window_start");