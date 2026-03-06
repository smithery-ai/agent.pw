-- Webhook registrations table
CREATE TABLE IF NOT EXISTS "warden"."webhook_registrations" (
  "id" text PRIMARY KEY,
  "org_id" text NOT NULL,
  "service" text NOT NULL,
  "callback_url" text NOT NULL,
  "encrypted_webhook_secret" bytea,
  "metadata" text,
  "created_at" timestamp NOT NULL DEFAULT now(),
  "updated_at" timestamp NOT NULL DEFAULT now()
);--> statement-breakpoint

-- Webhook config on services
ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "webhook_config" text;
