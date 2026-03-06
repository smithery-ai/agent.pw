ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_client_secret";--> statement-breakpoint
ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "encrypted_oauth_client_secret" "bytea";
