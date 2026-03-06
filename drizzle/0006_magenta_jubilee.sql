CREATE TABLE IF NOT EXISTS "warden"."auth_flows" (
	"id" text PRIMARY KEY NOT NULL,
	"service" text NOT NULL,
	"method" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"code_verifier" text,
	"org_id" text,
	"token" text,
	"identity" text,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
DROP TABLE IF EXISTS "warden"."doc_pages" CASCADE;--> statement-breakpoint
ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "auth_schemes" text;--> statement-breakpoint
ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "encrypted_oauth_client_secret" "bytea";--> statement-breakpoint
ALTER TABLE "warden"."credentials" DROP COLUMN IF EXISTS "tags";--> statement-breakpoint
ALTER TABLE "warden"."credentials" DROP COLUMN IF EXISTS "expires_at";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "auth_method";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "header_name";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "header_scheme";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_client_secret";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_authorize_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_token_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_scopes";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "supported_auth_methods";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "api_type";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "preview";