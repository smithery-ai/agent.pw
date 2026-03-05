CREATE TABLE "warden"."auth_flows" (
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
DROP TABLE "warden"."doc_pages" CASCADE;--> statement-breakpoint
ALTER TABLE "warden"."services" ADD COLUMN "auth_schemes" text;--> statement-breakpoint
ALTER TABLE "warden"."services" ADD COLUMN "encrypted_oauth_client_secret" "bytea";--> statement-breakpoint
ALTER TABLE "warden"."credentials" DROP COLUMN "tags";--> statement-breakpoint
ALTER TABLE "warden"."credentials" DROP COLUMN "expires_at";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "auth_method";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "header_name";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "header_scheme";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "oauth_client_secret";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "oauth_authorize_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "oauth_token_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "oauth_scopes";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "supported_auth_methods";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "api_type";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN "preview";