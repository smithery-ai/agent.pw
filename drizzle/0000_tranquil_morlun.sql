CREATE SCHEMA IF NOT EXISTS "warden";
--> statement-breakpoint
DROP TABLE IF EXISTS "warden"."auth_flows";
--> statement-breakpoint
DROP TABLE IF EXISTS "warden"."vaults";
--> statement-breakpoint
DROP TABLE IF EXISTS "warden"."credentials";
--> statement-breakpoint
CREATE TABLE "warden"."credentials" (
	"org_id" text NOT NULL,
	"service" text NOT NULL,
	"slug" text DEFAULT 'default' NOT NULL,
	"encrypted_credentials" "bytea" NOT NULL,
	"tags" jsonb,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "credentials_org_id_service_slug_pk" PRIMARY KEY("org_id","service","slug")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warden"."doc_pages" (
	"hostname" text NOT NULL,
	"path" text NOT NULL,
	"content" text,
	"status" text DEFAULT 'skeleton' NOT NULL,
	"generated_at" timestamp DEFAULT now() NOT NULL,
	"ttl_days" integer DEFAULT 7 NOT NULL,
	CONSTRAINT "doc_pages_hostname_path_pk" PRIMARY KEY("hostname","path")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warden"."revocations" (
	"revocation_id" text PRIMARY KEY NOT NULL,
	"revoked_at" timestamp DEFAULT now() NOT NULL,
	"reason" text
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warden"."services" (
	"service" text PRIMARY KEY NOT NULL,
	"base_url" text NOT NULL,
	"display_name" text,
	"description" text,
	"auth_method" text DEFAULT 'bearer' NOT NULL,
	"header_name" text DEFAULT 'Authorization' NOT NULL,
	"header_scheme" text DEFAULT 'Bearer' NOT NULL,
	"oauth_client_id" text,
	"oauth_client_secret" text,
	"oauth_authorize_url" text,
	"oauth_token_url" text,
	"oauth_scopes" text,
	"supported_auth_methods" text,
	"api_type" text,
	"docs_url" text,
	"preview" text,
	"auth_config" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warden"."users" (
	"workos_user_id" text PRIMARY KEY NOT NULL,
	"workos_org_id" text NOT NULL,
	"email" text,
	"name" text,
	"created_at" timestamp DEFAULT now() NOT NULL
);
