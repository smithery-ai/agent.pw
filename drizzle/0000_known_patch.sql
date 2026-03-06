CREATE SCHEMA IF NOT EXISTS "agentpw";
--> statement-breakpoint
CREATE TABLE "agentpw"."auth_flows" (
	"id" text PRIMARY KEY NOT NULL,
	"slug" text NOT NULL,
	"method" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"code_verifier" text,
	"exec_policy" text,
	"token" text,
	"identity" text,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agentpw"."cred_profiles" (
	"slug" text PRIMARY KEY NOT NULL,
	"host" text NOT NULL,
	"auth" text,
	"managed_oauth" text,
	"display_name" text,
	"description" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agentpw"."credentials" (
	"id" text PRIMARY KEY NOT NULL,
	"host" text NOT NULL,
	"slug" text NOT NULL,
	"auth" text NOT NULL,
	"secret" "bytea" NOT NULL,
	"exec_policy" text,
	"admin_policy" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "credentials_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "agentpw"."revocations" (
	"revocation_id" text PRIMARY KEY NOT NULL,
	"revoked_at" timestamp DEFAULT now() NOT NULL,
	"reason" text
);
