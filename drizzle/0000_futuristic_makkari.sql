CREATE TABLE "wdn_auth_flows" (
	"id" text PRIMARY KEY NOT NULL,
	"service" text NOT NULL,
	"method" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"code_verifier" text,
	"vault_slug" text,
	"warden_token" text,
	"identity" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"expires_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wdn_credentials" (
	"vault_slug" text NOT NULL,
	"service" text NOT NULL,
	"identity" text,
	"encrypted_credentials" "bytea" NOT NULL,
	"metadata" text,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "wdn_credentials_vault_slug_service_pk" PRIMARY KEY("vault_slug","service")
);
--> statement-breakpoint
CREATE TABLE "wdn_doc_pages" (
	"hostname" text NOT NULL,
	"path" text NOT NULL,
	"content" text,
	"status" text DEFAULT 'skeleton' NOT NULL,
	"generated_at" timestamp DEFAULT now() NOT NULL,
	"ttl_days" integer DEFAULT 7 NOT NULL,
	CONSTRAINT "wdn_doc_pages_hostname_path_pk" PRIMARY KEY("hostname","path")
);
--> statement-breakpoint
CREATE TABLE "wdn_revocations" (
	"revocation_id" text PRIMARY KEY NOT NULL,
	"revoked_at" timestamp DEFAULT now() NOT NULL,
	"reason" text
);
--> statement-breakpoint
CREATE TABLE "wdn_services" (
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
CREATE TABLE "wdn_vaults" (
	"slug" text PRIMARY KEY NOT NULL,
	"display_name" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
