CREATE TABLE "warden"."oauth_apps" (
  "org_id" text NOT NULL,
  "service" text NOT NULL,
  "client_id" text NOT NULL,
  "encrypted_client_secret" "bytea",
  "scopes" text,
  "created_at" timestamp DEFAULT now() NOT NULL,
  CONSTRAINT "oauth_apps_org_id_service_pk" PRIMARY KEY("org_id","service")
);
