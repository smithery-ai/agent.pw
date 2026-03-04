-- Add auth_schemes column
ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "auth_schemes" text;--> statement-breakpoint

-- Backfill auth_schemes from existing columns
UPDATE "warden"."services"
SET "auth_schemes" = (
  CASE
    -- Service has OAuth URLs: build array with api key + oauth2 scheme
    WHEN "oauth_authorize_url" IS NOT NULL AND "oauth_token_url" IS NOT NULL THEN
      CASE
        WHEN "auth_method" = 'api_key' THEN
          json_build_array(
            json_build_object('type', 'apiKey', 'in', 'header', 'name', COALESCE("header_name", 'Authorization')),
            json_build_object('type', 'oauth2', 'authorizeUrl', "oauth_authorize_url", 'tokenUrl', "oauth_token_url", 'scopes', "oauth_scopes")
          )::text
        WHEN "auth_method" = 'basic' THEN
          json_build_array(
            json_build_object('type', 'http', 'scheme', 'basic'),
            json_build_object('type', 'oauth2', 'authorizeUrl', "oauth_authorize_url", 'tokenUrl', "oauth_token_url", 'scopes', "oauth_scopes")
          )::text
        ELSE
          json_build_array(
            json_build_object('type', 'http', 'scheme', 'bearer'),
            json_build_object('type', 'oauth2', 'authorizeUrl', "oauth_authorize_url", 'tokenUrl', "oauth_token_url", 'scopes', "oauth_scopes")
          )::text
      END
    -- No OAuth: single scheme based on auth_method
    WHEN "auth_method" = 'api_key' THEN
      json_build_array(
        json_build_object('type', 'apiKey', 'in', 'header', 'name', COALESCE("header_name", 'Authorization'))
      )::text
    WHEN "auth_method" = 'basic' THEN
      json_build_array(json_build_object('type', 'http', 'scheme', 'basic'))::text
    ELSE
      json_build_array(json_build_object('type', 'http', 'scheme', 'bearer'))::text
  END
)
WHERE "auth_schemes" IS NULL;--> statement-breakpoint

-- Drop old columns
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "auth_method";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "header_name";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "header_scheme";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_authorize_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_token_url";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "oauth_scopes";--> statement-breakpoint
ALTER TABLE "warden"."services" DROP COLUMN IF EXISTS "supported_auth_methods";
