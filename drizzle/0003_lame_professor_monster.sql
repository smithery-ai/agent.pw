DROP INDEX "agentpw"."cred_profiles_host_idx";--> statement-breakpoint
DROP INDEX "agentpw"."credentials_host_idx";--> statement-breakpoint
DROP INDEX "agentpw"."credentials_profile_path_idx";--> statement-breakpoint
DROP INDEX "agentpw"."credentials_profile_path_path_idx";--> statement-breakpoint
ALTER TABLE "agentpw"."cred_profiles" ALTER COLUMN "auth" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "agentpw"."cred_profiles" ADD COLUMN "resource_patterns" jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" ADD COLUMN "resource" text NOT NULL;--> statement-breakpoint
CREATE INDEX "cred_profiles_resource_patterns_idx" ON "agentpw"."cred_profiles" USING gin ("resource_patterns");--> statement-breakpoint
CREATE INDEX "credentials_resource_idx" ON "agentpw"."credentials" USING btree ("resource");--> statement-breakpoint
ALTER TABLE "agentpw"."cred_profiles" DROP COLUMN "host";--> statement-breakpoint
ALTER TABLE "agentpw"."cred_profiles" DROP COLUMN "oauth_config";--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" DROP COLUMN "profile_path";--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" DROP COLUMN "host";