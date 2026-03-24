DROP INDEX "agentpw"."credentials_resource_idx";--> statement-breakpoint
CREATE INDEX "credentials_path_idx" ON "agentpw"."credentials" USING btree ("path");--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" DROP COLUMN "resource";