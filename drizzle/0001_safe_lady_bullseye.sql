DROP INDEX "agentpw"."credentials_host_path_idx";--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" DROP CONSTRAINT "credentials_host_path_pk";--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" ALTER COLUMN "host" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" ADD CONSTRAINT "credentials_path_pk" PRIMARY KEY("path");--> statement-breakpoint
ALTER TABLE "agentpw"."credentials" ADD COLUMN "profile_path" text NOT NULL;--> statement-breakpoint
CREATE INDEX "credentials_profile_path_idx" ON "agentpw"."credentials" USING btree ("profile_path");--> statement-breakpoint
CREATE INDEX "credentials_profile_path_path_idx" ON "agentpw"."credentials" USING btree ("profile_path","path");