ALTER TABLE "warden"."auth_flows" RENAME COLUMN "service" TO "slug";--> statement-breakpoint
ALTER TABLE "warden"."credentials" RENAME COLUMN "slug" TO "label";--> statement-breakpoint
ALTER TABLE "warden"."credentials" RENAME COLUMN "service" TO "slug";--> statement-breakpoint
ALTER TABLE "warden"."services" RENAME COLUMN "service" TO "slug";--> statement-breakpoint
ALTER TABLE "warden"."services" RENAME COLUMN "base_url" TO "allowed_hosts";--> statement-breakpoint
ALTER TABLE "warden"."credentials" DROP CONSTRAINT "credentials_org_id_service_slug_pk";--> statement-breakpoint
ALTER TABLE "warden"."credentials" ADD CONSTRAINT "credentials_org_id_slug_label_pk" PRIMARY KEY("org_id","slug","label");