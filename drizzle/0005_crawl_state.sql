ALTER TABLE "warden"."services" ADD COLUMN IF NOT EXISTS "crawl_state" text DEFAULT 'pending';
