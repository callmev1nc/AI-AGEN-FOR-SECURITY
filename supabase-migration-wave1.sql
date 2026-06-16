-- SecureScan Wave 1 Migration
--
-- Run via the Supabase SQL editor (or `supabase db execute`). Statements are
-- written to be idempotent so re-running is safe.
--
-- IMPORTANT: `ALTER TYPE ... ADD VALUE` cannot execute inside a transaction
-- block (and therefore cannot be inside a DO $$ ... $$ block). Each ADD VALUE
-- below is a standalone statement. Run the whole file as-is; the SQL editor
-- runs each statement in its own implicit transaction.

-- ---------------------------------------------------------------------------
-- 1. ReportFormat enum
--    - 'markdown' fixes a latent bug: ai-report-writer.ts inserts format:'markdown'
--      but the enum only allowed ('pdf','json','html'), which throws on insert.
--    - 'sarif' and 'csv' enable the new export formats.
-- ---------------------------------------------------------------------------
ALTER TYPE "ReportFormat" ADD VALUE IF NOT EXISTS 'markdown';
ALTER TYPE "ReportFormat" ADD VALUE IF NOT EXISTS 'sarif';
ALTER TYPE "ReportFormat" ADD VALUE IF NOT EXISTS 'csv';

-- ---------------------------------------------------------------------------
-- 2. False-positive triage + dedup columns on vulnerabilities
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'vulnerabilities' AND column_name = 'triaged') THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "triaged" BOOLEAN NOT NULL DEFAULT false;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'vulnerabilities' AND column_name = 'triageConfidence') THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "triageConfidence" DOUBLE PRECISION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'vulnerabilities' AND column_name = 'triageReason') THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "triageReason" TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'vulnerabilities' AND column_name = 'findingHash') THEN
    ALTER TABLE "vulnerabilities" ADD COLUMN "findingHash" TEXT;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "vulnerabilities_findingHash_idx" ON "vulnerabilities" ("findingHash");

-- ---------------------------------------------------------------------------
-- 3. AI triage cache (service-role only). No RLS policy => denied for
--    anon/authenticated clients; the service role bypasses RLS.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "ai_triage_cache" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "findingHash" TEXT NOT NULL UNIQUE,
  "verdict" TEXT NOT NULL,
  "confidence" DOUBLE PRECISION NOT NULL,
  "reasoning" TEXT,
  "modelVersion" TEXT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE "ai_triage_cache" ENABLE ROW LEVEL SECURITY;
