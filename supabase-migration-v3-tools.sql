-- SecureScan Migration v3
-- Adds tool_results table for Security Tools section

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tool_type') THEN
    CREATE TYPE "tool_type" AS ENUM (
      'phishing-analyzer',
      'cve-explainer',
      'secrets-scanner',
      'firewall-rules',
      'password-auditor',
      'payload-generator',
      'headers-analyzer'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS "tool_results" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID NOT NULL REFERENCES "auth"."users"("id") ON DELETE CASCADE,
  "toolType" "tool_type" NOT NULL,
  "input" JSONB NOT NULL,
  "output" JSONB NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE "tool_results" ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'tool_results' AND policyname = 'Users can view own tool results'
  ) THEN
    CREATE POLICY "Users can view own tool results"
      ON "tool_results" FOR SELECT
      USING ("userId" = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'tool_results' AND policyname = 'Users can insert own tool results'
  ) THEN
    CREATE POLICY "Users can insert own tool results"
      ON "tool_results" FOR INSERT
      WITH CHECK ("userId" = auth.uid());
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tool_results_userId ON "tool_results" ("userId");
CREATE INDEX IF NOT EXISTS idx_tool_results_toolType ON "tool_results" ("toolType");
CREATE INDEX IF NOT EXISTS idx_tool_results_createdAt ON "tool_results" ("createdAt" DESC);
