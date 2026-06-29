-- SecureScan Scan Queue Migration
-- Adds heartbeatAt and attempts columns to the scans table for
-- durable background queue support.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'heartbeatAt') THEN
    ALTER TABLE "scans" ADD COLUMN "heartbeatAt" TIMESTAMPTZ;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'attempts') THEN
    ALTER TABLE "scans" ADD COLUMN "attempts" INTEGER NOT NULL DEFAULT 0;
  END IF;
END $$;
