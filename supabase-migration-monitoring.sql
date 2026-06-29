-- SecureScan Monitoring + Alerts Migration

DO $$
BEGIN
  -- monitored_assets table
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'monitored_assets') THEN
    CREATE TABLE "monitored_assets" (
      "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      "userId" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
      "targetUrl" TEXT NOT NULL,
      "scanType" "ScanType" NOT NULL DEFAULT 'website',
      "scanLevel" "ScanLevel" NOT NULL DEFAULT 'standard',
      "cronExpr" TEXT NOT NULL DEFAULT '0 0 * * *',
      "lastScanId" UUID REFERENCES "scans"("id") ON DELETE SET NULL,
      "nextRunAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      "isActive" BOOLEAN NOT NULL DEFAULT true,
      "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE("userId", "targetUrl")
    );
    CREATE INDEX IF NOT EXISTS "monitored_assets_nextRunAt_idx" ON "monitored_assets"("nextRunAt") WHERE "isActive" = true;
    ALTER TABLE "monitored_assets" ENABLE ROW LEVEL SECURITY;
  END IF;

  -- alert_channels table
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alert_channels') THEN
    CREATE TABLE "alert_channels" (
      "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      "userId" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
      "type" TEXT NOT NULL CHECK ("type" IN ('email', 'slack', 'webhook')),
      "config" JSONB NOT NULL,
      "isActive" BOOLEAN NOT NULL DEFAULT true,
      "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE "alert_channels" ENABLE ROW LEVEL SECURITY;
  END IF;

  -- alert_events table
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alert_events') THEN
    CREATE TABLE "alert_events" (
      "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      "assetId" UUID NOT NULL REFERENCES "monitored_assets"("id") ON DELETE CASCADE,
      "scanId" UUID NOT NULL REFERENCES "scans"("id") ON DELETE CASCADE,
      "newCriticalCount" INTEGER NOT NULL DEFAULT 0,
      "delivered" BOOLEAN NOT NULL DEFAULT false,
      "channelId" UUID REFERENCES "alert_channels"("id"),
      "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE "alert_events" ENABLE ROW LEVEL SECURITY;
  END IF;

  -- Add assetId to scans (nullable)
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'assetId') THEN
    ALTER TABLE "scans" ADD COLUMN "assetId" UUID REFERENCES "monitored_assets"("id") ON DELETE SET NULL;
  END IF;
END $$;
