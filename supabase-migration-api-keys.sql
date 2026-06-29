-- SecureScan API Keys Migration

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'api_keys') THEN
    CREATE TABLE "api_keys" (
      "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      "userId" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
      "name" TEXT NOT NULL,
      "keyHash" TEXT NOT NULL,
      "keyPrefix" TEXT NOT NULL,
      "lastUsedAt" TIMESTAMPTZ,
      "lastIp" TEXT,
      "revokedAt" TIMESTAMPTZ,
      "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS "api_keys_keyHash_idx" ON "api_keys"("keyHash");
    CREATE INDEX IF NOT EXISTS "api_keys_userId_idx" ON "api_keys"("userId");
    ALTER TABLE "api_keys" ENABLE ROW LEVEL SECURITY;
  END IF;
END $$;
