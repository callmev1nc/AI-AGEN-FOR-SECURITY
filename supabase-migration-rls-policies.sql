-- SecureScan RLS Policies (defense-in-depth)
--
-- monitored_assets, alert_channels, alert_events, and api_keys were created
-- with RLS ENABLED but no policies, which is deny-by-default for the anon /
-- authenticated keys (server access uses the service-role admin client, which
-- bypasses RLS). These explicit per-user policies ensure any future client-key
-- access path stays scoped to the owning user.
--
-- Idempotent: DROP IF EXISTS before CREATE so re-running is safe.

-- monitored_assets: owner-only CRUD
DROP POLICY IF EXISTS "monitored_assets_select_own" ON "monitored_assets";
CREATE POLICY "monitored_assets_select_own" ON "monitored_assets"
  FOR SELECT USING (auth.uid() = "userId");

DROP POLICY IF EXISTS "monitored_assets_insert_own" ON "monitored_assets";
CREATE POLICY "monitored_assets_insert_own" ON "monitored_assets"
  FOR INSERT WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "monitored_assets_update_own" ON "monitored_assets";
CREATE POLICY "monitored_assets_update_own" ON "monitored_assets"
  FOR UPDATE USING (auth.uid() = "userId") WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "monitored_assets_delete_own" ON "monitored_assets";
CREATE POLICY "monitored_assets_delete_own" ON "monitored_assets"
  FOR DELETE USING (auth.uid() = "userId");

-- alert_channels: owner-only CRUD
DROP POLICY IF EXISTS "alert_channels_select_own" ON "alert_channels";
CREATE POLICY "alert_channels_select_own" ON "alert_channels"
  FOR SELECT USING (auth.uid() = "userId");

DROP POLICY IF EXISTS "alert_channels_insert_own" ON "alert_channels";
CREATE POLICY "alert_channels_insert_own" ON "alert_channels"
  FOR INSERT WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "alert_channels_update_own" ON "alert_channels";
CREATE POLICY "alert_channels_update_own" ON "alert_channels"
  FOR UPDATE USING (auth.uid() = "userId") WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "alert_channels_delete_own" ON "alert_channels";
CREATE POLICY "alert_channels_delete_own" ON "alert_channels"
  FOR DELETE USING (auth.uid() = "userId");

-- alert_events: owner can read events for their own assets
DROP POLICY IF EXISTS "alert_events_select_own" ON "alert_events";
CREATE POLICY "alert_events_select_own" ON "alert_events"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM "monitored_assets"
      WHERE "monitored_assets"."id" = "alert_events"."assetId"
        AND "monitored_assets"."userId" = auth.uid()
    )
  );

-- api_keys: owner-only CRUD.
-- (keyHash is a one-way SHA-256 of the secret; it cannot be reversed to
-- recover the key, so exposing it via RLS is not a credential leak. The
-- plaintext key is returned only once at creation time, server-side.)
DROP POLICY IF EXISTS "api_keys_select_own" ON "api_keys";
CREATE POLICY "api_keys_select_own" ON "api_keys"
  FOR SELECT USING (auth.uid() = "userId");

DROP POLICY IF EXISTS "api_keys_insert_own" ON "api_keys";
CREATE POLICY "api_keys_insert_own" ON "api_keys"
  FOR INSERT WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "api_keys_update_own" ON "api_keys";
CREATE POLICY "api_keys_update_own" ON "api_keys"
  FOR UPDATE USING (auth.uid() = "userId") WITH CHECK (auth.uid() = "userId");

DROP POLICY IF EXISTS "api_keys_delete_own" ON "api_keys";
CREATE POLICY "api_keys_delete_own" ON "api_keys"
  FOR DELETE USING (auth.uid() = "userId");
