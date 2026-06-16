-- SecureScan — Stripe webhook idempotency
--
-- Stripe may deliver the same event more than once (retries / duplicate
-- delivery). Recording processed event IDs lets the webhook handler skip
-- replays so customers are never charged / credited twice.
--
-- Service-role only: no RLS policy is defined, so anon/authenticated clients
-- are denied; the service role bypasses RLS (used by the webhook route).
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS "stripe_events" (
  "eventId" TEXT PRIMARY KEY,
  "type" TEXT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE "stripe_events" ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS "stripe_events_createdAt_idx"
  ON "stripe_events" ("createdAt");
