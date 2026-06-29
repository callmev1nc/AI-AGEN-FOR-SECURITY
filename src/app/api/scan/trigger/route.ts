import { after } from "next/server";
import { createClient as createSupabaseServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { runScanInline } from "@/lib/scan-runner";
import { checkRateLimit } from "@/lib/rate-limit";
import { logger } from "@/lib/logger";
import { enqueueScan, isEnabled as queueEnabled } from "@/lib/scan-queue";

export const maxDuration = 300;

export async function POST(req: Request) {
  let scanId: unknown;
  try {
    ({ scanId } = await req.json());
  } catch {
    return Response.json({ error: "Invalid request body" }, { status: 400 });
  }

  if (!scanId || typeof scanId !== "string") {
    return Response.json({ error: "Missing scanId" }, { status: 400 });
  }

  // Authenticate the caller from their session cookies.
  const supabase = await createSupabaseServerClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createAdminClient();

  // Ownership + status check: only the owning user may trigger a scan, and
  // only a scan that is still "queued" will be started. Re-POSTing a running /
  // completed / failed scan is a safe no-op (idempotency), which also matches
  // how the scan detail page calls this on mount.
  const { data: scan, error } = await admin
    .from("scans")
    .select("id, targetUrl, scanLevel, scanType, status, userId")
    .eq("id", scanId)
    .eq("userId", user.id)
    .single();

  if (error || !scan) {
    return Response.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status !== "queued") {
    return Response.json({ success: true, scanId, skipped: true });
  }

  // Rate-limit triggers per user (cheap abuse / compute-exhaustion guard).
  const { data: userProfile } = await admin
    .from("users")
    .select("plan")
    .eq("id", user.id)
    .single();
  const plan = (userProfile?.plan as string) || "free";
  const rateLimit = await checkRateLimit(`trigger:${user.id}`, plan);
  if (!rateLimit.success) {
    return Response.json(
      { error: "Too many scan triggers. Please wait and try again." },
      { status: 429 }
    );
  }

  const isDeep = scan.scanLevel === "deep";

  // Deep scans route to the background queue (when enabled); quick/standard
  // run inline via Vercel's after().
  if (isDeep && queueEnabled) {
    after(async () => {
      try {
        await enqueueScan({
          scanId: scan.id,
          targetUrl: scan.targetUrl,
          scanLevel: scan.scanLevel,
          scanType: scan.scanType,
        });
      } catch (err) {
        logger.error("Trigger", `Failed to enqueue scan ${scanId}: ${err}`);
      }
    });
  } else {
    after(async () => {
      try {
        await runScanInline({
          scanId: scan.id,
          targetUrl: scan.targetUrl,
          scanLevel: scan.scanLevel,
          scanType: scan.scanType,
        });
      } catch (err) {
        logger.error("Trigger", `Scan ${scanId} failed: ${err}`);
      }
    });
  }

  return Response.json({ success: true, scanId });
}
