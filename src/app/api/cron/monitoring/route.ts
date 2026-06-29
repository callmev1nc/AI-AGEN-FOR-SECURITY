import { createAdminClient } from "@/lib/supabase/admin";
import { enqueueScan } from "@/lib/scan-queue";
import { logger } from "@/lib/logger";

export async function GET(req: Request) {
  const auth = req.headers.get("authorization");
  const expected = `Bearer ${process.env.CRON_SECRET}`;
  if (!auth || auth !== expected) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createAdminClient();

  // Pick due active assets
  const now = new Date().toISOString();
  const { data: assets } = await admin
    .from("monitored_assets")
    .select("id, userId, targetUrl, scanType, scanLevel")
    .eq("isActive", true)
    .lte("nextRunAt", now)
    .limit(50);

  if (!assets || assets.length === 0) {
    return Response.json({ processed: 0 });
  }

  let processed = 0;
  for (const asset of assets) {
    try {
      const { data: scan } = await admin
        .from("scans")
        .insert({
          userId: asset.userId,
          targetUrl: asset.targetUrl,
          scanType: asset.scanType,
          scanLevel: asset.scanLevel,
          status: "queued",
          assetId: asset.id,
        })
        .select("id")
        .single();

      if (scan) {
        await enqueueScan({
          scanId: scan.id,
          targetUrl: asset.targetUrl,
          scanLevel: asset.scanLevel,
          scanType: asset.scanType,
        });

        // Recompute next run (daily by default)
        const nextRun = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        await admin
          .from("monitored_assets")
          .update({ lastScanId: scan.id, nextRunAt: nextRun })
          .eq("id", asset.id);

        processed++;
      }
    } catch (err) {
      logger.error("CronMonitoring", `Failed to process asset ${asset.id}: ${err}`);
    }
  }

  return Response.json({ processed });
}
