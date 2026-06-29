import { after } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { runScanInline } from "@/lib/scan-runner";
import { checkRateLimit } from "@/lib/rate-limit";
import { resolveAndAssertPublic } from "@/lib/safe-fetch";
import { authenticateApiKey, ApiAuthError } from "@/lib/api-auth";
import { logger } from "@/lib/logger";

export async function POST(req: Request) {
  try {
    const { userId } = await authenticateApiKey(req);

    let body: { targetUrl?: string; scanType?: string; scanLevel?: string };
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid request body" }, { status: 400 });
    }

    if (!body.targetUrl || typeof body.targetUrl !== "string") {
      return Response.json({ error: "Missing targetUrl" }, { status: 400 });
    }

    // SSRF guard (C1): validate target is public before creating scan
    try {
      const parsed = new URL(body.targetUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return Response.json({ error: "Only http/https targets are allowed" }, { status: 400 });
      }
      await resolveAndAssertPublic(parsed.hostname);
    } catch {
      return Response.json({ error: "Target resolves to a private or invalid address" }, { status: 400 });
    }

    // Rate limit (C2): separate API bucket so CI/CD doesn't starve dashboard
    const rateLimit = await checkRateLimit(`api:${userId}`, "pro");
    if (!rateLimit.success) {
      return Response.json({ error: "Rate limit exceeded" }, { status: 429 });
    }

    const admin = createAdminClient();

    const { data: scan, error } = await admin
      .from("scans")
      .insert({
        userId,
        targetUrl: body.targetUrl,
        scanType: body.scanType || "website",
        scanLevel: body.scanLevel || "standard",
        status: "queued",
      })
      .select("id, targetUrl, scanLevel, scanType")
      .single();

    if (error || !scan) {
      return Response.json({ error: "Failed to create scan" }, { status: 500 });
    }

    const scanLevel = scan.scanLevel as "quick" | "standard" | "deep";

    after(async () => {
      try {
        await runScanInline({
          scanId: scan.id,
          targetUrl: scan.targetUrl,
          scanLevel,
          scanType: scan.scanType as "website" | "api" | "infrastructure",
        });
      } catch (err) {
        logger.error("ApiV1", `Scan ${scan.id} failed: ${err}`);
      }
    });

    return Response.json({ success: true, scanId: scan.id }, { status: 201 });
  } catch (err) {
    if (err instanceof ApiAuthError) {
      return Response.json({ error: err.message }, { status: err.statusCode });
    }
    logger.error("ApiV1", `POST /api/v1/scans failed: ${err}`);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
