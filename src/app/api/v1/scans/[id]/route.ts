import { createAdminClient } from "@/lib/supabase/admin";
import { authenticateApiKey, ApiAuthError } from "@/lib/api-auth";
import { logger } from "@/lib/logger";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { userId } = await authenticateApiKey(req);
    const { id } = await params;

    const admin = createAdminClient();

    const { data: scan, error } = await admin
      .from("scans")
      .select("id, userId, targetUrl, scanType, scanLevel, status, overallScore, createdAt, completedAt, errorMessage")
      .eq("id", id)
      .single();

    if (error || !scan) {
      return Response.json({ error: "Scan not found" }, { status: 404 });
    }

    // Ownership check
    if ((scan as unknown as Record<string, string>).userId !== userId) {
      return Response.json({ error: "Scan not found" }, { status: 404 });
    }

    return Response.json({ scan });
  } catch (err) {
    if (err instanceof ApiAuthError) {
      return Response.json({ error: err.message }, { status: err.statusCode });
    }
    logger.error("ApiV1", `GET /api/v1/scans/[id] failed: ${err}`);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
