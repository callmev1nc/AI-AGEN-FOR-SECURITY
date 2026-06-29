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
    const url = new URL(req.url);
    const format = url.searchParams.get("format") || "json";

    if (!["json", "sarif", "pdf"].includes(format)) {
      return Response.json({ error: "Invalid format. Use json, sarif, or pdf." }, { status: 400 });
    }

    const admin = createAdminClient();

    const { data: scan } = await admin
      .from("scans")
      .select("*, vulnerabilities(*)")
      .eq("id", id)
      .single();

    if (!scan) {
      return Response.json({ error: "Scan not found" }, { status: 404 });
    }

    // ownership check — the scans table has userId
    if ((scan as Record<string, unknown>).userId !== userId) {
      return Response.json({ error: "Scan not found" }, { status: 404 });
    }

    if (format === "json") {
      return Response.json({ scan });
    }

    if (format === "sarif") {
      const sarif = {
        version: "2.1.0",
        runs: [{
          tool: { driver: { name: "SecureScan", version: "1.0" } },
          results: (scan.vulnerabilities || []).map((v: { severity: string; title: string; description: string; affectedUrl: string; remediation: string }) => ({
            ruleId: v.title,
            level: v.severity === "critical" ? "error" : v.severity === "high" ? "warning" : "note",
            message: { text: v.description },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: v.affectedUrl },
              },
            }],
            fixes: v.remediation ? [{ description: { text: v.remediation } }] : undefined,
          })),
        }],
      };
      return Response.json(sarif);
    }

    return Response.json({ error: "PDF export not yet available via API" }, { status: 501 });
  } catch (err) {
    if (err instanceof ApiAuthError) {
      return Response.json({ error: err.message }, { status: err.statusCode });
    }
    logger.error("ApiV1", `GET /api/v1/scans/[id]/report failed: ${err}`);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
