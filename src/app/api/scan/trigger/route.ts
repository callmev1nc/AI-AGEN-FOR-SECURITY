import { after } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { runScanInline } from "@/lib/scan-runner";

export const maxDuration = 60;

export async function POST(req: Request) {
  try {
    const { scanId } = await req.json();

    if (!scanId || typeof scanId !== "string") {
      return Response.json({ error: "Missing scanId" }, { status: 400 });
    }

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceRoleKey) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }

    const supabase = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: scan, error } = await supabase
      .from("scans")
      .select("id, targetUrl, scanLevel")
      .eq("id", scanId)
      .single();

    if (error || !scan) {
      return Response.json({ error: "Scan not found" }, { status: 404 });
    }

    after(async () => {
      try {
        await runScanInline({
          scanId: scan.id,
          targetUrl: scan.targetUrl,
          scanLevel: scan.scanLevel,
        });
      } catch (err) {
        console.error(`[Trigger] Scan ${scanId} failed:`, err);
      }
    });

    return Response.json({ success: true, scanId });
  } catch (err) {
    console.error("[Trigger] Invalid request:", err);
    return Response.json({ error: "Invalid request" }, { status: 400 });
  }
}
