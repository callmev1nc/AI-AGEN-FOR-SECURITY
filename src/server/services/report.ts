import React from "react";
import { renderToBuffer } from "@react-pdf/renderer";
import { SecurityReport } from "@/components/report/pdf-template";
import { createAdminClient } from "@/lib/supabase/admin";

export async function generatePdfReport(scanId: string, userId: string) {
  const admin = createAdminClient();

  const { data: scan, error } = await admin
    .from("scans")
    .select("*, vulnerabilities(*)")
    .eq("id", scanId)
    .eq("userId", userId)
    .single();

  if (error || !scan) throw new Error("Scan not found");
  if (scan.status !== "completed") throw new Error("Scan not completed");

  const vulnerabilities = scan.vulnerabilities.map((v: Record<string, unknown>) => ({
    severity: v.severity,
    category: v.category,
    title: v.title,
    description: v.description,
    evidence: v.evidence || undefined,
    remediation: v.remediation,
    affectedUrl: v.affectedUrl,
  }));

  const element = React.createElement(SecurityReport, {
    targetUrl: scan.targetUrl,
    scanLevel: scan.scanLevel,
    overallScore: scan.overallScore ?? 0,
    date: new Date().toLocaleDateString(),
    vulnerabilities,
  });

  const buffer = await renderToBuffer(element as never);

  const storagePath = `reports/${userId}/${scanId}-${Date.now()}.pdf`;

  const { data: report, error: reportError } = await admin
    .from("reports")
    .insert({
      scanId,
      userId,
      format: "pdf",
      storagePath,
    })
    .select()
    .single();

  if (reportError) throw new Error(reportError.message);

  return { report, buffer };
}
