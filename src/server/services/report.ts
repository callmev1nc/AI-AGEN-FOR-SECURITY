import React from "react";
import { renderToBuffer } from "@react-pdf/renderer";
import { SecurityReport } from "@/components/report/pdf-template";
import { db } from "@/lib/db";

export async function generatePdfReport(scanId: string, userId: string) {
  const scan = await db.scan.findUnique({
    where: { id: scanId, userId },
    include: { vulnerabilities: true },
  });

  if (!scan) throw new Error("Scan not found");
  if (scan.status !== "completed") throw new Error("Scan not completed");

  const vulnerabilities = scan.vulnerabilities.map((v) => ({
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

  // TODO: Upload to Supabase Storage when configured
  // const supabase = createSupabaseClient();
  // await supabase.storage.from('reports').upload(storagePath, buffer, { contentType: 'application/pdf' });

  const report = await db.report.create({
    data: {
      scanId,
      userId,
      format: "pdf",
      storagePath,
    },
  });

  return { report, buffer };
}
