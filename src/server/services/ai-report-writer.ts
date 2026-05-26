import { createAdminClient } from "@/lib/supabase/admin";
import { callClaude } from "@/lib/ai/client";
import { logger } from "@/lib/logger";

interface VulnerabilityInput {
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence: string | null;
  remediation: string;
  cvssScore: number | null;
  affectedUrl: string;
}

interface ScanInput {
  id: string;
  targetUrl: string;
  scanLevel: string;
  scanType: string;
  overallScore: number | null;
  vulnerabilities: VulnerabilityInput[];
}

export async function generateAiReport(scanId: string, userId: string) {
  const admin = createAdminClient();

  const { data: scan, error } = await admin
    .from("scans")
    .select("*, vulnerabilities(*)")
    .eq("id", scanId)
    .eq("userId", userId)
    .single();

  if (error || !scan) throw new Error("Scan not found");
  if (scan.status !== "completed") throw new Error("Scan not completed yet");

  const findingsText = scan.vulnerabilities.map((v: VulnerabilityInput, i: number) =>
    `[${i + 1}] ${v.severity.toUpperCase()}: ${v.title}
   Category: ${v.category}
   Description: ${v.description}
   Affected: ${v.affectedUrl}
   CVSS: ${v.cvssScore ?? "N/A"}
   Remediation: ${v.remediation}${v.evidence ? `\n   Evidence: ${v.evidence}` : ""}`
  ).join("\n\n");

  const systemPrompt = `You are a professional penetration test report writer. Generate a comprehensive security assessment report in markdown format.

Your report must include these sections:
1. **Executive Summary** — Brief overview of findings, risk level, and bottom line for management
2. **Methodology** — Describe the scanning approach and tools used
3. **Findings by Severity** — Group vulnerabilities by severity (critical, high, medium, low, info)
4. **OWASP/CWE Mapping** — Map each finding to relevant OWASP Top 10 (2021) and CWE categories
5. **Risk Assessment** — Overall risk score interpretation (0-100 scale)
6. **Prioritized Remediation Roadmap** — Actionable steps ordered by impact and effort

Write in a professional, clear tone suitable for both technical teams and management.`;

  const userPrompt = `Generate a pentest report for the following scan results:

Target: ${scan.targetUrl}
Scan Type: ${scan.scanType}
Scan Level: ${scan.scanLevel}
Overall Security Score: ${scan.overallScore ?? 0}/100

Findings (${scan.vulnerabilities.length} total):
${findingsText}

${scan.vulnerabilities.length === 0 ? "No vulnerabilities were found during this scan." : ""}`;

  logger.info("AiReportWriter", `Generating AI report for scan ${scanId} (${scan.vulnerabilities.length} findings)`);

  const reportMarkdown = await callClaude(
    [{ role: "user", content: userPrompt }],
    { system: systemPrompt, maxTokens: 8192 }
  );

  const storagePath = `reports/${userId}/${scanId}-ai-${Date.now()}.md`;

  const { error: uploadError } = await admin.storage
    .from("reports")
    .upload(storagePath, reportMarkdown, {
      contentType: "text/markdown",
      upsert: true,
    });

  if (uploadError) {
    throw new Error(`Failed to upload AI report: ${uploadError.message}`);
  }

  const { data: report, error: reportError } = await admin
    .from("reports")
    .insert({
      scanId,
      userId,
      format: "markdown",
      storagePath,
    })
    .select()
    .single();

  if (reportError) throw new Error(reportError.message);

  const { data: signedUrl } = await admin.storage
    .from("reports")
    .createSignedUrl(storagePath, 60 * 60);

  logger.info("AiReportWriter", `AI report generated for scan ${scanId}`);

  return { report, downloadUrl: signedUrl?.signedUrl || null, content: reportMarkdown };
}
