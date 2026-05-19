import { createClient } from "@supabase/supabase-js";
import type { VulnerabilityResult, Severity } from "../../worker/src/scanners/types";

import { scan as scanHeaders } from "../../worker/src/scanners/headers";
import { scan as scanSsl } from "../../worker/src/scanners/ssl";
import { scan as scanCookies } from "../../worker/src/scanners/cookies";
import { scan as scanInfoDisclosure } from "../../worker/src/scanners/info-disclosure";
import { scan as scanMixedContent } from "../../worker/src/scanners/mixed-content";
import { scan as scanCors } from "../../worker/src/scanners/cors";
import { scan as scanXss } from "../../worker/src/scanners/xss";
import { scan as scanPorts } from "../../worker/src/scanners/ports";
import { scan as scanXssAdvanced } from "../../worker/src/scanners/xss-advanced";
import { scan as scanCorsAdvanced } from "../../worker/src/scanners/cors-advanced";
import { scan as scanCookieAnalysis } from "../../worker/src/scanners/cookie-analysis";
import { scan as scanErrorFuzzing } from "../../worker/src/scanners/error-fuzzing";
import { scan as scanHeaderFuzzing } from "../../worker/src/scanners/header-fuzzing";

interface ScannerEntry {
  name: string;
  scan: (targetUrl: string) => Promise<VulnerabilityResult[]>;
  level: "quick" | "standard" | "deep";
}

const SCANNER_MODULES: ScannerEntry[] = [
  { name: "Security Headers", scan: scanHeaders, level: "quick" },
  { name: "SSL/TLS", scan: scanSsl, level: "quick" },
  { name: "Cookies", scan: scanCookies, level: "quick" },
  { name: "Information Disclosure", scan: scanInfoDisclosure, level: "quick" },
  { name: "Mixed Content", scan: scanMixedContent, level: "quick" },
  { name: "CORS", scan: scanCors, level: "standard" },
  { name: "XSS", scan: scanXss, level: "standard" },
  { name: "Port Scan", scan: scanPorts, level: "deep" },
  { name: "XSS Advanced", scan: scanXssAdvanced, level: "deep" },
  { name: "CORS Advanced", scan: scanCorsAdvanced, level: "deep" },
  { name: "Cookie Analysis", scan: scanCookieAnalysis, level: "deep" },
  { name: "Error Fuzzing", scan: scanErrorFuzzing, level: "deep" },
  { name: "Header Fuzzing", scan: scanHeaderFuzzing, level: "deep" },
];

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

function calculateScore(findings: VulnerabilityResult[]): number {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_DEDUCTIONS[finding.severity];
  }
  return Math.max(0, Math.min(100, score));
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${minutes}m ${secs}s`;
}

export async function runScanInline(params: {
  scanId: string;
  targetUrl: string;
  scanLevel: "quick" | "standard" | "deep";
}): Promise<void> {
  const { scanId, targetUrl, scanLevel } = params;

  console.log(`[ScanRunner] Starting scan ${scanId} for ${targetUrl} (level: ${scanLevel})`);

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error("Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const startedAt = Date.now();

  const activeModules = SCANNER_MODULES.filter((m) => {
    if (scanLevel === "quick") return m.level === "quick";
    if (scanLevel === "standard") return m.level === "quick" || m.level === "standard";
    return true;
  });

  const totalModules = activeModules.length;

  await supabase
    .from("scans")
    .update({
      status: "running",
      startedAt: new Date().toISOString(),
      progressPercent: 0,
      modulesCompleted: 0,
      totalModules,
      currentModule: "Initializing scanners...",
    })
    .eq("id", scanId);

  let completedCount = 0;

  async function updateProgress(moduleName: string, errorMsg?: string) {
    completedCount++;
    const percent = Math.round((completedCount / totalModules) * 100);
    const update: Record<string, unknown> = {
      progressPercent: percent,
      modulesCompleted: completedCount,
      totalModules,
      currentModule: percent < 100 ? moduleName : "Finalizing results...",
    };
    if (errorMsg) {
      update.errorMessage = errorMsg;
    }
    const { error } = await supabase.from("scans").update(update).eq("id", scanId);
    if (error) {
      console.error(`[ScanRunner] Failed to update progress: ${error.message}`);
    }
  }

  const results = await Promise.allSettled(
    activeModules.map(async (module) => {
      try {
        console.log(`[ScanRunner] Running scanner: ${module.name}`);
        const moduleStart = Date.now();
        const findings = await module.scan(targetUrl);
        const elapsed = Date.now() - moduleStart;
        console.log(`[ScanRunner] ${module.name}: found ${findings.length} issue(s) in ${formatDuration(elapsed)}`);
        await updateProgress(module.name);
        return findings;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[ScanRunner] Scanner "${module.name}" failed: ${message}`);
        await updateProgress(module.name, message);
        return [] as VulnerabilityResult[];
      }
    })
  );

  const allFindings: VulnerabilityResult[] = [];
  for (const result of results) {
    if (result.status === "fulfilled") {
      allFindings.push(...result.value);
    }
  }

  const overallScore = calculateScore(allFindings);
  const totalElapsed = Date.now() - startedAt;
  console.log(
    `[ScanRunner] Scan ${scanId} complete in ${formatDuration(totalElapsed)}. ${allFindings.length} findings. Score: ${overallScore}`
  );

  if (allFindings.length > 0) {
    const vulnerabilityRecords = allFindings.map((f) => ({
      scanId,
      severity: f.severity,
      category: f.category,
      title: f.title,
      description: f.description,
      evidence: f.evidence || null,
      remediation: f.remediation,
      cvssScore: f.cvssScore || null,
      affectedUrl: f.affectedUrl,
    }));

    const batchSize = 50;
    for (let i = 0; i < vulnerabilityRecords.length; i += batchSize) {
      const batch = vulnerabilityRecords.slice(i, i + batchSize);
      const { error: insertError } = await supabase
        .from("vulnerabilities")
        .insert(batch);

      if (insertError) {
        console.error(
          `[ScanRunner] Failed to insert vulnerability batch ${Math.floor(i / batchSize) + 1}:`,
          insertError.message
        );
      }
    }
  }

  const { error: updateError } = await supabase
    .from("scans")
    .update({
      status: "completed",
      overallScore,
      progressPercent: 100,
      currentModule: "Scan complete",
      completedAt: new Date().toISOString(),
    })
    .eq("id", scanId);

  if (updateError) {
    console.error(`[ScanRunner] Failed to update scan ${scanId}:`, updateError.message);
    throw updateError;
  }

  console.log(`[ScanRunner] Scan ${scanId} saved successfully. Score: ${overallScore}`);
}
