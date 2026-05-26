import { createClient } from "@supabase/supabase-js";
import type { VulnerabilityResult, Severity, ScannerEntry } from "@/lib/scanners/types";
import { logger } from "@/lib/logger";

import { scan as scanHeaders } from "@/lib/scanners/headers";
import { scan as scanSsl } from "@/lib/scanners/ssl";
import { scan as scanCookies } from "@/lib/scanners/cookies";
import { scan as scanInfoDisclosure } from "@/lib/scanners/info-disclosure";
import { scan as scanMixedContent } from "@/lib/scanners/mixed-content";
import { scan as scanCors } from "@/lib/scanners/cors";
import { scan as scanXss } from "@/lib/scanners/xss";
import { scan as scanPorts } from "@/lib/scanners/ports";
import { scan as scanXssAdvanced } from "@/lib/scanners/xss-advanced";
import { scan as scanCorsAdvanced } from "@/lib/scanners/cors-advanced";
import { scan as scanCookieAnalysis } from "@/lib/scanners/cookie-analysis";
import { scan as scanErrorFuzzing } from "@/lib/scanners/error-fuzzing";
import { scan as scanHeaderFuzzing } from "@/lib/scanners/header-fuzzing";

const SCANNER_MODULES: ScannerEntry[] = [
  { name: "Security Headers", scan: scanHeaders, level: "quick", scanType: "website" },
  { name: "SSL/TLS", scan: scanSsl, level: "quick", scanType: "website" },
  { name: "Cookies", scan: scanCookies, level: "quick", scanType: "website" },
  { name: "Information Disclosure", scan: scanInfoDisclosure, level: "quick", scanType: "website" },
  { name: "Mixed Content", scan: scanMixedContent, level: "quick", scanType: "website" },
  { name: "CORS", scan: scanCors, level: "standard", scanType: "website" },
  { name: "XSS", scan: scanXss, level: "standard", scanType: "website" },
  { name: "Port Scan", scan: scanPorts, level: "deep", scanType: "website" },
  { name: "XSS Advanced", scan: scanXssAdvanced, level: "deep", scanType: "website" },
  { name: "CORS Advanced", scan: scanCorsAdvanced, level: "deep", scanType: "website" },
  { name: "Cookie Analysis", scan: scanCookieAnalysis, level: "deep", scanType: "website" },
  { name: "Error Fuzzing", scan: scanErrorFuzzing, level: "deep", scanType: "website" },
  { name: "Header Fuzzing", scan: scanHeaderFuzzing, level: "deep", scanType: "website" },
];

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function calculateScore(findings: VulnerabilityResult[]): number {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_DEDUCTIONS[finding.severity];
  }
  return Math.max(0, Math.min(100, score));
}

export function formatDuration(ms: number): string {
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
  scanType?: "website" | "api" | "infrastructure";
}): Promise<void> {
  const { scanId, targetUrl, scanLevel, scanType = "website" } = params;

  logger.info("ScanRunner", `Starting scan ${scanId} for ${targetUrl} (type: ${scanType}, level: ${scanLevel})`);

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
    if (m.scanType !== scanType) return false;
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
      logger.error("ScanRunner", `Failed to update progress: ${error.message}`);
    }
  }

  const results = await Promise.allSettled(
    activeModules.map(async (module) => {
      try {
        logger.info("ScanRunner", `Running scanner: ${module.name}`);
        const moduleStart = Date.now();
        const findings = await module.scan(targetUrl);
        const elapsed = Date.now() - moduleStart;
        logger.info("ScanRunner", `${module.name}: found ${findings.length} issue(s) in ${formatDuration(elapsed)}`);
        await updateProgress(module.name);
        return findings;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error("ScanRunner", `Scanner "${module.name}" failed: ${message}`);
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
  logger.info("ScanRunner", `Scan ${scanId} complete in ${formatDuration(totalElapsed)}. ${allFindings.length} findings. Score: ${overallScore}`);

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
      suggestedFix: f.suggestedFix ?? null,
      filePath: f.filePath ?? null,
      lineStart: f.lineStart ?? null,
      lineEnd: f.lineEnd ?? null,
    }));

    const batchSize = 50;
    for (let i = 0; i < vulnerabilityRecords.length; i += batchSize) {
      const batch = vulnerabilityRecords.slice(i, i + batchSize);
      const { error: insertError } = await supabase
        .from("vulnerabilities")
        .insert(batch);

      if (insertError) {
        logger.error("ScanRunner", `Failed to insert vulnerability batch ${Math.floor(i / batchSize) + 1}: ${insertError.message}`);
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
    logger.error("ScanRunner", `Failed to update scan ${scanId}: ${updateError.message}`);
    throw updateError;
  }

  logger.info("ScanRunner", `Scan ${scanId} saved successfully. Score: ${overallScore}`);
}
