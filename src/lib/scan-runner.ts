import { createClient } from "@supabase/supabase-js";
import { createHash } from "crypto";
import type { VulnerabilityResult, Severity, ScannerEntry } from "@/lib/scanners/types";
import { logger } from "@/lib/logger";
import pLimit from "p-limit";
import { runWithContext, initCache } from "@/lib/scanners/scan-context";

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
import { scan as scanPromptInjectionBasic } from "@/lib/scanners/prompt-injection-basic";
import { scan as scanPromptInjectionAdvanced } from "@/lib/scanners/prompt-injection-advanced";
import { scan as scanPromptInjectionContext } from "@/lib/scanners/prompt-injection-context";
import { scan as scanApiSqlInjection } from "@/lib/scanners/api-sql-injection";
import { scan as scanApiPathTraversal } from "@/lib/scanners/api-path-traversal";
import { scan as scanApiAuthBypass } from "@/lib/scanners/api-auth-bypass";
import { scan as scanInfraDependencies } from "@/lib/scanners/infra-dependencies";
import { scan as scanInfraSecrets } from "@/lib/scanners/infra-secrets";
import { scan as scanInfraCodePatterns } from "@/lib/scanners/infra-code-patterns";
import { scan as scanInfraCodeAudit } from "@/lib/scanners/infra-code-audit";

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
  { name: "Prompt Injection (Basic)", scan: scanPromptInjectionBasic, level: "quick", scanType: "api" },
  { name: "Prompt Injection (Advanced)", scan: scanPromptInjectionAdvanced, level: "standard", scanType: "api" },
  { name: "Prompt Injection (Context)", scan: scanPromptInjectionContext, level: "deep", scanType: "api" },
  { name: "SQL Injection (API)", scan: scanApiSqlInjection, level: "standard", scanType: "api" },
  { name: "Path Traversal (API)", scan: scanApiPathTraversal, level: "standard", scanType: "api" },
  { name: "Auth Bypass (API)", scan: scanApiAuthBypass, level: "deep", scanType: "api" },
  { name: "Dependency Scan", scan: scanInfraDependencies, level: "quick", scanType: "infrastructure" },
  { name: "Secrets Detection", scan: scanInfraSecrets, level: "quick", scanType: "infrastructure" },
  { name: "Code Patterns", scan: scanInfraCodePatterns, level: "standard", scanType: "infrastructure" },
  { name: "AI Code Audit", scan: scanInfraCodeAudit, level: "deep", scanType: "infrastructure" },
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

/**
 * De-duplicate findings produced across scanners. Conservative: only merges
 * EXACT duplicates (same category + affectedUrl + title), keeping the highest
 * severity. We deliberately do NOT merge across different parameters/paths —
 * those are distinct injection points and merging would hide real vulns.
 */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
export function dedupeFindings(findings: VulnerabilityResult[]): VulnerabilityResult[] {
  const map = new Map<string, VulnerabilityResult>();
  for (const finding of findings) {
    const key = `${finding.category}|${finding.affectedUrl}|${finding.title}`;
    const existing = map.get(key);
    if (
      !existing ||
      (SEVERITY_RANK[finding.severity] ?? 9) < (SEVERITY_RANK[existing.severity] ?? 9)
    ) {
      map.set(key, finding);
    }
  }
  return [...map.values()];
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
  const cache = initCache();

  const ctx = { scanId, level: scanLevel, type: scanType, targetUrl, cache };

  return runWithContext(ctx, async () => {
    // Heartbeat: a durable worker writes this periodically so a reclaim job can
    // detect scans stuck in "running" after a crash / forced redeploy.
    const heartbeat = setInterval(() => {
      void supabase
        .from("scans")
        .update({ heartbeatAt: new Date().toISOString() })
        .eq("id", scanId);
    }, 15_000);
    try {
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

      const concurrencyMap: Record<string, number> = { quick: 8, standard: 6, deep: 4 };
      const limit = pLimit(concurrencyMap[scanLevel] ?? 5);
      const results = await Promise.allSettled(
        activeModules.map((module) =>
          limit(async () => {
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
        )
      );

      const rawFindings: VulnerabilityResult[] = [];
      for (const result of results) {
        if (result.status === "fulfilled") {
          rawFindings.push(...result.value);
        }
      }

      const allFindings = dedupeFindings(rawFindings);
      if (rawFindings.length !== allFindings.length) {
        logger.info("ScanRunner", `Deduplicated ${rawFindings.length} -> ${allFindings.length} findings`);
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
          findingHash: createHash("sha256").update(`${f.category}|${f.affectedUrl}|${f.title}`).digest("hex"),
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
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error("ScanRunner", `Scan ${scanId} failed: ${message}`);
      await supabase.from("scans").update({ status: "failed", errorMessage: message }).eq("id", scanId);
    } finally {
      clearInterval(heartbeat);
    }
  });
}
