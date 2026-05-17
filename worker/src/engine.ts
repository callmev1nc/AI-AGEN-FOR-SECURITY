import { createClient } from "@supabase/supabase-js";
import type { ScanJobData } from "../../src/lib/queue";
import type { VulnerabilityResult, Severity } from "./scanners/types";

// Scanner module imports
import { scan as scanHeaders } from "./scanners/headers";
import { scan as scanSsl } from "./scanners/ssl";
import { scan as scanCookies } from "./scanners/cookies";
import { scan as scanInfoDisclosure } from "./scanners/info-disclosure";
import { scan as scanMixedContent } from "./scanners/mixed-content";
import { scan as scanCors } from "./scanners/cors";
import { scan as scanXss } from "./scanners/xss";
import { scan as scanPorts } from "./scanners/ports";
import { scan as scanXssAdvanced } from "./scanners/xss-advanced";
import { scan as scanCorsAdvanced } from "./scanners/cors-advanced";
import { scan as scanCookieAnalysis } from "./scanners/cookie-analysis";
import { scan as scanErrorFuzzing } from "./scanners/error-fuzzing";
import { scan as scanHeaderFuzzing } from "./scanners/header-fuzzing";

// ---------------------------------------------------------------------------
// Scanner module registry
// ---------------------------------------------------------------------------

interface ScannerEntry {
  name: string;
  scan: (targetUrl: string) => Promise<VulnerabilityResult[]>;
  level: "quick" | "standard" | "deep";
}

const SCANNER_MODULES: ScannerEntry[] = [
  // Quick level (5 modules)
  { name: "Security Headers", scan: scanHeaders, level: "quick" },
  { name: "SSL/TLS", scan: scanSsl, level: "quick" },
  { name: "Cookies", scan: scanCookies, level: "quick" },
  { name: "Information Disclosure", scan: scanInfoDisclosure, level: "quick" },
  { name: "Mixed Content", scan: scanMixedContent, level: "quick" },

  // Standard level (+2 modules)
  { name: "CORS", scan: scanCors, level: "standard" },
  { name: "XSS", scan: scanXss, level: "standard" },

  // Deep level (+6 modules)
  { name: "Port Scan", scan: scanPorts, level: "deep" },
  { name: "XSS Advanced", scan: scanXssAdvanced, level: "deep" },
  { name: "CORS Advanced", scan: scanCorsAdvanced, level: "deep" },
  { name: "Cookie Analysis", scan: scanCookieAnalysis, level: "deep" },
  { name: "Error Fuzzing", scan: scanErrorFuzzing, level: "deep" },
  { name: "Header Fuzzing", scan: scanHeaderFuzzing, level: "deep" },
];

// ---------------------------------------------------------------------------
// Score calculation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Supabase client
// ---------------------------------------------------------------------------

function getSupabaseClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error(
      "Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables"
    );
  }

  return createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

// ---------------------------------------------------------------------------
// Main scan engine
// ---------------------------------------------------------------------------

export async function runScan(job: { data: ScanJobData }): Promise<void> {
  const { scanId, targetUrl, scanLevel } = job.data;

  console.log(`[Engine] Starting scan ${scanId} for ${targetUrl} (level: ${scanLevel})`);

  const supabase = getSupabaseClient();

  // Mark scan as running
  await supabase
    .from("scans")
    .update({ status: "running", startedAt: new Date().toISOString() })
    .eq("id", scanId);

  // Select modules based on scan level
  const activeModules = SCANNER_MODULES.filter((m) => {
    if (scanLevel === "quick") return m.level === "quick";
    if (scanLevel === "standard") return m.level === "quick" || m.level === "standard";
    // deep = all modules
    return true;
  });

  console.log(
    `[Engine] Running ${activeModules.length} scanner modules: ${activeModules.map((m) => m.name).join(", ")}`
  );

  // Run modules sequentially
  const allFindings: VulnerabilityResult[] = [];

  for (const module of activeModules) {
    console.log(`[Engine] Running scanner: ${module.name}`);
    try {
      const findings = await module.scan(targetUrl);
      console.log(`[Engine] ${module.name}: found ${findings.length} issue(s)`);
      allFindings.push(...findings);
    } catch (error) {
      // A failing scanner should not crash the worker
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[Engine] Scanner "${module.name}" failed: ${message}`);
    }
  }

  // Calculate overall score
  const overallScore = calculateScore(allFindings);
  console.log(
    `[Engine] Scan ${scanId} complete. ${allFindings.length} findings. Score: ${overallScore}`
  );

  // Create vulnerability records
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

    // Insert in batches of 50 to avoid request size limits
    const batchSize = 50;
    for (let i = 0; i < vulnerabilityRecords.length; i += batchSize) {
      const batch = vulnerabilityRecords.slice(i, i + batchSize);
      const { error: insertError } = await supabase
        .from("vulnerabilities")
        .insert(batch);

      if (insertError) {
        console.error(
          `[Engine] Failed to insert vulnerability batch ${i / batchSize + 1}:`,
          insertError.message
        );
      }
    }
  }

  // Update scan record with final status and score
  const { error: updateError } = await supabase
    .from("scans")
    .update({
      status: "completed",
      overallScore,
      completedAt: new Date().toISOString(),
    })
    .eq("id", scanId);

  if (updateError) {
    console.error(`[Engine] Failed to update scan ${scanId}:`, updateError.message);
    throw updateError;
  }

  console.log(`[Engine] Scan ${scanId} saved successfully. Score: ${overallScore}`);
}
