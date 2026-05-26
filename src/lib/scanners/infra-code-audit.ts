import type { ScannerModule, VulnerabilityResult } from "./types";
import { analyzeBatchWithAi } from "@/server/services/code-analyzer";
import { logger } from "@/lib/logger";

const SOURCE_FILES = [
  "src/app/**/*.ts", "src/app/**/*.tsx", "src/lib/**/*.ts",
  "src/server/**/*.ts", "src/components/**/*.tsx",
  "index.js", "server.js", "app.js", "main.py",
  "src/**/*.js", "src/**/*.py", "src/**/*.go", "src/**/*.rb",
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  const filesToAudit: Array<{ path: string; content: string }> = [];

  for (const pattern of SOURCE_FILES) {
    const fileName = pattern.replace("**/", "");
    const fileUrl = `${targetUrl.replace(/\/?$/, "")}/${fileName}`;
    const content = await fetchUrl(fileUrl);
    if (!content) continue;

    filesToAudit.push({ path: fileName, content });
  }

  if (filesToAudit.length === 0) {
    logger.info("InfraCodeAudit", "No source files found to audit");
    return findings;
  }

  logger.info("InfraCodeAudit", `Auditing ${filesToAudit.length} files with AI`);

  const aiFindings = await analyzeBatchWithAi(filesToAudit);
  findings.push(...aiFindings);

  return findings;
};

async function fetchUrl(url: string): Promise<string | null> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (response.ok) return response.text();
  } catch {
    // not found
  }
  return null;
}
