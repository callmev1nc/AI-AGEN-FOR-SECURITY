import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";
import { detectDangerousPatternsInFiles, DANGEROUS_PATTERNS } from "./core/code-patterns";

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const filesToCheck = [
    "src/app/**/*.ts", "src/app/**/*.tsx", "src/lib/**/*.ts",
    "src/server/**/*.ts", "index.js", "server.js", "app.js",
    "src/**/*.js", "src/**/*.py", "lib/**/*.rb",
  ];
  const files: Array<{ path: string; content: string }> = [];

  for (const pattern of filesToCheck) {
    const fileName = pattern.replace("**/", "");
    const fileUrl = `${targetUrl.replace(/\/?$/, "")}/${fileName}`;
    const content = await fetchUrl(fileUrl);
    if (!content) continue;
    files.push({ path: fileName, content });
  }

  return detectDangerousPatternsInFiles(files);
};

async function fetchUrl(url: string): Promise<string | null> {
  const res = await scannerRequest(url, {
    method: "GET",
    followRedirects: true,
    timeoutMs: 10000,
  });
  if (!res) return null;
  if (res.statusCode >= 200 && res.statusCode < 300) return res.body;
  return null;
}

export { DANGEROUS_PATTERNS };
