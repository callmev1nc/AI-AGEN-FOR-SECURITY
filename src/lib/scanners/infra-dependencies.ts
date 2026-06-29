import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";
import { detectVulnerableDepsInFiles, CVE_PATTERNS, semverLt } from "./core/dependencies";

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const filesToCheck = ["package.json", "requirements.txt", "Gemfile", "Cargo.toml", "composer.json"];
  const files: Array<{ path: string; content: string }> = [];

  for (const fileName of filesToCheck) {
    const manifestUrl = targetUrl.replace(/\/?$/, "") + "/" + fileName;
    const content = await fetchUrl(manifestUrl);
    if (!content) continue;
    files.push({ path: fileName, content });
  }

  return detectVulnerableDepsInFiles(files);
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

export { CVE_PATTERNS, semverLt };
