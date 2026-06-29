import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";
import { detectSecretsInFiles, SECRET_PATTERNS } from "./core/secrets";

const FILES_TO_SKIP = /node_modules|\.git\/|\.next\/|dist\/|build\/|\.cache\/|vendor\/|__pycache__|\.venv\//;

const REPO_FILES = [
  "package.json", ".env", ".env.production", ".env.local", ".env.example",
  "config.js", "config.ts", "config.json", "config.yaml", "config.yml",
  "settings.py", "settings.json", "credentials.json", "credentials.yml",
  "docker-compose.yml", "docker-compose.yaml", "secrets.yml", "secrets.yaml",
  "appsettings.json", "web.config", "application.properties",
  "src/**/*.ts", "src/**/*.js", "src/**/*.py", "src/**/*.go", "src/**/*.rb",
  "src/**/*.java", "src/**/*.php", "src/**/*.env*",
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const files: Array<{ path: string; content: string }> = [];

  for (const fileName of REPO_FILES) {
    if (FILES_TO_SKIP.test(fileName)) continue;

    const fileUrl = targetUrl.replace(/\/?$/, "") + "/" + fileName.replace("**/", "");
    const content = await fetchUrl(fileUrl);
    if (!content) continue;

    files.push({ path: fileName, content });
  }

  return detectSecretsInFiles(files);
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

export { SECRET_PATTERNS };
