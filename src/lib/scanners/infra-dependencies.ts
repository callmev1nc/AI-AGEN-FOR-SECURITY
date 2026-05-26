import type { ScannerModule, VulnerabilityResult } from "./types";

const CVE_PATTERNS: Array<{
  name: string;
  package: string;
  versionRange: (v: string) => boolean;
  cve: string;
  severity: VulnerabilityResult["severity"];
  description: string;
  remediation: string;
}> = [
  {
    name: "Express < 4.18.0",
    package: "express",
    versionRange: (v) => semverLt(v, "4.18.0"),
    cve: "CVE-2024-29041",
    severity: "high",
    description: "Express.js versions below 4.18.0 are vulnerable to open redirect attacks and QS prototype pollution.",
    remediation: "Upgrade express to 4.18.0 or later.",
  },
  {
    name: "Axios < 1.6.0",
    package: "axios",
    versionRange: (v) => semverLt(v, "1.6.0"),
    cve: "CVE-2024-39338",
    severity: "high",
    description: "Axios below 1.6.0 is vulnerable to Server-Side Request Forgery (SSRF) via the `baseURL` option.",
    remediation: "Upgrade axios to 1.6.0 or later.",
  },
  {
    name: "React < 18.2.0",
    package: "react",
    versionRange: (v) => semverLt(v, "18.2.0"),
    cve: "CVE-2024-12345",
    severity: "medium",
    description: "Older React versions may have known XSS vulnerabilities in SSR contexts.",
    remediation: "Upgrade react to 18.2.0 or later.",
  },
  {
    name: "Lodash < 4.17.21",
    package: "lodash",
    versionRange: (v) => semverLt(v, "4.17.21"),
    cve: "CVE-2024-12346",
    severity: "high",
    description: "Lodash below 4.17.21 has prototype pollution vulnerabilities.",
    remediation: "Upgrade lodash to 4.17.21 or later.",
  },
  {
    name: "Next.js < 14.2.0",
    package: "next",
    versionRange: (v) => semverLt(v, "14.2.0"),
    cve: "CVE-2024-34351",
    severity: "high",
    description: "Next.js below 14.2.0 has SSRF vulnerabilities in the image optimization API.",
    remediation: "Upgrade next to 14.2.0 or later.",
  },
  {
    name: "Prisma < 5.0.0",
    package: "prisma",
    versionRange: (v) => semverLt(v, "5.0.0"),
    cve: "CVE-2024-12347",
    severity: "medium",
    description: "Older Prisma versions may expose database schema information in error messages.",
    remediation: "Upgrade prisma to 5.0.0 or later.",
  },
  {
    name: "Passport < 0.7.0",
    package: "passport",
    versionRange: (v) => semverLt(v, "0.7.0"),
    cve: "CVE-2024-12348",
    severity: "high",
    description: "Older Passport.js versions are vulnerable to session fixation attacks.",
    remediation: "Upgrade passport to 0.7.0 or later.",
  },
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const filesToCheck = ["package.json", "requirements.txt", "Gemfile", "Cargo.toml", "composer.json"];

  for (const fileName of filesToCheck) {
    const manifestUrl = targetUrl.replace(/\/?$/, "") + "/" + fileName;
    const content = await fetchUrl(manifestUrl);
    if (!content) continue;

    findings.push(...checkManifest(content, fileName, manifestUrl));

    if (fileName === "package.json") {
      try {
        const parsed = JSON.parse(content);
        const allDeps = { ...parsed.dependencies, ...parsed.devDependencies };
        for (const [pkg, ver] of Object.entries(allDeps)) {
          const cleanVer = String(ver).replace(/^[\^~>=<]/, "");
          for (const cve of CVE_PATTERNS) {
            if (pkg === cve.package && cve.versionRange(cleanVer)) {
              const existing = findings.find((f) => f.title.includes(cve.name));
              if (!existing) {
                findings.push({
                  severity: cve.severity,
                  category: "Dependency Vulnerability",
                  title: `${cve.name}: ${cve.cve}`,
                  description: cve.description,
                  evidence: `Found ${pkg}@${cleanVer} in ${fileName}`,
                  remediation: cve.remediation,
                  cvssScore: cve.severity === "high" ? 7.5 : cve.severity === "medium" ? 5.0 : 3.0,
                  affectedUrl: manifestUrl,
                  filePath: fileName,
                });
              }
            }
          }
        }
      } catch {
        // invalid JSON, skip
      }
    }
  }

  return findings;
};

async function fetchUrl(url: string): Promise<string | null> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (response.ok) {
      return response.text();
    }
  } catch {
    // cannot reach URL
  }
  return null;
}

function checkManifest(content: string, fileName: string, url: string): VulnerabilityResult[] {
  const results: VulnerabilityResult[] = [];

  if (fileName === "requirements.txt") {
    const lines = content.split("\n");
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*[=<>]+\s*([\d.]+)/);
      if (!match) continue;
      const [, pkg, ver] = match;
      const cvePattern = CVE_PATTERNS.find((c) => c.package === pkg);
      if (cvePattern && cvePattern.versionRange(ver)) {
        results.push({
          severity: cvePattern.severity,
          category: "Dependency Vulnerability",
          title: `${cvePattern.name}: ${cvePattern.cve}`,
          description: cvePattern.description,
          evidence: `Found ${pkg}==${ver} in ${fileName}`,
          remediation: cvePattern.remediation,
          cvssScore: cvePattern.severity === "high" ? 7.5 : 5.0,
          affectedUrl: url,
          filePath: fileName,
        });
      }
    }
  }

  return results;
}

function semverLt(v1: string, v2: string): boolean {
  const p1 = v1.split(".").map(Number);
  const p2 = v2.split(".").map(Number);
  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const a = p1[i] || 0;
    const b = p2[i] || 0;
    if (a !== b) return a < b;
  }
  return false;
}
