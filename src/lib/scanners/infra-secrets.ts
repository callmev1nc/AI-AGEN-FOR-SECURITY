import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";

export const SECRET_PATTERNS: Array<{
  name: string;
  regex: RegExp;
  severity: VulnerabilityResult["severity"];
  remediation: string;
}> = [
  {
    name: "AWS Access Key",
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    severity: "critical",
    remediation: "Rotate the AWS access key immediately. Remove it from the source code and use IAM roles or environment variables instead.",
  },
  {
    name: "AWS Secret Key",
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"][A-Za-z0-9\/+=]{40}['"]/g,
    severity: "critical",
    remediation: "Rotate the AWS secret key immediately. Use AWS Secrets Manager or environment variables.",
  },
  {
    name: "GitHub Token",
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    severity: "critical",
    remediation: "Revoke the GitHub token and rotate it. Use GitHub Actions secrets or environment variables instead.",
  },
  {
    name: "GitHub OAuth Token",
    regex: /(?:ghp|gho)_[A-Za-z0-9_]{36,}/g,
    severity: "high",
    remediation: "Revoke the GitHub OAuth token. Use a fine-grained token with minimal permissions.",
  },
  {
    name: "Slack Token",
    regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
    severity: "high",
    remediation: "Revoke the Slack token. Store it in environment variables or a secrets manager.",
  },
  {
    name: "Stripe Secret Key",
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: "critical",
    remediation: "Rotate the Stripe secret key immediately. Restrict key permissions and use environment variables.",
  },
  {
    name: "Stripe Publishable Key",
    regex: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: "low",
    remediation: "Consider restricting Stripe key permissions. While publishable keys are meant to be public, live keys should be carefully managed.",
  },
  {
    name: "JWT Secret",
    regex: /(?:JWT_SECRET|jwt_secret|jwtSecret)\s*[:=]\s*['"][^'"]{16,}['"]/g,
    severity: "high",
    remediation: "Rotate the JWT secret. Use a strong randomly-generated key stored in environment variables.",
  },
  {
    name: "Private SSH Key",
    regex: /-----BEGIN\s?(?:RSA|DSA|EC|OPENSSH)\s?PRIVATE\s?KEY-----/g,
    severity: "critical",
    remediation: "Remove the private key from the codebase. Use SSH agent or secrets manager. Rotate the key pair.",
  },
  {
    name: "Database Connection String",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s]{8,}@/gi,
    severity: "critical",
    remediation: "Remove the connection string from code. Use environment variables and a secrets manager. Rotate the database password.",
  },
  {
    name: "Redis Connection String",
    regex: /redis:\/\/[^\s]{8,}@/gi,
    severity: "high",
    remediation: "Remove the Redis connection string from code. Use environment variables.",
  },
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    severity: "high",
    remediation: "Revoke the Google API key and restrict it by IP/referrer. Use environment variables.",
  },
  {
    name: "Heroku API Key",
    regex: /(?:heroku|HEROKU)_(?:api_key|API_KEY)\s*[:=]\s*['"][A-Za-z0-9-]{36}['"]/g,
    severity: "high",
    remediation: "Revoke the Heroku API key. Use environment variables or Heroku's built-in config vars.",
  },
  {
    name: "npm Auth Token",
    regex: /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9-]{36,}/g,
    severity: "high",
    remediation: "Revoke the npm auth token. Use npm token management to generate a new one.",
  },
  {
    name: "Twilio API Key",
    regex: /SK[0-9a-fA-F]{32}/g,
    severity: "high",
    remediation: "Revoke the Twilio API key. Restrict key permissions and use environment variables.",
  },
  {
    name: "Azure Storage Key",
    regex: /(?:accountkey|account_key|AccountKey)\s*[:=]\s*['"][A-Za-z0-9+/=]{88}['"]/gi,
    severity: "high",
    remediation: "Rotate the Azure storage key. Use Azure Managed Identity or environment variables.",
  },
  {
    name: ".env file detected",
    regex: /\.env\b/g,
    severity: "high",
    remediation: "Ensure .env files are in .gitignore. Never commit environment files to version control.",
  },
  {
    name: "Generic API Key Pattern",
    regex: /(?:api_key|apikey|API_KEY)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/gi,
    severity: "medium",
    remediation: "Review if this is a sensitive API key. If so, rotate it and move to environment variables.",
  },
  {
    name: "Password in Code",
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi,
    severity: "high",
    remediation: "Remove hardcoded passwords. Use environment variables, secrets manager, or OAuth instead.",
  },
];

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
  const findings: VulnerabilityResult[] = [];

  for (const fileName of REPO_FILES) {
    if (FILES_TO_SKIP.test(fileName)) continue;

    const fileUrl = targetUrl.replace(/\/?$/, "") + "/" + fileName.replace("**/", "");
    const content = await fetchUrl(fileUrl);
    if (!content) continue;

    for (const pattern of SECRET_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (!matches) continue;

      const lineIndex = findLineNumber(content, matches[0]);
      const context = getContextLines(content, lineIndex);

      const maskedMatch = matches[0].length > 8
        ? matches[0].slice(0, 4) + "..." + matches[0].slice(-4)
        : matches[0].slice(0, 2) + "...";

      findings.push({
        severity: pattern.severity,
        category: "Hardcoded Secret",
        title: `${pattern.name} detected in ${fileName}`,
        description: `A ${pattern.name} was found in "${fileName}". Hardcoded secrets in source code can lead to account compromise, data breaches, and unauthorized access.`,
        evidence: `File: ${fileName}, Line: ${lineIndex}\nPattern: ${maskedMatch}\nContext:\n${context}`,
        remediation: pattern.remediation,
        cvssScore: pattern.severity === "critical" ? 9.0 : pattern.severity === "high" ? 7.0 : 3.0,
        affectedUrl: fileUrl,
        filePath: fileName,
        lineStart: lineIndex,
      });
    }
  }

  return findings;
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

function findLineNumber(content: string, match: string): number {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(match)) return i + 1;
  }
  return 0;
}

function getContextLines(content: string, lineNumber: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNumber - 3);
  const end = Math.min(lines.length, lineNumber + 2);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join("\n");
}
