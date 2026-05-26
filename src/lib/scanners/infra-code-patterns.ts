import type { ScannerModule, VulnerabilityResult } from "./types";

const DANGEROUS_PATTERNS: Array<{
  category: string;
  regex: RegExp;
  severity: VulnerabilityResult["severity"];
  title: string;
  description: string;
  remediation: string;
  cvss: number;
}> = [
  {
    category: "Code Injection",
    regex: /\b(eval|exec)\s*\(/,
    severity: "critical",
    title: "Dangerous eval() or exec() usage",
    description: "The use of eval() or exec() can execute arbitrary code and is a severe security risk. Input passed to these functions may allow code injection attacks.",
    remediation: "Avoid eval()/exec() entirely. Use safer alternatives like JSON.parse(), Function constructor (with caution), or domain-specific parsers.",
    cvss: 9.0,
  },
  {
    category: "Cross-Site Scripting (XSS)",
    regex: /\.innerHTML\s*=/,
    severity: "high",
    title: "innerHTML assignment (XSS risk)",
    description: "Setting innerHTML directly can introduce XSS vulnerabilities if the content contains user-controlled data.",
    remediation: "Use textContent instead of innerHTML when inserting text. If HTML is required, use DOMPurify or similar sanitization library.",
    cvss: 7.5,
  },
  {
    category: "SQL Injection",
    regex: /(?:executeQuery|query|run)\s*\(\s*(?:`|'|")\s*SELECT.*\+/,
    severity: "critical",
    title: "SQL query string concatenation",
    description: "Building SQL queries by concatenating strings can lead to SQL injection. User input in concatenated queries can break the SQL syntax.",
    remediation: "Use parameterized queries (prepared statements) or an ORM. Never concatenate user input into SQL strings.",
    cvss: 9.0,
  },
  {
    category: "Command Injection",
    regex: /\b(?:exec|execSync|spawn|execFile)\s*\(/,
    severity: "critical",
    title: "OS command execution",
    description: "Executing OS commands directly from application code is risky. If user input influences the command, it can lead to command injection.",
    remediation: "Avoid executing OS commands directly. If necessary, validate and sanitize all inputs strictly, and use an allowlist of permitted commands.",
    cvss: 9.0,
  },
  {
    category: "Insecure Deserialization",
    regex: /JSON\.parse\s*\(.*user|unsafe|unserialize|pickle\.loads/,
    severity: "high",
    title: "Potential insecure deserialization",
    description: "Deserializing untrusted data can lead to remote code execution, injection attacks, or privilege escalation.",
    remediation: "Avoid deserializing untrusted data. If necessary, use validation and consider using safer formats like JSON with schema validation.",
    cvss: 8.0,
  },
  {
    category: "Insecure TLS",
    regex: /(?:rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:false|0)/,
    severity: "high",
    title: "TLS verification disabled",
    description: "Disabling TLS/SSL certificate verification makes the application vulnerable to man-in-the-middle attacks.",
    remediation: "Enable TLS verification by setting rejectUnauthorized: true. Only disable in development environments with explicit justification.",
    cvss: 7.5,
  },
  {
    category: "Hardcoded Credentials",
    regex: /\b(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i,
    severity: "high",
    title: "Hardcoded password detected",
    description: "Hardcoded passwords in source code can be extracted from version control history and lead to unauthorized access.",
    remediation: "Use environment variables, secrets management services (AWS Secrets Manager, HashiCorp Vault), or OAuth.",
    cvss: 7.0,
  },
  {
    category: "Prototype Pollution",
    regex: /Object\.assign\s*\(\s*[^,]+,\s*(?:req|body|userInput|params|query)/,
    severity: "medium",
    title: "Potential prototype pollution",
    description: "Merging user-controlled objects without proper validation can lead to prototype pollution, affecting object behavior globally.",
    remediation: "Use safe object merging with whitelist of allowed keys, or use Object.assign with frozen/sealed objects.",
    cvss: 6.0,
  },
  {
    category: "Path Traversal",
    regex: /(?:fs\.readFile|fs\.readFileSync|fs\.writeFile|fs\.writeFileSync)\s*\(\s*['"`][^'"]*\+/,
    severity: "high",
    title: "Dynamic file path construction",
    description: "Building file paths from dynamic values can enable path traversal attacks, allowing access to files outside the intended directory.",
    remediation: "Use path.normalize() and verify the resolved path starts with the expected base directory. Use an allowlist of permitted files.",
    cvss: 7.5,
  },
  {
    category: "Cross-Site Request Forgery",
    regex: /app\.(?:get|post|put|delete|patch)\s*\(/,
    severity: "medium",
    title: "Route without CSRF protection",
    description: "API routes should be protected against CSRF attacks, especially if they modify state. Without CSRF tokens, attackers can forge requests on behalf of authenticated users.",
    remediation: "Implement CSRF tokens for state-changing operations. Use SameSite cookies and check Origin/Referrer headers.",
    cvss: 5.0,
  },
  {
    category: "Insecure Randomness",
    regex: /\bMath\.random\s*\(\s*\)/,
    severity: "low",
    title: "Insecure random number generation",
    description: "Math.random() is not cryptographically secure. Using it for security-critical operations (tokens, passwords, secrets) is unsafe.",
    remediation: "Use crypto.randomBytes() or crypto.randomUUID() for security-critical randomness.",
    cvss: 3.0,
  },
];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];

  const filesToCheck = [
    "src/app/**/*.ts", "src/app/**/*.tsx", "src/lib/**/*.ts",
    "src/server/**/*.ts", "index.js", "server.js", "app.js",
    "src/**/*.js", "src/**/*.py", "lib/**/*.rb",
  ];

  for (const pattern of filesToCheck) {
    const fileName = pattern.replace("**/", "");
    const fileUrl = `${targetUrl.replace(/\/?$/, "")}/${fileName}`;
    const content = await fetchUrl(fileUrl);
    if (!content) continue;

    const lines = content.split("\n");

    for (const dangerous of DANGEROUS_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (dangerous.regex.test(line)) {
          const existing = findings.find(
            (f) => f.title === dangerous.title && f.filePath === fileName
          );
          if (!existing) {
            findings.push({
              severity: dangerous.severity,
              category: dangerous.category,
              title: dangerous.title,
              description: `Found in ${fileName} at line ${i + 1}: ${dangerous.description}`,
              evidence: `File: ${fileName}\nLine ${i + 1}: ${line.trim()}\n\nContext:\n${getContext(lines, i)}`,
              remediation: dangerous.remediation,
              cvssScore: dangerous.cvss,
              affectedUrl: fileUrl,
              filePath: fileName,
              lineStart: i + 1,
              lineEnd: i + 1,
            });
          }
          break;
        }
      }
    }
  }

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

function getContext(lines: string[], lineIndex: number): string {
  const start = Math.max(0, lineIndex - 2);
  const end = Math.min(lines.length, lineIndex + 3);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join("\n");
}
