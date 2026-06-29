import { describe, it, expect } from "vitest";
import { detectSecretsInFiles } from "@/lib/scanners/core/secrets";
import { detectVulnerableDepsInFiles } from "@/lib/scanners/core/dependencies";
import { detectDangerousPatternsInFiles } from "@/lib/scanners/core/code-patterns";

describe("scan-core: secrets detection", () => {
  it("detects AWS access keys in file content", () => {
    const files = [
      { path: "config.js", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
    ];
    const findings = detectSecretsInFiles(files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe("Hardcoded Secret");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].title).toContain("AWS Access Key");
  });

  it("detects private SSH keys", () => {
    const files = [
      { path: "id_rsa", content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..." },
    ];
    const findings = detectSecretsInFiles(files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].title).toContain("Private SSH Key");
  });

  it("returns empty for safe files", () => {
    const files = [
      { path: "readme.md", content: "# My Project\nThis is a safe file." },
    ];
    const findings = detectSecretsInFiles(files);
    expect(findings.length).toBe(0);
  });
});

describe("scan-core: dependency detection", () => {
  it("detects vulnerable express version in package.json", () => {
    const files = [
      { path: "package.json", content: JSON.stringify({
        dependencies: { express: "4.17.1" },
      })},
    ];
    const findings = detectVulnerableDepsInFiles(files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].title).toContain("Express");
  });

  it("does not flag safe versions", () => {
    const files = [
      { path: "package.json", content: JSON.stringify({
        dependencies: { express: "4.18.0" },
      })},
    ];
    const findings = detectVulnerableDepsInFiles(files);
    const expressFindings = findings.filter((f) => f.title.includes("Express"));
    expect(expressFindings.length).toBe(0);
  });
});

describe("scan-core: dangerous code patterns", () => {
  it("detects eval() usage", () => {
    const files = [
      { path: "server.js", content: 'const result = eval(userInput);' },
    ];
    const findings = detectDangerousPatternsInFiles(files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].title).toContain("eval");
  });

  it("detects innerHTML assignment", () => {
    const files = [
      { path: "component.js", content: 'element.innerHTML = userInput;' },
    ];
    const findings = detectDangerousPatternsInFiles(files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].title).toContain("innerHTML");
  });

  it("returns empty for safe code", () => {
    const files = [
      { path: "safe.js", content: 'const x = 1; const y = x + 2;' },
    ];
    const findings = detectDangerousPatternsInFiles(files);
    expect(findings.length).toBe(0);
  });
});
