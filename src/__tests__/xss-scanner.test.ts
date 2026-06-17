import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the SSRF-safe HTTP helper so the scanner's DETECTION logic is tested in
// isolation (no network). This also implicitly proves the scanner imports the
// shared helper rather than raw http/https.
const fetchBodyMock = vi.fn();
vi.mock("@/lib/scanners/http", () => ({
  fetchBody: (...args: unknown[]) => fetchBodyMock(...(args as [string])),
}));

import { scan } from "@/lib/scanners/xss";

describe("xss scanner", () => {
  beforeEach(() => fetchBodyMock.mockReset());

  it("flags an unescaped reflected payload (html context) as high", async () => {
    fetchBodyMock.mockResolvedValue({
      statusCode: 200,
      body: `<div><script>secupi-test</script></div>`,
    });
    const findings = await scan("https://example.com/?q=benign");
    expect(findings.some((f) => f.severity === "high" && f.category.includes("XSS"))).toBe(true);
  });

  it("does not flag a response that does not reflect the payload", async () => {
    fetchBodyMock.mockResolvedValue({ statusCode: 200, body: "<div>safe content</div>" });
    const findings = await scan("https://example.com/?q=benign");
    expect(findings.length).toBe(0);
  });

  it("returns an empty list when the target is unreachable", async () => {
    fetchBodyMock.mockResolvedValue(null);
    const findings = await scan("https://example.com/?q=benign");
    expect(findings).toEqual([]);
  });
});
