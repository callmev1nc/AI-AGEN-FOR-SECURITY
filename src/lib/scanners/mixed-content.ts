import type { ScannerModule, VulnerabilityResult } from "./types";
import { scannerRequest } from "./http";

/**
 * Fetch the HTML page and parse for http:// URLs in resource attributes
 * (img src, script src, link href, iframe src, etc.) when the page is served over HTTPS.
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);

  // Only relevant for HTTPS pages
  if (parsed.protocol !== "https:") {
    return findings;
  }

  const html = await fetchHtml(targetUrl);
  if (!html) {
    return findings;
  }

  // Patterns to find mixed-content references
  const patterns: Array<{
    regex: RegExp;
    elementType: string;
  }> = [
    {
      regex: /<img[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "img",
    },
    {
      regex: /<script[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "script",
    },
    {
      regex: /<link[^>]+href\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "link",
    },
    {
      regex: /<iframe[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "iframe",
    },
    {
      regex: /<video[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "video",
    },
    {
      regex: /<audio[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "audio",
    },
    {
      regex: /<source[^>]+src\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "source",
    },
    {
      regex: /<object[^>]+data\s*=\s*["']http:\/\/[^"']+["']/gi,
      elementType: "object",
    },
  ];

  const seenUrls = new Set<string>();

  for (const { regex, elementType } of patterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(html)) !== null) {
      // Extract the URL from the matched attribute
      const urlMatch = match[0].match(/["'](http:\/\/[^"']+)["']/);
      if (urlMatch) {
        const resourceUrl = urlMatch[1];
        if (seenUrls.has(resourceUrl)) continue;
        seenUrls.add(resourceUrl);

        // Determine severity based on element type
        // Scripts and iframes are "active" mixed content (blocked by browsers, higher severity)
        // Images, etc. are "passive" mixed content (may be displayed but degraded)
        const isPassive = ["img", "audio", "video", "source"].includes(elementType);
        const severity: VulnerabilityResult["severity"] = isPassive ? "low" : "medium";
        const cvss = isPassive ? 2.4 : 4.3;

        findings.push({
          severity,
          category: "Mixed Content",
          title: `Mixed content: insecure HTTP ${elementType} on HTTPS page`,
          description: isPassive
            ? `The HTTPS page loads a passive resource via HTTP: <${elementType}> loading ${resourceUrl}. Passive mixed content does not execute code but can be modified by a man-in-the-middle attacker.`
            : `The HTTPS page loads an active resource via HTTP: <${elementType}> loading ${resourceUrl}. Active mixed content is blocked by modern browsers and, if loaded, can compromise the entire page's security.`,
          evidence: match[0],
          remediation: `Change the ${elementType} URL to use HTTPS: ${resourceUrl.replace("http://", "https://")}. Consider using protocol-relative URLs or ensuring all resources support HTTPS.`,
          cvssScore: cvss,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchHtml(targetUrl: string): Promise<string | null> {
  const res = await scannerRequest(targetUrl, {
    method: "GET",
    headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
    followRedirects: true, // safeFetch re-validates each hop
    timeoutMs: 10000,
  });
  return res ? res.body : null;
}
