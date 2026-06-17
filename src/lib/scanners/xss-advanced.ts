import type { ScannerModule, VulnerabilityResult } from "./types";
import { fetchBody as httpGetBody } from "./http";

/**
 * Advanced XSS testing:
 *  - DOM-based XSS: check for dangerous sinks (innerHTML, document.write, eval) in inline scripts
 *  - Mutation XSS payloads
 *  - Event handler injection
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const html = await fetchHtml(targetUrl);
  if (!html) return findings;

  // ---- 1. DOM-based XSS: dangerous sinks in inline scripts ----
  const inlineScripts = extractInlineScripts(html);

  const dangerousSinks: Array<{
    pattern: RegExp;
    sink: string;
    severity: VulnerabilityResult["severity"];
    cvss: number;
  }> = [
    {
      pattern: /\.innerHTML\s*=/,
      sink: "innerHTML assignment",
      severity: "high",
      cvss: 7.5,
    },
    {
      pattern: /\.outerHTML\s*=/,
      sink: "outerHTML assignment",
      severity: "high",
      cvss: 7.5,
    },
    {
      pattern: /document\.write\s*\(/,
      sink: "document.write()",
      severity: "high",
      cvss: 7.5,
    },
    {
      pattern: /document\.writeln\s*\(/,
      sink: "document.writeln()",
      severity: "high",
      cvss: 7.5,
    },
    {
      pattern: /\beval\s*\(/,
      sink: "eval()",
      severity: "high",
      cvss: 8.0,
    },
    {
      pattern: /new\s+Function\s*\(/,
      sink: "new Function()",
      severity: "high",
      cvss: 8.0,
    },
    {
      pattern: /setTimeout\s*\(\s*["'`]/,
      sink: "setTimeout with string argument",
      severity: "medium",
      cvss: 6.1,
    },
    {
      pattern: /setInterval\s*\(\s*["'`]/,
      sink: "setInterval with string argument",
      severity: "medium",
      cvss: 6.1,
    },
    {
      pattern: /\.insertAdjacentHTML\s*\(/,
      sink: "insertAdjacentHTML()",
      severity: "medium",
      cvss: 6.1,
    },
  ];

  const sources = [
    /location\.hash/,
    /location\.search/,
    /location\.href/,
    /location\.pathname/,
    /document\.URL/,
    /document\.documentURI/,
    /document\.referrer/,
    /window\.name/,
    /document\.cookie/,
    /\.getParameter/,
    /URLSearchParams/,
    /new\s+URL\(/,
  ];

  for (const script of inlineScripts) {
    for (const { pattern, sink, severity, cvss } of dangerousSinks) {
      if (pattern.test(script)) {
        // Check if any source feeds into this sink (taint indicator)
        const hasSource = sources.some((s) => s.test(script));

        findings.push({
          severity: hasSource ? severity : "medium",
          category: "Cross-Site Scripting (XSS)",
          title: hasSource
            ? `Potential DOM-based XSS: ${sink} with user-controlled source`
            : `Dangerous DOM sink detected: ${sink}`,
          description: hasSource
            ? `Inline script uses ${sink} which appears to receive data from a user-controllable source (e.g., location.hash, URL parameters). An attacker can inject malicious HTML/JS through the URL.`
            : `Inline script uses ${sink}. While no direct user-controlled source was identified in the same script block, the data flowing into this sink should be audited manually.`,
          evidence: truncate(script, 300),
          remediation: getSinkRemediation(sink),
          cvssScore: hasSource ? cvss : 5.0,
          affectedUrl: targetUrl,
        });
      }
    }
  }

  // ---- 2. Mutation XSS (mXSS) testing ----
  const mxFinding = await testMutationXss(targetUrl);
  if (mxFinding) findings.push(mxFinding);

  // ---- 3. Event handler injection ----
  const eventFindings = await testEventHandlerInjection(targetUrl);
  findings.push(...eventFindings);

  // ---- 4. Template literal injection ----
  for (const script of inlineScripts) {
    if (/\$\{.*location/.test(script) || /\$\{.*document\.URL/.test(script)) {
      findings.push({
        severity: "high",
        category: "Cross-Site Scripting (XSS)",
        title: "Potential template literal injection with URL source",
        description:
          "Inline script uses template literals that incorporate URL-derived values. If these are rendered into the DOM without encoding, they can lead to XSS.",
        evidence: truncate(script, 300),
        remediation:
          "Avoid interpolating URL-derived values into HTML strings. Use textContent or other safe DOM APIs instead.",
        cvssScore: 7.5,
        affectedUrl: targetUrl,
      });
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractInlineScripts(html: string): string[] {
  const scripts: string[] = [];
  const regex = /<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(html)) !== null) {
    if (match[1].trim().length > 0) {
      scripts.push(match[1]);
    }
  }
  return scripts;
}

async function testMutationXss(
  targetUrl: string
): Promise<VulnerabilityResult | null> {
  // Test mutation XSS payloads that can bypass sanitization
  const payloads = [
    {
      name: "SVG mXSS",
      value: '<svg><svg/onload=secupi-test>',
    },
    {
      name: "Math mXSS",
      value: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=secupi>',
    },
    {
      name: "SVG foreignObject mXSS",
      value: '<svg><foreignObject><body xmlns=xmlns:svg="http://www.w3.org/2000/svg"><img src=x onerror=secupi>',
    },
    {
      name: "Noscript mXSS",
      value: '<noscript><p title="</noscript><img src=x onerror=secupi>">',
    },
    {
      name: "Listing mXSS",
      value: '<listing>&lt;img src=x onerror=secupi&gt;</listing>',
    },
  ];

  for (const payload of payloads) {
    const testUrl = appendQueryParam(targetUrl, "q", payload.value);
    const resp = await httpGetBody(testUrl);
    if (resp && resp.body) {
      // Check if the payload or key parts survived sanitization
      const indicators = ["onerror=secupi", "onload=secupi", "<img src=x"];
      for (const indicator of indicators) {
        if (resp.body.includes(indicator)) {
          return {
            severity: "high",
            category: "Cross-Site Scripting (XSS)",
            title: `Potential mutation XSS: ${payload.name}`,
            description: `The payload "${payload.name}" survived server-side sanitization and the event handler indicator "${indicator}" appears in the response. This suggests the sanitizer can be bypassed through DOM mutation.`,
            evidence: `Payload: ${payload.value}\nReflected indicator: ${indicator}`,
            remediation:
              "Use a robust, well-tested sanitizer such as DOMPurify. Keep sanitization libraries updated. Test against mXSS vectors specifically.",
            cvssScore: 8.1,
            affectedUrl: testUrl,
          };
        }
      }
    }
  }

  return null;
}

async function testEventHandlerInjection(
  targetUrl: string
): Promise<VulnerabilityResult[]> {
  const findings: VulnerabilityResult[] = [];

  const eventPayloads = [
    { param: "q", value: "' onmouseover='secupi-test' x='", event: "onmouseover" },
    { param: "q", value: '" onfocus="secupi-test" x="', event: "onfocus" },
    { param: "q", value: "' onerror='secupi-test' src='x' x='", event: "onerror" },
    { param: "id", value: "' onmouseover='secupi-test", event: "onmouseover" },
    { param: "class", value: "' onclick='secupi-test' x='", event: "onclick" },
  ];

  for (const payload of eventPayloads) {
    const testUrl = appendQueryParam(targetUrl, payload.param, payload.value);
    const resp = await httpGetBody(testUrl);
    if (resp && resp.body && resp.body.includes(payload.event)) {
      findings.push({
        severity: "medium",
        category: "Cross-Site Scripting (XSS)",
        title: `Potential event handler injection via "${payload.param}"`,
        description: `The payload injected via the "${payload.param}" parameter appears to create an event handler attribute (${payload.event}) in the response. If an attacker can control attribute values, they can execute arbitrary JavaScript.`,
        evidence: `Parameter: ${payload.param}=${payload.value}`,
        remediation:
          "Encode all user input used in HTML attributes. Use context-aware encoding for attribute values. Implement CSP as an additional defense layer.",
        cvssScore: 5.3,
        affectedUrl: testUrl,
      });
    }
  }

  return findings;
}

function appendQueryParam(baseUrl: string, name: string, value: string): string {
  const parsed = new URL(baseUrl);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

// fetchHtml delegates to the SSRF-safe httpGetBody (no redirect following,
// matching the original behaviour).
async function fetchHtml(url: string): Promise<string | null> {
  const r = await httpGetBody(url);
  return r?.body ?? null;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.substring(0, maxLen) + "...";
}

function getSinkRemediation(sink: string): string {
  if (sink.includes("innerHTML") || sink.includes("outerHTML")) {
    return "Replace innerHTML/outerHTML assignments with textContent, innerText, or DOM manipulation methods (createElement, appendChild) which do not parse HTML.";
  }
  if (sink.includes("document.write")) {
    return "Never use document.write(). Use DOM manipulation methods instead (createElement, appendChild, textContent).";
  }
  if (sink.includes("eval") || sink.includes("Function")) {
    return "Never use eval() or new Function(). Use JSON.parse() for data parsing and explicit logic instead of dynamic code execution.";
  }
  if (sink.includes("setTimeout") || sink.includes("setInterval")) {
    return "Pass functions instead of strings to setTimeout/setInterval. Example: setTimeout(() => { ... }, 1000)";
  }
  if (sink.includes("insertAdjacentHTML")) {
    return "Avoid insertAdjacentHTML with user-controlled content. Use textContent or DOM manipulation methods instead.";
  }
  return "Avoid using dangerous DOM sinks with user-controlled data. Sanitize all input and use safe DOM APIs.";
}
