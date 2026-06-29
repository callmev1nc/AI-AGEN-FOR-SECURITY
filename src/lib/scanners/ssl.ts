import * as tls from "tls";
import type { ScannerModule, VulnerabilityResult } from "./types";
import { resolveAndAssertPublic } from "@/lib/safe-fetch";

/**
 * Check SSL/TLS configuration:
 *  - Certificate expiry (< 30 days = medium, expired = critical)
 *  - Self-signed certificates
 *  - Weak protocols (TLS 1.0 / 1.1)
 *  - Weak cipher suites
 */
export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;
  const port = parseInt(parsed.port || "443", 10);

  // Only scan if the target is HTTPS
  if (parsed.protocol !== "https:") {
    return findings;
  }

  // SSRF guard: resolve the hostname and assert it is public-routable, then
  // connect to the validated IP (keeping `hostname` for SNI) so a private /
  // metadata target can't be probed and DNS-rebinding can't slip through.
  let resolvedIp: string;
  try {
    const ips = await resolveAndAssertPublic(hostname);
    resolvedIp = ips[0];
  } catch {
    return findings;
  }

  const certResult = await checkCertificate(resolvedIp, hostname, port);
  const protocolResult = await checkProtocols(resolvedIp, hostname, port);

  if (certResult) {
    // --- Certificate expiry ---
    const now = new Date();
    const expires = new Date(certResult.valid_to);
    const daysUntilExpiry = (expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

    if (daysUntilExpiry <= 0) {
      findings.push({
        severity: "critical",
        category: "SSL/TLS",
        title: "SSL certificate has expired",
        description: `The SSL certificate for ${hostname} expired on ${certResult.valid_to}. Users will see browser warnings and the connection is not secure.`,
        evidence: `Valid to: ${certResult.valid_to}`,
        remediation: "Renew the SSL certificate immediately.",
        cvssScore: 9.1,
        affectedUrl: targetUrl,
      });
    } else if (daysUntilExpiry < 7) {
      findings.push({
        severity: "high",
        category: "SSL/TLS",
        title: "SSL certificate expires within 7 days",
        description: `The SSL certificate expires in ${Math.ceil(daysUntilExpiry)} day(s) (${certResult.valid_to}). Imminent expiry will cause browser trust errors.`,
        evidence: `Valid to: ${certResult.valid_to}`,
        remediation: "Renew the SSL certificate before it expires.",
        cvssScore: 7.5,
        affectedUrl: targetUrl,
      });
    } else if (daysUntilExpiry < 30) {
      findings.push({
        severity: "medium",
        category: "SSL/TLS",
        title: "SSL certificate expires within 30 days",
        description: `The SSL certificate expires in ${Math.ceil(daysUntilExpiry)} days (${certResult.valid_to}). Plan renewal to avoid service disruption.`,
        evidence: `Valid to: ${certResult.valid_to}`,
        remediation: "Renew the SSL certificate before it expires.",
        cvssScore: 5.3,
        affectedUrl: targetUrl,
      });
    }

    // --- Self-signed certificate ---
    if (certResult.issuer.CN === certResult.subject.CN || isSelfSigned(certResult)) {
      findings.push({
        severity: "high",
        category: "SSL/TLS",
        title: "Self-signed SSL certificate detected",
        description: `The SSL certificate for ${hostname} appears to be self-signed (issuer CN: ${certResult.issuer.CN}). This will cause browser trust warnings and provides no chain-of-trust validation.`,
        evidence: `Issuer: ${certResult.issuer.CN}, Subject: ${certResult.subject.CN}`,
        remediation:
          "Replace the self-signed certificate with one issued by a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert).",
        cvssScore: 6.5,
        affectedUrl: targetUrl,
      });
    }
  } else {
    findings.push({
      severity: "high",
      category: "SSL/TLS",
      title: "Could not retrieve SSL certificate",
      description: `Failed to establish a TLS connection to ${hostname}:${port}. The server may not support TLS or may be unreachable.`,
      remediation: "Verify that the server is configured for TLS and the port is correct.",
      cvssScore: 6.0,
      affectedUrl: targetUrl,
    });
  }

  // --- Weak protocols ---
  if (protocolResult) {
    if (protocolResult.protocol === "TLSv1.0" || protocolResult.protocol === "TLSv1.1") {
      findings.push({
        severity: "high",
        category: "SSL/TLS",
        title: `Weak TLS protocol: ${protocolResult.protocol}`,
        description: `The server negotiated ${protocolResult.protocol}, which is deprecated and vulnerable to attacks such as BEAST and POODLE.`,
        evidence: `Negotiated protocol: ${protocolResult.protocol}`,
        remediation: "Disable TLS 1.0 and TLS 1.1. Configure the server to use TLS 1.2 or later only.",
        cvssScore: 7.4,
        affectedUrl: targetUrl,
      });
    }

    // Check for weak ciphers
    const weakCipherPatterns = [
      /RC4/i,
      /DES/i,
      /3DES/i,
      /MD5/i,
      /NULL/i,
      /EXPORT/i,
      /anon/i,
      /RC2/i,
    ];
    const cipherName = protocolResult.currentCipher?.name || "";
    for (const pattern of weakCipherPatterns) {
      if (pattern.test(cipherName)) {
        findings.push({
          severity: "high",
          category: "SSL/TLS",
          title: `Weak cipher suite: ${cipherName}`,
          description: `The server negotiated a weak cipher suite (${cipherName}). This cipher is considered insecure and may allow attackers to decrypt traffic.`,
          evidence: `Cipher: ${cipherName}`,
          remediation:
            "Configure the server to prefer strong cipher suites such as AES-GCM with ECDHE key exchange.",
          cvssScore: 7.5,
          affectedUrl: targetUrl,
        });
        break; // One weak-cipher finding is enough
      }
    }
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface CertInfo {
  subject: { CN?: string; [k: string]: string | undefined };
  issuer: { CN?: string; [k: string]: string | undefined };
  valid_from: string;
  valid_to: string;
  fingerprint: string;
}

interface ProtocolInfo {
  protocol: string;
  currentCipher?: { name: string };
}

function checkCertificate(ip: string, servername: string, port: number): Promise<CertInfo | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: ip, port, servername, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || Object.keys(cert).length === 0) {
          resolve(null);
          return;
        }
        resolve({
          subject: cert.subject as CertInfo["subject"],
          issuer: cert.issuer as CertInfo["issuer"],
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint: cert.fingerprint,
        });
      }
    );
    socket.on("error", () => {
      socket.destroy();
      resolve(null);
    });
    socket.setTimeout(8000, () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function checkProtocols(ip: string, servername: string, port: number): Promise<ProtocolInfo | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: ip, port, servername, rejectUnauthorized: false },
      () => {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.end();
        resolve({
          protocol: protocol || "unknown",
          currentCipher: cipher ? { name: cipher.name } : undefined,
        });
      }
    );
    socket.on("error", () => {
      socket.destroy();
      resolve(null);
    });
    socket.setTimeout(8000, () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function isSelfSigned(cert: CertInfo): boolean {
  // Heuristic: issuer and subject share the same O or OU
  return (
    !!cert.issuer.O &&
    !!cert.subject.O &&
    cert.issuer.O === cert.subject.O &&
    cert.issuer.CN === cert.subject.CN
  );
}
