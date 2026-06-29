import * as net from "net";
import type { ScannerModule, VulnerabilityResult } from "./types";
import { resolveAndAssertPublic } from "@/lib/safe-fetch";

/**
 * TCP connect scan on common ports.
 * Reports open ports that should not be exposed to the internet.
 */

interface PortEntry {
  port: number;
  service: string;
  risk: "critical" | "high" | "medium" | "low" | "info";
  reason: string;
}

const SENSITIVE_PORTS: PortEntry[] = [
  { port: 21, service: "FTP", risk: "high", reason: "FTP transmits credentials in cleartext and is frequently targeted for brute-force attacks." },
  { port: 22, service: "SSH", risk: "medium", reason: "SSH should not be exposed to the public internet without key-based authentication and IP restrictions." },
  { port: 23, service: "Telnet", risk: "critical", reason: "Telnet transmits all data including credentials in cleartext. It should never be exposed." },
  { port: 25, service: "SMTP", risk: "medium", reason: "SMTP may be abused for open relay spam if misconfigured." },
  { port: 465, service: "SMTPS", risk: "low", reason: "SMTP over TLS; verify it is not an open relay." },
  { port: 110, service: "POP3", risk: "medium", reason: "POP3 transmits credentials in cleartext by default." },
  { port: 143, service: "IMAP", risk: "medium", reason: "IMAP without TLS transmits credentials in cleartext." },
  { port: 993, service: "IMAPS", risk: "low", reason: "IMAP over TLS; verify authentication requirements." },
  { port: 995, service: "POP3S", risk: "low", reason: "POP3 over TLS; verify authentication requirements." },
  { port: 135, service: "MSRPC", risk: "high", reason: "Microsoft RPC is commonly exploited in Windows environments and should not be internet-facing." },
  { port: 139, service: "NetBIOS", risk: "high", reason: "NetBIOS over TCP exposes file sharing and authentication information." },
  { port: 445, service: "SMB", risk: "critical", reason: "SMB is heavily targeted by ransomware and worms (e.g., EternalBlue). Must not be exposed to the internet." },
  { port: 512, service: "rexec", risk: "critical", reason: "Remote execution service — extremely dangerous if exposed." },
  { port: 513, service: "rlogin", risk: "critical", reason: "Remote login service — transmits data in cleartext." },
  { port: 514, service: "rsh/syslog", risk: "high", reason: "Remote shell or syslog — should not be internet-facing." },
  { port: 1099, service: "RMI Registry", risk: "high", reason: "Java RMI registry can allow remote code execution if misconfigured." },
  { port: 1433, service: "MSSQL", risk: "critical", reason: "Microsoft SQL Server should never be exposed directly to the internet." },
  { port: 1521, service: "Oracle DB", risk: "critical", reason: "Oracle database should never be exposed directly to the internet." },
  { port: 3306, service: "MySQL", risk: "critical", reason: "MySQL should never be exposed directly to the internet." },
  { port: 3389, service: "RDP", risk: "critical", reason: "Remote Desktop Protocol is frequently targeted for brute-force attacks and BlueKeep exploits." },
  { port: 5432, service: "PostgreSQL", risk: "critical", reason: "PostgreSQL should never be exposed directly to the internet." },
  { port: 5900, service: "VNC", risk: "high", reason: "VNC provides remote desktop access and is often misconfigured without encryption." },
  { port: 6379, service: "Redis", risk: "critical", reason: "Redis is commonly left unauthenticated and can be exploited for remote code execution." },
  { port: 6443, service: "Kubernetes API", risk: "critical", reason: "Kubernetes API server should not be accessible without authentication." },
  { port: 7001, service: "WebLogic", risk: "high", reason: "Oracle WebLogic admin console is frequently targeted for remote code execution." },
  { port: 8000, service: "HTTP Alt", risk: "info", reason: "Alternative HTTP port — verify this is intentional and secured." },
  { port: 8080, service: "HTTP Proxy", risk: "info", reason: "HTTP proxy or alternative web server — verify access controls." },
  { port: 8443, service: "HTTPS Alt", risk: "info", reason: "Alternative HTTPS port — verify access controls." },
  { port: 8888, service: "HTTP Alt", risk: "info", reason: "Alternative HTTP port — verify access controls." },
  { port: 9000, service: "PHP-FPM/sonar", risk: "medium", reason: "PHP-FPM or SonarQube may be exposed; verify authentication." },
  { port: 9200, service: "Elasticsearch", risk: "critical", reason: "Elasticsearch HTTP API is often left unauthenticated, exposing indexed data." },
  { port: 9300, service: "ES Transport", risk: "critical", reason: "Elasticsearch transport port should not be exposed to the internet." },
  { port: 11211, service: "Memcached", risk: "critical", reason: "Memcached is frequently abused for amplification DDoS attacks and data theft." },
  { port: 27017, service: "MongoDB", risk: "critical", reason: "MongoDB is often left unauthenticated, exposing all stored data." },
  { port: 27018, service: "MongoDB", risk: "critical", reason: "MongoDB shard server should not be exposed." },
  { port: 28017, service: "MongoDB Web", risk: "high", reason: "MongoDB web interface should not be publicly accessible." },
];

// Additional common ports to scan (for information gathering)
const COMMON_PORTS: PortEntry[] = [
  { port: 80, service: "HTTP", risk: "info", reason: "Standard HTTP port." },
  { port: 443, service: "HTTPS", risk: "info", reason: "Standard HTTPS port." },
  { port: 587, service: "SMTP Submission", risk: "info", reason: "Mail submission port." },
  { port: 3000, service: "Dev Server", risk: "low", reason: "Common development server port — should not be in production." },
  { port: 5000, service: "Dev Server", risk: "low", reason: "Common development server port — should not be in production." },
];

const ALL_PORTS = [...SENSITIVE_PORTS, ...COMMON_PORTS];

export const scan: ScannerModule = async (targetUrl: string): Promise<VulnerabilityResult[]> => {
  const findings: VulnerabilityResult[] = [];
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  // SSRF guard: resolve once and probe the validated public IP only.
  let target: string;
  try {
    const ips = await resolveAndAssertPublic(hostname);
    target = ips[0];
  } catch {
    return findings;
  }

  // Scan all ports concurrently with controlled concurrency
  const concurrency = Math.min(
    Number(process.env.PORT_SCAN_CONCURRENCY) || 100,
    ALL_PORTS.length
  );
  const results: Array<{ port: PortEntry; open: boolean }> = [];

  for (let i = 0; i < ALL_PORTS.length; i += concurrency) {
    const batch = ALL_PORTS.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (port) => {
        const open = await probePort(target, port.port);
        return { port, open };
      })
    );
    results.push(...batchResults);
  }

  // Generate findings for open ports
  for (const { port, open } of results) {
    if (!open) continue;

    const severity = port.risk;

    findings.push({
      severity,
      category: "Open Ports",
      title: `Open port ${port.port} (${port.service})`,
      description: `Port ${port.port} (${port.service}) is open and reachable from the internet. ${port.reason}`,
      evidence: `TCP connection to ${hostname}:${port.port} succeeded`,
      remediation: getRemediation(port),
      cvssScore: severityToCvss(port.risk),
      affectedUrl: `${parsed.protocol}//${hostname}:${port.port}`,
    });
  }

  return findings;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function probePort(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timeout = Math.min(Number(process.env.PORT_SCAN_TIMEOUT_MS) || 750, 5000);

    socket.setTimeout(timeout);

    socket.connect(port, host, () => {
      socket.destroy();
      resolve(true);
    });

    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function getRemediation(port: PortEntry): string {
  if (["critical", "high"].includes(port.risk)) {
    return `Close port ${port.port} (${port.service}) at the firewall level. If the service is needed, restrict access via VPN, IP whitelist, or move it behind an authenticated reverse proxy.`;
  }
  if (port.risk === "medium") {
    return `Review whether port ${port.port} (${port.service}) needs to be publicly accessible. Apply access controls, encryption (TLS), and strong authentication.`;
  }
  return `Verify that port ${port.port} (${port.service}) exposure is intentional and properly secured with appropriate access controls.`;
}

function severityToCvss(severity: string): number {
  const map: Record<string, number> = {
    critical: 9.8,
    high: 7.5,
    medium: 5.3,
    low: 3.1,
    info: 0.0,
  };
  return map[severity] ?? 0.0;
}
