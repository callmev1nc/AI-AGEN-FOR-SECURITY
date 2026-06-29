/**
 * safe-fetch-pool.ts — HTTP agent pool keyed by validated IP.
 *
 * Agents are keyed by `(protocol, host, port, validatedIp)` so that a socket
 * only ever connects to one IP that passed SSRF validation. The pool lookup
 * happens *after* resolveAndAssertPublic runs, so C1 is maintained.
 *
 * Max sockets per agent is 6, staying below scanner fan-out (C3).
 */
import * as http from "http";
import * as https from "https";

interface AgentKey {
  protocol: "http:" | "https:";
  host: string;
  port: number;
  ip: string;
}

function agentKeyToString(key: AgentKey): string {
  return `${key.protocol}//${key.ip}:${key.port}__${key.host}`;
}

const agentPool = new Map<string, http.Agent | https.Agent>();

const AGENT_OPTIONS = {
  keepAlive: true,
  maxSockets: 6,
  timeout: 15000,
  keepAliveMsecs: 3000,
  scheduling: "lifo" as const,
};

export function getPoolAgent(protocol: string, host: string, port: number, ip: string): http.Agent | https.Agent {
  const key: AgentKey = {
    protocol: protocol as "http:" | "https:",
    host,
    port,
    ip,
  };
  const str = agentKeyToString(key);
  let agent = agentPool.get(str);
  if (!agent) {
    const isHttps = protocol === "https:";
    agent = isHttps
      ? new https.Agent({ ...AGENT_OPTIONS, servername: host })
      : new http.Agent(AGENT_OPTIONS);
    agentPool.set(str, agent);
  }
  return agent;
}

/**
 * Drain all pooled sockets and clear the pool. Called during testing or
 * graceful shutdown.
 */
export function drainPool(): void {
  for (const [, agent] of agentPool) {
    agent.destroy();
  }
  agentPool.clear();
}

export function poolSize(): number {
  return agentPool.size;
}
