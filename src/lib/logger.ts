const isDev = process.env.NODE_ENV === "development";

function formatTimestamp(): string {
  return new Date().toISOString();
}

function devPrint(level: string, namespace: string, message: string, meta?: unknown) {
  const prefix = `[${formatTimestamp()}] [${level}] [${namespace}]`;
  if (meta !== undefined) {
    console.log(`${prefix} ${message}`, meta);
  } else {
    console.log(`${prefix} ${message}`);
  }
}

function prodPrint(level: string, namespace: string, message: string, meta?: unknown) {
  const entry = JSON.stringify({
    timestamp: formatTimestamp(),
    level,
    namespace,
    message,
    ...(meta !== undefined ? { meta } : {}),
  });
  if (level === "ERROR") {
    console.error(entry);
  } else if (level === "WARN") {
    console.warn(entry);
  } else {
    console.log(entry);
  }
}

function log(level: string, namespace: string, message: string, meta?: unknown) {
  if (isDev) {
    devPrint(level, namespace, message, meta);
  } else {
    prodPrint(level, namespace, message, meta);
  }
}

export const logger = {
  info: (namespace: string, message: string, meta?: unknown) => log("INFO", namespace, message, meta),
  warn: (namespace: string, message: string, meta?: unknown) => log("WARN", namespace, message, meta),
  error: (namespace: string, message: string, meta?: unknown) => log("ERROR", namespace, message, meta),
};
