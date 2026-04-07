import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

function loadVersion(): string {
  // Walk up from the current file (or bundled dist/) to find package.json
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      const content = readFileSync(join(dir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(content) as { version?: string };
      if (pkg.version) return pkg.version;
    } catch {
      // Not found at this level, go up
    }
    dir = dirname(dir);
  }
  return '0.0.0';
}

const VERSION = loadVersion();

export interface HealthContext {
  startTime: number;
  getServerStatuses: () => Map<string, string>;
  getBridgeCount: () => number;
  isDatabaseHealthy: () => boolean;
  getLastAuditWrite: () => string | null;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime_seconds: number;
  servers: Record<string, string>;
  bridges: number;
  database: 'ok' | 'error';
  last_audit_write: string | null;
  version: string;
}

export function buildHealthResponse(ctx: HealthContext): HealthResponse {
  const serverStatuses = ctx.getServerStatuses();
  const dbHealthy = ctx.isDatabaseHealthy();
  const servers: Record<string, string> = {};

  for (const [name, status] of serverStatuses) {
    servers[name] = status;
  }

  const serverValues = [...serverStatuses.values()];
  const allConnected = serverValues.length > 0 && serverValues.every((s) => s === 'connected');
  const noneConnected = serverValues.length === 0 || serverValues.every((s) => s !== 'connected');

  let status: HealthResponse['status'];
  if (!dbHealthy || noneConnected) {
    status = 'unhealthy';
  } else if (allConnected) {
    status = 'healthy';
  } else {
    status = 'degraded';
  }

  return {
    status,
    uptime_seconds: Math.floor((Date.now() - ctx.startTime) / 1000),
    servers,
    bridges: ctx.getBridgeCount(),
    database: dbHealthy ? 'ok' : 'error',
    last_audit_write: ctx.getLastAuditWrite(),
    version: VERSION,
  };
}
