import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { version: string };

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
    version: pkg.version,
  };
}
