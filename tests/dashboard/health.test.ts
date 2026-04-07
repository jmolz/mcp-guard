import { describe, it, expect } from 'vitest';
import { buildHealthResponse, type HealthContext } from '../../src/dashboard/health.js';

function makeContext(overrides: Partial<HealthContext> = {}): HealthContext {
  return {
    startTime: Date.now() - 60_000, // 60 seconds ago
    getServerStatuses: () => new Map([['test', 'connected']]),
    getBridgeCount: () => 2,
    isDatabaseHealthy: () => true,
    getLastAuditWrite: () => '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('Health Endpoint', () => {
  it('returns healthy when all servers connected', () => {
    const ctx = makeContext();
    const health = buildHealthResponse(ctx);

    expect(health.status).toBe('healthy');
    expect(health.servers['test']).toBe('connected');
    expect(health.database).toBe('ok');
    expect(health.bridges).toBe(2);
  });

  it('returns degraded when some servers disconnected', () => {
    const ctx = makeContext({
      getServerStatuses: () => new Map([
        ['server1', 'connected'],
        ['server2', 'disconnected'],
      ]),
    });
    const health = buildHealthResponse(ctx);

    expect(health.status).toBe('degraded');
  });

  it('returns unhealthy when database error', () => {
    const ctx = makeContext({
      isDatabaseHealthy: () => false,
    });
    const health = buildHealthResponse(ctx);

    expect(health.status).toBe('unhealthy');
    expect(health.database).toBe('error');
  });

  it('includes correct uptime calculation', () => {
    const ctx = makeContext({ startTime: Date.now() - 120_000 });
    const health = buildHealthResponse(ctx);

    // Should be approximately 120 seconds
    expect(health.uptime_seconds).toBeGreaterThanOrEqual(119);
    expect(health.uptime_seconds).toBeLessThanOrEqual(121);
  });

  it('includes server status map', () => {
    const ctx = makeContext({
      getServerStatuses: () => new Map([
        ['s1', 'connected'],
        ['s2', 'error'],
      ]),
    });
    const health = buildHealthResponse(ctx);

    expect(health.servers).toEqual({ s1: 'connected', s2: 'error' });
  });

  it('includes bridge count', () => {
    const ctx = makeContext({ getBridgeCount: () => 5 });
    const health = buildHealthResponse(ctx);

    expect(health.bridges).toBe(5);
  });

  it('returns unhealthy when no servers', () => {
    const ctx = makeContext({
      getServerStatuses: () => new Map(),
    });
    const health = buildHealthResponse(ctx);

    expect(health.status).toBe('unhealthy');
  });
});
