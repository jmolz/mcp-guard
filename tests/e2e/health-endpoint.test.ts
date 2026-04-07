import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import type { HealthResponse } from '../../src/dashboard/health.js';

let tempDir: string;
let daemonHandle: DaemonHandle;

describe('E2E: Health endpoint', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-health-'));
    const socketPath = join(tempDir, 'daemon.sock');
    const keyPath = join(tempDir, 'daemon.key');

    await ensureDaemonKey(keyPath);

    const configPath = join(tempDir, 'config.yaml');
    await writeFile(
      configPath,
      `
servers:
  mock:
    transport: stdio
    command: npx
    args: ["tsx", "${mockServerPath}"]
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config, configPath);
    await new Promise((r) => setTimeout(r, 2000));
  }, 15000);

  afterAll(async () => {
    await daemonHandle.shutdown();
    await rm(tempDir, { recursive: true, force: true });
  });

  it('GET /healthz returns 200 with healthy status', async () => {
    const port = daemonHandle.getDashboardPort();
    const res = await fetch(`http://127.0.0.1:${port}/healthz`);

    expect(res.status).toBe(200);
    const body = await res.json() as HealthResponse;
    expect(body.status).toBe('healthy');
    expect(body.version).toBe('0.1.0');
    expect(body.database).toBe('ok');
    expect(body.servers).toHaveProperty('mock');
    expect(typeof body.uptime_seconds).toBe('number');
  });

  it('GET /api/status requires auth token', async () => {
    const port = daemonHandle.getDashboardPort();
    const res = await fetch(`http://127.0.0.1:${port}/api/status`);

    expect(res.status).toBe(401);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('Unauthorized');
  });

  it('GET /api/status with valid token returns detailed status', async () => {
    const port = daemonHandle.getDashboardPort();
    const token = daemonHandle.getDashboardToken();
    const res = await fetch(`http://127.0.0.1:${port}/api/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json() as HealthResponse;
    expect(body.status).toBe('healthy');
    expect(body.servers).toHaveProperty('mock');
  });

  it('GET /api/status with invalid token returns 401', async () => {
    const port = daemonHandle.getDashboardPort();
    const res = await fetch(`http://127.0.0.1:${port}/api/status`, {
      headers: { Authorization: 'Bearer wrong-token-here' },
    });

    expect(res.status).toBe(401);
  });
});
