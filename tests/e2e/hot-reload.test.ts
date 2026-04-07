import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';

let tempDir: string;
let daemonHandle: DaemonHandle | undefined;

const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

describe('E2E: Hot config reload', () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-hotreload-'));
  });

  afterEach(async () => {
    if (daemonHandle) {
      await daemonHandle.shutdown();
      daemonHandle = undefined;
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it('change policy (add denied_tool) — next request blocked', async () => {
    const socketPath = join(tempDir, 'daemon.sock');
    const keyPath = join(tempDir, 'daemon.key');
    const configPath = join(tempDir, 'config.yaml');

    await ensureDaemonKey(keyPath);

    // Start with no denied tools
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

    // Connect bridge
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const authResp = await readFramed(socket) as { type: string };
    expect(authResp.type).toBe('auth_ok');

    // First request should succeed (add tool is allowed)
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'add', arguments: { a: 1, b: 2 } } },
    });
    const resp1 = await readFramed(socket) as { type: string; data: { result?: unknown } };
    expect(resp1.data.result).toBeDefined();

    // Now update config to deny 'add' tool
    await writeFile(
      configPath,
      `
servers:
  mock:
    transport: stdio
    command: npx
    args: ["tsx", "${mockServerPath}"]
    policy:
      permissions:
        denied_tools:
          - add
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`,
    );

    // Wait for hot reload (debounce 250ms + reload time)
    await new Promise((r) => setTimeout(r, 1000));

    // Second request should be blocked
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'add', arguments: { a: 1, b: 2 } } },
    });
    const resp2 = await readFramed(socket) as { type: string; data: { error?: { message: string } } };
    expect(resp2.data.error).toBeDefined();
    expect(resp2.data.error!.message).toContain('denied');

    socket.destroy();
  }, 20000);

  it('invalid config change — previous config stays active', async () => {
    const socketPath = join(tempDir, 'daemon.sock');
    const keyPath = join(tempDir, 'daemon.key');
    const configPath = join(tempDir, 'config.yaml');

    await ensureDaemonKey(keyPath);

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

    // Write invalid config
    await writeFile(configPath, 'this is not valid yaml: [[[');

    // Wait for hot reload to process (and reject)
    await new Promise((r) => setTimeout(r, 1000));

    // Daemon should still be running and healthy
    const port = daemonHandle.getDashboardPort();
    const res = await fetch(`http://127.0.0.1:${port}/healthz`);
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string };
    expect(body.status).toBe('healthy');
  }, 15000);
});
