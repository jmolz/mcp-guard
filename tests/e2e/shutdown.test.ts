import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon } from '../../src/daemon/index.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';

let tempDir: string;
let socketPath: string;
let keyPath: string;
let pidFile: string;

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

describe('E2E: Graceful shutdown', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-shutdown-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');
    pidFile = join(tempDir, 'daemon.pid');
    const dbPath = join(tempDir, 'mcp-guard.db');

    await mkdir(tempDir, { recursive: true });

    // Patch constants for test isolation
    const constantsModule = await import('../../src/constants.js');
    Object.defineProperty(constantsModule, 'DEFAULT_SOCKET_PATH', { value: socketPath });
    Object.defineProperty(constantsModule, 'DEFAULT_DAEMON_KEY_PATH', { value: keyPath });
    Object.defineProperty(constantsModule, 'DEFAULT_DB_PATH', { value: dbPath });
    Object.defineProperty(constantsModule, 'DEFAULT_PID_FILE', { value: pidFile });
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('shuts down cleanly — socket removed, PID file removed, no errors', async () => {
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
    const daemonHandle = await startDaemon(config);

    // Give upstream time to connect
    await new Promise((r) => setTimeout(r, 2000));

    // Verify daemon is running
    expect(await fileExists(socketPath)).toBe(true);
    expect(await fileExists(pidFile)).toBe(true);

    // Shutdown
    await daemonHandle.shutdown();

    // Verify cleanup
    expect(await fileExists(socketPath)).toBe(false);
    expect(await fileExists(pidFile)).toBe(false);
  }, 15000);

  it('notifies connected bridges on shutdown', async () => {
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
    const daemonHandle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 2000));

    // Connect a bridge
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const authResp = (await readFramed(socket)) as { type: string };
    expect(authResp.type).toBe('auth_ok');

    // Trigger shutdown — bridge should receive shutdown message
    const shutdownMsgPromise = readFramed(socket, 5000).catch(() => null);
    await daemonHandle.shutdown();

    const msg = (await shutdownMsgPromise) as { type: string; reason: string } | null;
    expect(msg).not.toBeNull();
    if (msg) {
      expect(msg.type).toBe('shutdown');
      expect(msg.reason).toBe('daemon stopping');
    }

    socket.destroy();
  }, 15000);

  it('calling shutdown twice is idempotent — no double-close errors', async () => {
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
    const daemonHandle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 2000));

    // Call shutdown twice — should not throw
    await daemonHandle.shutdown();
    await daemonHandle.shutdown();

    expect(await fileExists(socketPath)).toBe(false);
    expect(await fileExists(pidFile)).toBe(false);
  }, 15000);
});
