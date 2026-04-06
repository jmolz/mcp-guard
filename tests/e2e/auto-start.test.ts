import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, type ChildProcess } from 'node:child_process';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { isDaemonRunning } from '../../src/daemon/auto-start.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';

let tempDir: string;
let socketPath: string;
let keyPath: string;

/** Poll until daemon socket is available, up to maxWait ms */
async function waitForDaemon(path: string, maxWait = 5000): Promise<boolean> {
  const interval = 200;
  let waited = 0;
  while (waited < maxWait) {
    if (await isDaemonRunning(path)) return true;
    await new Promise((r) => setTimeout(r, interval));
    waited += interval;
  }
  return false;
}

describe('E2E: Daemon auto-start detection', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');
  let daemonHandle: DaemonHandle | undefined;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-autostart-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');
    const dbPath = join(tempDir, 'mcp-guard.db');
    const pidFile = join(tempDir, 'daemon.pid');

    await mkdir(tempDir, { recursive: true });

    const constantsModule = await import('../../src/constants.js');
    Object.defineProperty(constantsModule, 'DEFAULT_SOCKET_PATH', { value: socketPath });
    Object.defineProperty(constantsModule, 'DEFAULT_DAEMON_KEY_PATH', { value: keyPath });
    Object.defineProperty(constantsModule, 'DEFAULT_DB_PATH', { value: dbPath });
    Object.defineProperty(constantsModule, 'DEFAULT_PID_FILE', { value: pidFile });
  });

  afterEach(async () => {
    if (daemonHandle) {
      await daemonHandle.shutdown();
      daemonHandle = undefined;
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it('isDaemonRunning returns false when no daemon is running', async () => {
    expect(await isDaemonRunning(socketPath)).toBe(false);
  });

  it('isDaemonRunning returns true when daemon is running', async () => {
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
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 1000));

    expect(await isDaemonRunning(socketPath)).toBe(true);
  }, 10000);

  it('isDaemonRunning returns false after daemon shuts down', async () => {
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
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 1000));

    expect(await isDaemonRunning(socketPath)).toBe(true);

    await daemonHandle.shutdown();
    daemonHandle = undefined;

    expect(await isDaemonRunning(socketPath)).toBe(false);
  }, 15000);

  it('bridge connects after daemon starts — simulates auto-start flow', async () => {
    expect(await isDaemonRunning(socketPath)).toBe(false);

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
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config);
    await new Promise((r) => setTimeout(r, 2000));

    expect(await isDaemonRunning(socketPath)).toBe(true);

    // Bridge connects and authenticates
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const response = (await readFramed(socket)) as { type: string };
    expect(response.type).toBe('auth_ok');

    // Bridge can proxy messages
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    });

    const mcpResp = (await readFramed(socket)) as {
      type: string;
      data: { result: { tools: Array<{ name: string }> } };
    };
    expect(mcpResp.type).toBe('mcp');
    expect(mcpResp.data.result.tools.map((t) => t.name)).toContain('echo');

    socket.destroy();
  }, 15000);
});

describe('E2E: Daemon process spawn (real auto-start flow)', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');
  const cliPath = join(import.meta.dirname, '..', '..', 'src', 'cli.ts');
  let daemonProc: ChildProcess | undefined;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-procstart-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');
    await mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    if (daemonProc && !daemonProc.killed) {
      daemonProc.kill('SIGTERM');
      // Wait briefly for cleanup
      await new Promise((r) => setTimeout(r, 500));
      if (!daemonProc.killed) daemonProc.kill('SIGKILL');
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it('spawns daemon process and bridge connects successfully', async () => {
    const dbPath = join(tempDir, 'mcp-guard.db');
    const pidFile = join(tempDir, 'daemon.pid');

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
`,
    );

    // Spawn daemon as a real child process (mirrors what autoStartDaemon does)
    daemonProc = spawn('npx', ['tsx', cliPath, 'start', '--config', configPath], {
      stdio: 'ignore',
      detached: true,
      env: {
        ...process.env,
        MCP_GUARD_TEST_SOCKET: socketPath,
        MCP_GUARD_TEST_KEY: keyPath,
        MCP_GUARD_TEST_DB: dbPath,
        MCP_GUARD_TEST_PID: pidFile,
      },
    });
    daemonProc.unref();

    // Wait for daemon socket to become available (same polling as autoStartDaemon)
    const started = await waitForDaemon(socketPath, 10000);
    expect(started).toBe(true);

    // Bridge connects and authenticates — proves full auto-start flow works
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const response = (await readFramed(socket)) as { type: string };
    expect(response.type).toBe('auth_ok');

    // Bridge can proxy MCP messages
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    });

    const mcpResp = (await readFramed(socket)) as {
      type: string;
      data: { result: { tools: Array<{ name: string }> } };
    };
    expect(mcpResp.type).toBe('mcp');
    expect(mcpResp.data.result.tools.map((t) => t.name)).toContain('echo');

    socket.destroy();
  }, 20000);
});
