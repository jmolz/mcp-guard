import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { computeSha256 } from '../../src/config/fetcher.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';

let tempDir: string;
let httpServer: Server;
let httpPort: number;
let daemonHandle: DaemonHandle | undefined;

function startHttpServer(content: string): Promise<number> {
  return new Promise((resolve) => {
    httpServer = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/yaml' });
      res.end(content);
    });
    httpServer.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
  });
}

function stopHttpServer(): Promise<void> {
  return new Promise((resolve) => {
    if (httpServer) {
      httpServer.close(() => resolve());
    } else {
      resolve();
    }
  });
}

const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

describe('E2E: Config extends', () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-extends-'));
  });

  afterEach(async () => {
    if (daemonHandle) {
      await daemonHandle.shutdown();
      daemonHandle = undefined;
    }
    await stopHttpServer();
    await rm(tempDir, { recursive: true, force: true });
  });

  it('daemon starts with extends config — base policies applied', async () => {
    const socketPath = join(tempDir, 'daemon.sock');
    const keyPath = join(tempDir, 'daemon.key');

    // Base config served over HTTP
    const baseYaml = `servers:
  mock:
    transport: stdio
    command: npx
    args: ["tsx", "${mockServerPath}"]
    policy:
      permissions:
        denied_tools:
          - dangerous_tool
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`;
    const baseHash = computeSha256(baseYaml);
    httpPort = await startHttpServer(baseYaml);

    // Personal config extends the base
    const personalConfigPath = join(tempDir, 'config.yaml');
    await writeFile(
      personalConfigPath,
      `extends:
  url: "http://127.0.0.1:${httpPort}/base.yaml"
  sha256: "${baseHash}"
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

    await ensureDaemonKey(keyPath);
    const config = await loadConfig(personalConfigPath);
    daemonHandle = await startDaemon(config, personalConfigPath);
    await new Promise((r) => setTimeout(r, 2000));

    // Connect bridge and try to call the denied tool
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const authResp = await readFramed(socket) as { type: string };
    expect(authResp.type).toBe('auth_ok');

    // Try to call a tool that's denied in base config
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'dangerous_tool', arguments: {} },
      },
    });

    const resp = await readFramed(socket) as { type: string; data: { error?: { message: string } } };
    expect(resp.type).toBe('mcp');
    expect(resp.data.error).toBeDefined();
    expect(resp.data.error!.message).toContain('denied');

    socket.destroy();
  }, 15000);

  it('NEGATIVE: hash mismatch — daemon refuses to start', async () => {
    const socketPath = join(tempDir, 'daemon.sock');

    const baseYaml = `servers:
  mock:
    command: echo
`;
    httpPort = await startHttpServer(baseYaml);

    const personalConfigPath = join(tempDir, 'config.yaml');
    await writeFile(
      personalConfigPath,
      `extends:
  url: "http://127.0.0.1:${httpPort}/base.yaml"
  sha256: "${'a'.repeat(64)}"
servers:
  mock:
    command: echo
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  dashboard_port: 0
`,
    );

    await expect(loadConfig(personalConfigPath)).rejects.toThrow('SHA-256 mismatch');
  }, 10000);

  it('personal config tightens base policies — denied_tools merged', async () => {
    const socketPath = join(tempDir, 'daemon.sock');
    const keyPath = join(tempDir, 'daemon.key');

    const baseYaml = `servers:
  mock:
    transport: stdio
    command: npx
    args: ["tsx", "${mockServerPath}"]
    policy:
      permissions:
        denied_tools:
          - delete_tool
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`;
    const baseHash = computeSha256(baseYaml);
    httpPort = await startHttpServer(baseYaml);

    const personalConfigPath = join(tempDir, 'config.yaml');
    await writeFile(
      personalConfigPath,
      `extends:
  url: "http://127.0.0.1:${httpPort}/base.yaml"
  sha256: "${baseHash}"
servers:
  mock:
    transport: stdio
    command: npx
    args: ["tsx", "${mockServerPath}"]
    policy:
      permissions:
        denied_tools:
          - drop_tool
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`,
    );

    await ensureDaemonKey(keyPath);
    const config = await loadConfig(personalConfigPath);

    // Both denied tools should be in the merged config (union)
    expect(config.servers['mock'].policy.permissions.denied_tools).toContain('delete_tool');
    expect(config.servers['mock'].policy.permissions.denied_tools).toContain('drop_tool');
  }, 10000);
});
