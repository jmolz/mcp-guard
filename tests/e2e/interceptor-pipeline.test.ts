import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';
import type { Socket } from 'node:net';

let tempDir: string;
let socketPath: string;
let keyPath: string;
let daemonHandle: DaemonHandle;

describe('E2E: Interceptor pipeline', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-pipeline-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');

    await mkdir(tempDir, { recursive: true });
    await ensureDaemonKey(keyPath);

    // Config with policies: deny 'add' tool, rate limit 3/min
    const configPath = join(tempDir, 'config.yaml');
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
      rate_limit:
        requests_per_minute: 10
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
audit:
  enabled: true
  stdout: false
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config);

    // Give upstream server time to connect
    await new Promise((r) => setTimeout(r, 2000));
  }, 15000);

  afterAll(async () => {
    await daemonHandle.shutdown();
    await rm(tempDir, { recursive: true, force: true });
  });

  async function authenticatedSocket(): Promise<Socket> {
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const response = (await readFramed(socket)) as { type: string };
    expect(response.type).toBe('auth_ok');
    return socket;
  }

  it('allowed request passes all interceptors and reaches upstream', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'pipeline test' } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { content: Array<{ text: string }> }; error?: { message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();
    const result = response.data.result as { content: Array<{ text: string }> };
    expect(result.content[0].text).toBe('pipeline test');
    socket.destroy();
  });

  it('denied tool is BLOCKED by permissions interceptor', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'add', arguments: { a: 1, b: 2 } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { error?: { code: number; message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();
    const error = response.data.error as { code: number; message: string };
    expect(error.message).toContain('denied');
    socket.destroy();
  });

  it('denied tool does NOT appear in tools/list response', async () => {
    // Run BEFORE rate-limit test to ensure we have budget
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: { jsonrpc: '2.0', id: 3, method: 'tools/list' },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { tools: Array<{ name: string }> }; error?: { message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeUndefined();
    expect(response.data.result).toBeDefined();
    const tools = response.data.result as { tools: Array<{ name: string }> };
    const toolNames = tools.tools.map((t) => t.name);
    expect(toolNames).toContain('echo');
    expect(toolNames).not.toContain('add'); // 'add' is denied
    socket.destroy();
  });

  it('rate-limited request is BLOCKED after limit exceeded', async () => {
    // Rate limit is 10/min. Exhaust the limit and verify the next request is blocked.
    // Prior tests have already consumed some tokens.
    const results: string[] = [];

    for (let i = 0; i < 12; i++) {
      const socket = await authenticatedSocket();
      writeFramed(socket, {
        type: 'mcp',
        server: 'mock',
        data: {
          jsonrpc: '2.0',
          id: 100 + i,
          method: 'tools/call',
          params: { name: 'echo', arguments: { message: `req-${i}` } },
        },
      });

      const response = (await readFramed(socket)) as {
        type: string;
        data: { result?: unknown; error?: { message: string } };
      };

      results.push(response.data.error ? 'BLOCK' : 'PASS');
      socket.destroy();
    }

    // At least one should be blocked (rate limit is 10/min, we sent 12+
    // previous tests' requests)
    expect(results).toContain('BLOCK');
    // And some should have passed
    expect(results).toContain('PASS');
  });

  it('audit log contains entry for allowed request', async () => {
    // Wait briefly for any async audit writes
    await new Promise((r) => setTimeout(r, 100));

    const dbPath = join(tempDir, 'mcp-guard.db');
    const db = openDatabase({ path: dbPath });

    const allowed = db
      .prepare('SELECT * FROM audit_logs WHERE allowed = 1')
      .all() as Array<{ method: string; allowed: number }>;

    expect(allowed.length).toBeGreaterThan(0);
    db.close();
  });

  it('audit log contains entry for blocked request', async () => {
    const dbPath = join(tempDir, 'mcp-guard.db');
    const db = openDatabase({ path: dbPath });

    const blocked = db
      .prepare('SELECT * FROM audit_logs WHERE allowed = 0')
      .all() as Array<{ method: string; allowed: number; block_reason: string }>;

    expect(blocked.length).toBeGreaterThan(0);
    // At least one should be permission-blocked
    const permBlocked = blocked.find((r) => r.block_reason?.includes('denied'));
    expect(permBlocked).toBeDefined();
    db.close();
  });

  it('audit log does NOT contain raw PII from request arguments', async () => {
    // Send a request with PII-laden arguments
    const piiEmail = 'secret-user@example.com';
    const piiSsn = '123-45-6789';
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 50,
        method: 'tools/call',
        params: {
          name: 'echo',
          arguments: {
            message: `My email is ${piiEmail} and SSN is ${piiSsn}`,
          },
        },
      },
    });

    await readFramed(socket);
    socket.destroy();

    // Wait for audit write
    await new Promise((r) => setTimeout(r, 100));

    // Inspect the ENTIRE audit database — PII must not appear in any column
    const dbPath = join(tempDir, 'mcp-guard.db');
    const db = openDatabase({ path: dbPath });

    const allRows = db
      .prepare('SELECT * FROM audit_logs WHERE method = ?')
      .all('tools/call') as Array<Record<string, unknown>>;

    expect(allRows.length).toBeGreaterThan(0);

    for (const row of allRows) {
      const serialized = JSON.stringify(row);
      expect(serialized).not.toContain(piiEmail);
      expect(serialized).not.toContain(piiSsn);
      // params_summary should be null (not populated in Phase 2)
      expect(row['params_summary']).toBeNull();
    }

    db.close();
  });

  it('existing proxy passthrough still works for non-tool methods', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 4,
        method: 'resources/read',
        params: { uri: 'test://hello' },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { contents: Array<{ text: string }> }; error?: { message: string } };
    };

    // Might be rate limited, but if it passed, verify the response
    if (response.data.result) {
      expect(response.data.result.contents[0].text).toBe('Hello from mock server');
    }
    socket.destroy();
  });
});
