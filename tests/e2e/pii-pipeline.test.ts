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

describe('E2E: PII pipeline and sampling guard', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-pii-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');

    await mkdir(tempDir, { recursive: true });
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
    policy:
      permissions: {}
      sampling:
        enabled: false
pii:
  enabled: true
  confidence_threshold: 0.8
  actions:
    email:
      request: redact
      response: warn
    ssn:
      request: block
      response: redact
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

  it('request with email is redacted before reaching upstream', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'Contact user@example.com please' } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { content: Array<{ text: string }> }; error?: { message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();
    const result = response.data.result as { content: Array<{ text: string }> };
    // Echo server returns what it received — the redacted version
    expect(result.content[0].text).toContain('[REDACTED:email]');
    expect(result.content[0].text).not.toContain('user@example.com');
    socket.destroy();
  });

  it('request with SSN is BLOCKED (never reaches upstream)', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'SSN: 123-45-6789' } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { error?: { code: number; message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();
    const error = response.data.error as { code: number; message: string };
    expect(error.message).toContain('PII');
    // Error message must NOT contain the actual SSN
    expect(error.message).not.toContain('123-45-6789');
    socket.destroy();
  });

  it('audit log records PII type and action but NOT original value', async () => {
    await new Promise((r) => setTimeout(r, 200));

    const dbPath = join(tempDir, 'mcp-guard.db');
    const db = openDatabase({ path: dbPath });

    const rows = db
      .prepare('SELECT * FROM audit_logs')
      .all() as Array<Record<string, unknown>>;

    expect(rows.length).toBeGreaterThan(0);

    // Check ALL rows — no raw PII anywhere
    for (const row of rows) {
      const serialized = JSON.stringify(row);
      expect(serialized).not.toContain('user@example.com');
      expect(serialized).not.toContain('123-45-6789');
    }

    // Verify interceptor decisions column includes PII metadata
    const piiRows = rows.filter((r) => {
      const decisions = String(r['interceptor_decisions']);
      return decisions.includes('pii-detect');
    });
    expect(piiRows.length).toBeGreaterThan(0);

    // Verify metadata with PII detection details is persisted (type + action, never value)
    for (const row of piiRows) {
      const decisions = JSON.parse(String(row['interceptor_decisions'])) as Array<{
        name: string;
        metadata?: { piiDetections?: Array<{ type: string; action: string }> };
      }>;
      const piiDecision = decisions.find((d) => d.name === 'pii-detect');
      expect(piiDecision).toBeDefined();
      if (piiDecision?.metadata?.piiDetections) {
        for (const detection of piiDecision.metadata.piiDetections) {
          expect(detection.type).toBeDefined();
          expect(detection.action).toBeDefined();
          // Ensure no value field leaked into metadata
          expect(detection).not.toHaveProperty('value');
        }
      }
    }

    db.close();
  });

  it('sampling/createMessage is BLOCKED (sampling disabled)', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 3,
        method: 'sampling/createMessage',
        params: {
          messages: [{ role: 'user', content: { type: 'text', text: 'test' } }],
          maxTokens: 100,
        },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { error?: { code: number; message: string } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();
    const error = response.data.error as { message: string };
    expect(error.message).toContain('Sampling is disabled');
    socket.destroy();
  });

  it('regular tools/call still works (no regression)', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'hello world' } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { content: Array<{ text: string }> } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();
    const result = response.data.result as { content: Array<{ text: string }> };
    expect(result.content[0].text).toBe('hello world');
    socket.destroy();
  });

  it('request with no PII passes through cleanly', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'echo', arguments: { message: 'Just a normal message' } },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { content: Array<{ text: string }> } };
    };

    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();
    const result = response.data.result as { content: Array<{ text: string }> };
    expect(result.content[0].text).toBe('Just a normal message');
    socket.destroy();
  });
});
