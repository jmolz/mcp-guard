import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer, type Server } from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
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
let jwksServer: Server;
let jwksPort: number;
let privateKey: CryptoKey;

describe('E2E: OAuth authentication flow', () => {
  const mockServerPath = join(import.meta.dirname, '..', 'fixtures', 'mock-mcp-server.ts');

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-oauth-e2e-'));
    socketPath = join(tempDir, 'daemon.sock');
    keyPath = join(tempDir, 'daemon.key');

    await mkdir(tempDir, { recursive: true });
    await ensureDaemonKey(keyPath);

    // 1. Set up mock JWKS server
    const keyPair = await generateKeyPair('RS256');
    privateKey = keyPair.privateKey as CryptoKey;
    const publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = 'e2e-key-1';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';

    jwksServer = createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ keys: [publicJwk] }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => {
      jwksServer.listen(0, '127.0.0.1', () => {
        const addr = jwksServer.address();
        jwksPort = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });

    const issuer = `http://127.0.0.1:${jwksPort}`;

    // 2. Write config with OAuth mode
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
      rate_limit:
        requests_per_minute: 30
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
auth:
  mode: oauth
  oauth:
    issuer: "${issuer}"
    client_id: e2e-test-client
    claims_to_roles:
      claim_name: roles
      mapping:
        admin:
          - admin
        viewer:
          - reader
  roles:
    admin:
      permissions:
        allowed_tools:
          - "*"
      rate_limit:
        requests_per_minute: 100
    reader:
      permissions:
        denied_tools:
          - "delete_*"
      rate_limit:
        requests_per_minute: 30
audit:
  enabled: true
  stdout: false
`,
    );

    const config = await loadConfig(configPath);
    daemonHandle = await startDaemon(config);

    await new Promise((r) => setTimeout(r, 2000));
  }, 15000);

  afterAll(async () => {
    await daemonHandle.shutdown();
    jwksServer.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  function issuer(): string {
    return `http://127.0.0.1:${jwksPort}`;
  }

  async function signJwt(claims: Record<string, unknown>): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'e2e-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer(issuer())
      .setAudience('e2e-test-client')
      .setSubject(claims['sub'] as string ?? 'e2e-user')
      .sign(privateKey);
  }

  async function authenticatedSocket(): Promise<Socket> {
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const response = (await readFramed(socket)) as { type: string };
    expect(response.type).toBe('auth_ok');
    return socket;
  }

  it('valid OAuth token → request reaches upstream, response returns', async () => {
    const socket = await authenticatedSocket();
    const token = await signJwt({ sub: 'e2e-user-1', roles: ['admin'] });

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hello' }, _bearer_token: token },
      },
    });

    const response = (await readFramed(socket)) as { type: string; data: { result?: unknown; error?: unknown } };
    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();
    expect(response.data.error).toBeUndefined();

    socket.destroy();
  });

  it('invalid OAuth token → request blocked', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hello' }, _bearer_token: 'invalid-token' },
      },
    });

    const response = (await readFramed(socket)) as { type: string; data: { error?: { message: string } } };
    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();
    expect(response.data.error!.message).toContain('JWT validation failed');

    socket.destroy();
  });

  it('expired OAuth token → request blocked', async () => {
    const socket = await authenticatedSocket();

    const expiredToken = await new SignJWT({ sub: 'expired-user' })
      .setProtectedHeader({ alg: 'RS256', kid: 'e2e-key-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .setIssuer(issuer())
      .setAudience('e2e-test-client')
      .setSubject('expired-user')
      .sign(privateKey);

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hello' }, _bearer_token: expiredToken },
      },
    });

    const response = (await readFramed(socket)) as { type: string; data: { error?: { message: string } } };
    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();

    socket.destroy();
  });

  it('missing OAuth token → request blocked', async () => {
    const socket = await authenticatedSocket();

    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hello' } },
      },
    });

    const response = (await readFramed(socket)) as { type: string; data: { error?: { message: string } } };
    expect(response.type).toBe('mcp');
    expect(response.data.error).toBeDefined();
    expect(response.data.error!.message).toContain('OAuth token required');

    socket.destroy();
  });

  it('_bearer_token is stripped from params before forwarding upstream', async () => {
    const socket = await authenticatedSocket();
    const token = await signJwt({ sub: 'strip-test', roles: ['admin'] });

    // The echo tool in the mock server returns its arguments, which allows us to verify
    // that _bearer_token is NOT present in the upstream request
    writeFramed(socket, {
      type: 'mcp',
      server: 'mock',
      data: {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'test' }, _bearer_token: token },
      },
    });

    const response = (await readFramed(socket)) as {
      type: string;
      data: { result?: { content?: Array<{ text?: string }> } };
    };
    expect(response.type).toBe('mcp');
    expect(response.data.result).toBeDefined();

    // The result shouldn't contain any trace of the bearer token
    const resultStr = JSON.stringify(response.data.result);
    expect(resultStr).not.toContain('_bearer_token');
    expect(resultStr).not.toContain(token);

    socket.destroy();
  });

  it('audit log does not contain bearer tokens or JWT values', async () => {
    // After the previous tests, check audit store for token leaks
    const dbPath = join(tempDir, 'mcp-guard.db');
    const db = openDatabase({ path: dbPath });

    try {
      const rows = db.prepare('SELECT * FROM audit_logs').all() as Array<Record<string, unknown>>;
      expect(rows.length).toBeGreaterThan(0); // Ensure we actually have audit rows to check

      for (const row of rows) {
        const rowStr = JSON.stringify(row);
        // Check 1: The _bearer_token key must not appear
        expect(rowStr).not.toContain('_bearer_token');
        // Check 2: No JWT-like values — header/payload segments (eyJ prefix)
        expect(rowStr).not.toMatch(/eyJ[A-Za-z0-9_-]{20,}/);
        // Check 3: No long base64url sequences that could be JWT signatures
        // Skip this check on fields that legitimately contain long values (e.g., bridge IDs, timestamps)
        const decisionsStr = typeof row['interceptor_decisions'] === 'string' ? row['interceptor_decisions'] : '';
        const blockReason = typeof row['block_reason'] === 'string' ? row['block_reason'] : '';
        expect(decisionsStr).not.toMatch(/[A-Za-z0-9_-]{40,}/);
        expect(blockReason).not.toMatch(/[A-Za-z0-9_-]{40,}/);
      }
    } finally {
      db.close();
    }
  });
});
