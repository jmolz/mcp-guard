import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { createAuthInterceptor } from '../../src/interceptors/auth.js';
import type { InterceptorContext } from '../../src/interceptors/types.js';
import type { McpGuardConfig } from '../../src/config/schema.js';
import { configSchema } from '../../src/config/schema.js';

describe('Auth interceptor — OAuth mode', () => {
  let server: Server;
  let port: number;
  let privateKey: CryptoKey;

  const issuer = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    const keyPair = await generateKeyPair('RS256');
    privateKey = keyPair.privateKey as CryptoKey;
    const publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = 'test-key-1';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';

    server = createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ keys: [publicJwk] }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterAll(() => {
    server.close();
  });

  function makeConfig(overrides?: Record<string, unknown>): McpGuardConfig {
    return configSchema.parse({
      servers: { test: { command: 'echo', transport: 'stdio' } },
      auth: {
        mode: 'oauth',
        oauth: {
          issuer: issuer(),
          client_id: 'test-client',
          claims_to_roles: {
            claim_name: 'roles',
            mapping: {
              admin: ['admin'],
              viewer: ['reader'],
            },
          },
        },
      },
      ...overrides,
    });
  }

  function makeContext(overrides?: Partial<InterceptorContext>): InterceptorContext {
    return {
      message: { method: 'tools/call', params: { name: 'echo' } },
      server: 'test',
      identity: { uid: 1000, username: 'bridge-user', roles: ['default'] },
      direction: 'request',
      metadata: { bridgeId: 'bridge-1', timestamp: Date.now() },
      ...overrides,
    };
  }

  async function signJwt(claims: Record<string, unknown>): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject(claims['sub'] as string ?? 'test-user')
      .sign(privateKey);
  }

  it('valid OAuth token → MODIFY (strips _bearer_token, resolves roles)', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);
    const token = await signJwt({ sub: 'user-1', roles: ['admin'] });

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _bearer_token: token } },
      }),
    );

    expect(result.action).toBe('MODIFY');
    if (result.action === 'MODIFY') {
      expect(result.params).not.toHaveProperty('_bearer_token');
      expect(result.params).toHaveProperty('name', 'echo');
      expect(result.metadata?.['oauthSubject']).toBe('user-1');
      expect(result.metadata?.['roles']).toContain('admin');
    }
  });

  it('missing _bearer_token → BLOCK with OAUTH_TOKEN_MISSING', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo' } },
      }),
    );

    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('OAUTH_TOKEN_MISSING');
    }
  });

  it('expired token → BLOCK with OAUTH_INVALID_TOKEN', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);

    const token = await new SignJWT({ sub: 'expired-user' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject('expired-user')
      .sign(privateKey);

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _bearer_token: token } },
      }),
    );

    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('OAUTH_INVALID_TOKEN');
    }
  });

  it('valid token with claims mapping to multiple roles → MODIFY with all roles', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);
    const token = await signJwt({ sub: 'multi-role', roles: ['admin', 'viewer'] });

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _bearer_token: token } },
      }),
    );

    expect(result.action).toBe('MODIFY');
    if (result.action === 'MODIFY') {
      const roles = result.metadata?.['roles'] as string[];
      expect(roles).toContain('admin');
      expect(roles).toContain('reader');
    }
  });

  it('valid token with unmapped claims → BLOCK with OAUTH_NO_ROLES (fail-closed)', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);
    // JWT has roles: ['unknown_role'] which is not in the claims_to_roles mapping
    const token = await signJwt({ sub: 'unmapped-user', roles: ['unknown_role'] });

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _bearer_token: token } },
      }),
    );

    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('OAUTH_NO_ROLES');
    }
  });

  it('JWT signed with different key → BLOCK with OAUTH_INVALID_TOKEN', async () => {
    const config = makeConfig();
    const interceptor = createAuthInterceptor(config);

    // Sign with a DIFFERENT key pair (not the one served by the mock JWKS)
    const { privateKey: wrongKey } = await generateKeyPair('RS256');
    const badToken = await new SignJWT({ sub: 'attacker', roles: ['admin'] })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject('attacker')
      .sign(wrongKey);

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _bearer_token: badToken } },
      }),
    );

    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('OAUTH_INVALID_TOKEN');
    }
  });

  it('OS mode still works (no regression)', async () => {
    const config = configSchema.parse({
      servers: { test: { command: 'echo', transport: 'stdio' } },
      auth: { mode: 'os' },
    });
    const interceptor = createAuthInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('PASS');
  });

  it('API key mode still works (no regression)', async () => {
    const config = configSchema.parse({
      servers: { test: { command: 'echo', transport: 'stdio' } },
      auth: {
        mode: 'api_key',
        api_keys: { 'valid-key': { roles: ['admin'] } },
      },
    });
    const interceptor = createAuthInterceptor(config);

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'tools/call', params: { name: 'echo', _api_key: 'valid-key' } },
      }),
    );
    expect(result.action).toBe('MODIFY');
  });
});
