import { describe, it, expect } from 'vitest';
import { createAuthInterceptor } from '../../src/interceptors/auth.js';
import type { InterceptorContext } from '../../src/interceptors/types.js';
import type { McpGuardConfig } from '../../src/config/schema.js';
import { configSchema } from '../../src/config/schema.js';

function makeConfig(overrides?: Record<string, unknown>): McpGuardConfig {
  return configSchema.parse({
    servers: { test: { command: 'echo', transport: 'stdio' } },
    ...overrides,
  });
}

function makeContext(overrides?: Partial<InterceptorContext>): InterceptorContext {
  return {
    message: { method: 'tools/call', params: { name: 'echo' } },
    server: 'test',
    identity: { uid: 1000, username: 'testuser', roles: ['default'] },
    direction: 'request',
    metadata: { bridgeId: 'bridge-1', timestamp: Date.now() },
    ...overrides,
  };
}

describe('Auth interceptor', () => {
  describe('OS mode', () => {
    it('passes with valid identity and roles', async () => {
      const config = makeConfig({ auth: { mode: 'os' } });
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(makeContext());
      expect(result.action).toBe('PASS');
    });

    it('passes identity with default role when no roles configured', async () => {
      const config = makeConfig({ auth: { mode: 'os' } });
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(
        makeContext({ identity: { uid: 1000, username: 'newuser', roles: ['default'] } }),
      );
      expect(result.action).toBe('PASS');
    });

    it('blocks identity with empty roles', async () => {
      const config = makeConfig({ auth: { mode: 'os' } });
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(
        makeContext({ identity: { uid: 1000, username: 'testuser', roles: [] } }),
      );
      expect(result.action).toBe('BLOCK');
    });
  });

  describe('API key mode', () => {
    const apiKeyConfig = {
      auth: {
        mode: 'api_key',
        api_keys: {
          'valid-key-123': { roles: ['admin'] },
          'readonly-key': { roles: ['reader'] },
        },
      },
    };

    it('passes with valid API key', async () => {
      const config = makeConfig(apiKeyConfig);
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(
        makeContext({
          message: { method: 'tools/call', params: { name: 'echo', _api_key: 'valid-key-123' } },
        }),
      );
      // MODIFY because it strips the _api_key from params
      expect(result.action).toBe('MODIFY');
      if (result.action === 'MODIFY') {
        expect(result.params).not.toHaveProperty('_api_key');
        expect(result.params).toHaveProperty('name', 'echo');
      }
    });

    it('blocks with invalid API key', async () => {
      const config = makeConfig(apiKeyConfig);
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(
        makeContext({
          message: { method: 'tools/call', params: { name: 'echo', _api_key: 'wrong-key' } },
        }),
      );
      expect(result.action).toBe('BLOCK');
      if (result.action === 'BLOCK') {
        expect(result.reason).toContain('Invalid API key');
      }
    });

    it('blocks with missing API key', async () => {
      const config = makeConfig(apiKeyConfig);
      const interceptor = createAuthInterceptor(config);

      const result = await interceptor.execute(
        makeContext({
          message: { method: 'tools/call', params: { name: 'echo' } },
        }),
      );
      expect(result.action).toBe('BLOCK');
      if (result.action === 'BLOCK') {
        expect(result.reason).toContain('not provided');
      }
    });
  });

  it('identity resolution failure → BLOCK (fail-closed)', async () => {
    const config = makeConfig({ auth: { mode: 'os' } });
    const interceptor = createAuthInterceptor(config);

    // Simulate missing identity fields
    const result = await interceptor.execute(
      makeContext({
        identity: { uid: 0, username: '', roles: ['default'] },
      }),
    );
    expect(result.action).toBe('BLOCK');
  });
});
