import { describe, it, expect } from 'vitest';
import { createPermissionInterceptor } from '../../src/interceptors/permissions.js';
import { matchesAny } from '../../src/interceptors/permissions.js';
import { configSchema, type McpGuardConfig } from '../../src/config/schema.js';
import type { InterceptorContext } from '../../src/interceptors/types.js';

function makeConfig(policy?: Record<string, unknown>): McpGuardConfig {
  return configSchema.parse({
    servers: {
      test: {
        command: 'echo',
        transport: 'stdio',
        policy: policy ?? {},
      },
    },
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

describe('Permission interceptor', () => {
  it('allows tool when no permissions configured', async () => {
    const config = makeConfig();
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('PASS');
  });

  it('allows tool in allowed_tools list', async () => {
    const config = makeConfig({
      permissions: { allowed_tools: ['echo', 'add'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('PASS');
  });

  it('blocks tool in denied_tools list', async () => {
    const config = makeConfig({
      permissions: { denied_tools: ['echo'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('BLOCK');
  });

  it('blocks tool not in allowed_tools list', async () => {
    const config = makeConfig({
      permissions: { allowed_tools: ['add', 'multiply'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.reason).toContain('not in allowed list');
    }
  });

  it('wildcard match blocks (delete_*)', async () => {
    const config = makeConfig({
      permissions: { denied_tools: ['delete_*'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(
      makeContext({ message: { method: 'tools/call', params: { name: 'delete_user' } } }),
    );
    expect(result.action).toBe('BLOCK');
  });

  it('regex match blocks (^drop_.*$)', async () => {
    const config = makeConfig({
      permissions: { denied_tools: ['^drop_.*$'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(
      makeContext({ message: { method: 'tools/call', params: { name: 'drop_table' } } }),
    );
    expect(result.action).toBe('BLOCK');
  });

  it('deny wins over allow when both match', async () => {
    const config = makeConfig({
      permissions: {
        allowed_tools: ['echo'],
        denied_tools: ['echo'],
      },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(makeContext());
    expect(result.action).toBe('BLOCK');
  });

  it('non-tool method (resources/list) → PASS', async () => {
    const config = makeConfig({
      permissions: { denied_tools: ['echo'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(
      makeContext({ message: { method: 'resources/list' } }),
    );
    expect(result.action).toBe('PASS');
  });

  it('resource URI matching for resources/read', async () => {
    const config = makeConfig({
      permissions: { denied_resources: ['secret://*'] },
    });
    const interceptor = createPermissionInterceptor(config);

    const result = await interceptor.execute(
      makeContext({
        message: { method: 'resources/read', params: { uri: 'secret://passwords' } },
      }),
    );
    expect(result.action).toBe('BLOCK');
  });
});

describe('matchesAny', () => {
  it('exact match', () => {
    expect(matchesAny('echo', ['echo'])).toBe(true);
    expect(matchesAny('echo', ['add'])).toBe(false);
  });

  it('glob match', () => {
    expect(matchesAny('delete_user', ['delete_*'])).toBe(true);
    expect(matchesAny('create_user', ['delete_*'])).toBe(false);
  });

  it('regex match', () => {
    expect(matchesAny('drop_table', ['^drop_.*$'])).toBe(true);
    expect(matchesAny('create_table', ['^drop_.*$'])).toBe(false);
  });

  it('invalid regex does not throw', () => {
    expect(matchesAny('test', ['^[invalid'])).toBe(false);
  });
});
