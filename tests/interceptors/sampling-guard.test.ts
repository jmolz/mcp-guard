import { describe, it, expect } from 'vitest';
import { createSamplingGuardInterceptor } from '../../src/interceptors/sampling-guard.js';
import { configSchema, type McpGuardConfig } from '../../src/config/schema.js';
import type { InterceptorContext } from '../../src/interceptors/types.js';

function makeConfig(samplingEnabled?: boolean): McpGuardConfig {
  return configSchema.parse({
    servers: {
      test: {
        command: 'echo',
        transport: 'stdio',
        policy: {
          sampling: { enabled: samplingEnabled ?? false },
        },
      },
    },
  });
}

function makeCtx(method: string, server = 'test'): InterceptorContext {
  return {
    message: { method, params: {} },
    server,
    identity: { uid: 1000, username: 'testuser', roles: ['default'] },
    direction: 'request',
    metadata: { bridgeId: 'bridge-1', timestamp: Date.now() },
  };
}

describe('Sampling guard interceptor', () => {
  it('blocks sampling/createMessage when sampling.enabled is false', async () => {
    const interceptor = createSamplingGuardInterceptor(makeConfig(false));
    const result = await interceptor.execute(makeCtx('sampling/createMessage'));
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('SAMPLING_DISABLED');
      expect(result.reason).toContain('test');
    }
  });

  it('passes sampling/createMessage when sampling.enabled is true', async () => {
    const interceptor = createSamplingGuardInterceptor(makeConfig(true));
    const result = await interceptor.execute(makeCtx('sampling/createMessage'));
    expect(result.action).toBe('PASS');
  });

  it('passes non-sampling method (tools/call) regardless of config', async () => {
    const interceptor = createSamplingGuardInterceptor(makeConfig(false));
    const result = await interceptor.execute(makeCtx('tools/call'));
    expect(result.action).toBe('PASS');
  });

  it('passes non-sampling method (resources/read) regardless of config', async () => {
    const interceptor = createSamplingGuardInterceptor(makeConfig(false));
    const result = await interceptor.execute(makeCtx('resources/read'));
    expect(result.action).toBe('PASS');
  });

  it('blocks when server is missing from config (fail-closed)', async () => {
    const interceptor = createSamplingGuardInterceptor(makeConfig(false));
    const result = await interceptor.execute(makeCtx('sampling/createMessage', 'unknown_server'));
    expect(result.action).toBe('BLOCK');
  });

  it('blocks with default config (sampling not specified)', async () => {
    // Default sampling.enabled is false
    const config = configSchema.parse({
      servers: { test: { command: 'echo', transport: 'stdio' } },
    });
    const interceptor = createSamplingGuardInterceptor(config);
    const result = await interceptor.execute(makeCtx('sampling/createMessage'));
    expect(result.action).toBe('BLOCK');
  });
});
