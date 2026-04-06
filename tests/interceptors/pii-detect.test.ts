import { describe, it, expect } from 'vitest';
import { createPiiInterceptor } from '../../src/interceptors/pii-detect.js';
import { createPIIRegistry, type PIIRegistry } from '../../src/pii/registry.js';
import { configSchema, type McpGuardConfig } from '../../src/config/schema.js';
import type { InterceptorContext } from '../../src/interceptors/types.js';

function makeConfig(overrides?: { pii?: Record<string, unknown>; servers?: Record<string, unknown> }): McpGuardConfig {
  return configSchema.parse({
    servers: overrides?.servers ?? {
      test: { command: 'echo', transport: 'stdio' },
    },
    pii: overrides?.pii ?? {},
  });
}

function makeCtx(overrides?: Partial<InterceptorContext>): InterceptorContext {
  return {
    message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'hello' } } },
    server: 'test',
    identity: { uid: 1000, username: 'testuser', roles: ['default'] },
    direction: 'request',
    metadata: { bridgeId: 'bridge-1', timestamp: Date.now() },
    ...overrides,
  };
}

describe('PII detection interceptor — request direction', () => {
  it('passes when no PII in params', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const result = await interceptor.execute(makeCtx());
    expect(result.action).toBe('PASS');
  });

  it('returns MODIFY with redacted params when action is redact', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'Email: user@example.com' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('MODIFY');
    if (result.action === 'MODIFY') {
      const args = result.params['arguments'] as Record<string, unknown>;
      expect(args['text']).toContain('[REDACTED:email]');
      expect(args['text']).not.toContain('user@example.com');
    }
  });

  it('returns BLOCK when action is block (SSN in request)', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'SSN: 123-45-6789' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.reason).toContain('ssn');
      // MUST NOT contain the actual SSN value
      expect(result.reason).not.toContain('123-45-6789');
    }
  });

  it('returns PASS with metadata when action is warn', async () => {
    const config = makeConfig({
      pii: {
        actions: {
          email: { request: 'warn', response: 'warn' },
        },
      },
    });
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'user@example.com' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('PASS');
    expect(result.metadata?.['piiDetections']).toBeDefined();
  });

  it('strictest action wins — block > redact > warn', async () => {
    // Email is redact, SSN is block → block should win
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: {
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'user@test.com SSN: 123-45-6789' } },
      },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('passes when PII disabled in config', async () => {
    const config = makeConfig({ pii: { enabled: false } });
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'SSN: 123-45-6789' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('PASS');
  });
});

describe('PII detection interceptor — response direction', () => {
  it('passes when no PII in response', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      direction: 'response',
      message: { method: 'tools/call', params: { content: [{ type: 'text', text: 'hello' }] } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('PASS');
  });

  it('returns MODIFY when response PII action is redact', async () => {
    // SSN response action is 'redact' by default
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      direction: 'response',
      message: { method: 'tools/call', params: { content: [{ type: 'text', text: 'SSN: 123-45-6789' }] } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('MODIFY');
  });

  it('returns BLOCK when response PII action is block', async () => {
    const config = makeConfig({
      pii: {
        actions: {
          email: { request: 'redact', response: 'block' },
        },
      },
    });
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      direction: 'response',
      message: { method: 'tools/call', params: { text: 'user@example.com' } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('returns PASS with metadata when response action is warn', async () => {
    // Email response action is 'warn' by default
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      direction: 'response',
      message: { method: 'tools/call', params: { text: 'user@example.com' } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('PASS');
    expect(result.metadata?.['piiDetections']).toBeDefined();
  });
});

describe('PII detection interceptor — fail-closed', () => {
  it('returns BLOCK when detector throws', async () => {
    const config = makeConfig();
    // Create a registry that throws on scan
    const throwingRegistry: PIIRegistry = {
      scan() { throw new Error('Detector failure'); },
    };
    const interceptor = createPiiInterceptor(throwingRegistry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'test' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('PII_DETECTOR_ERROR');
    }
  });
});

describe('PII detection interceptor — size guard', () => {
  it('blocks content exceeding 1MB (fail-closed)', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    // Create params exceeding 1MB
    const largeText = 'x'.repeat(1_100_000);
    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: largeText } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.code).toBe('PII_CONTENT_TOO_LARGE');
    }
  });
});

describe('PII detection interceptor — custom type actions', () => {
  it('uses custom type actions from config instead of fallback defaults', async () => {
    const config = makeConfig({
      pii: {
        custom_types: {
          internal_id: {
            label: 'Internal ID',
            patterns: [{ regex: 'INT-\\d{6}' }],
            actions: { request: 'block', response: 'block' },
          },
        },
      },
    });
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'ID: INT-123456' } } },
    });

    const result = await interceptor.execute(ctx);
    // Custom type has request: 'block', so it should BLOCK (not fallback redact)
    expect(result.action).toBe('BLOCK');
    if (result.action === 'BLOCK') {
      expect(result.reason).toContain('internal_id');
    }
  });
});

describe('PII detection interceptor — metadata safety', () => {
  it('metadata never includes original PII values', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'user@example.com' } } },
    });

    const result = await interceptor.execute(ctx);
    const metadataStr = JSON.stringify(result.metadata);
    expect(metadataStr).not.toContain('user@example.com');
  });

  it('MODIFY decision params do not contain original PII values', async () => {
    const config = makeConfig();
    const registry = createPIIRegistry(config.pii);
    const interceptor = createPiiInterceptor(registry, config);

    const ctx = makeCtx({
      message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'user@example.com' } } },
    });

    const result = await interceptor.execute(ctx);
    expect(result.action).toBe('MODIFY');
    if (result.action === 'MODIFY') {
      const paramsStr = JSON.stringify(result.params);
      expect(paramsStr).not.toContain('user@example.com');
    }
  });
});
