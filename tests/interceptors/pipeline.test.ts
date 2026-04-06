import { describe, it, expect, vi } from 'vitest';
import { createPipeline } from '../../src/interceptors/pipeline.js';
import type {
  Interceptor,
  InterceptorContext,
  InterceptorDecision,
} from '../../src/interceptors/types.js';
import type { Logger } from '../../src/logger.js';

function mockLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

function makeContext(overrides?: Partial<InterceptorContext>): InterceptorContext {
  return {
    message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'hello' } } },
    server: 'test-server',
    identity: { uid: 1000, username: 'testuser', roles: ['default'] },
    direction: 'request',
    metadata: { bridgeId: 'bridge-1', timestamp: Date.now() },
    ...overrides,
  };
}

function passInterceptor(name: string): Interceptor {
  return {
    name,
    execute: vi.fn(async () => ({ action: 'PASS' }) as InterceptorDecision),
  };
}

function blockInterceptor(name: string, reason: string): Interceptor {
  return {
    name,
    execute: vi.fn(async () => ({ action: 'BLOCK', reason }) as InterceptorDecision),
  };
}

function modifyInterceptor(name: string, params: Record<string, unknown>): Interceptor {
  return {
    name,
    execute: vi.fn(async () => ({ action: 'MODIFY', params }) as InterceptorDecision),
  };
}

describe('Pipeline runner', () => {
  it('runs interceptors in order and returns all decisions', async () => {
    const i1 = passInterceptor('auth');
    const i2 = passInterceptor('rate-limit');
    const i3 = passInterceptor('permissions');

    const pipeline = createPipeline({
      interceptors: [i1, i2, i3],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(true);
    expect(result.decisions).toHaveLength(3);
    expect(result.decisions[0].interceptor).toBe('auth');
    expect(result.decisions[1].interceptor).toBe('rate-limit');
    expect(result.decisions[2].interceptor).toBe('permissions');

    expect(i1.execute).toHaveBeenCalledOnce();
    expect(i2.execute).toHaveBeenCalledOnce();
    expect(i3.execute).toHaveBeenCalledOnce();
  });

  it('short-circuits on BLOCK — remaining interceptors NOT called', async () => {
    const i1 = passInterceptor('auth');
    const i2 = blockInterceptor('rate-limit', 'Rate limit exceeded');
    const i3 = passInterceptor('permissions');

    const pipeline = createPipeline({
      interceptors: [i1, i2, i3],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(false);
    expect(result.decisions).toHaveLength(2);
    expect(result.decisions[1].decision).toEqual({ action: 'BLOCK', reason: 'Rate limit exceeded' });

    expect(i1.execute).toHaveBeenCalledOnce();
    expect(i2.execute).toHaveBeenCalledOnce();
    expect(i3.execute).not.toHaveBeenCalled();
  });

  it('MODIFY decision updates params for next interceptor', async () => {
    const i1 = modifyInterceptor('modifier', { extra: 'value' });
    const i2: Interceptor = {
      name: 'checker',
      execute: vi.fn(async (ctx) => {
        // Verify params were modified by previous interceptor
        expect(ctx.message.params?.['extra']).toBe('value');
        return { action: 'PASS' };
      }),
    };

    const pipeline = createPipeline({
      interceptors: [i1, i2],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(true);
    expect(result.finalParams).toMatchObject({ extra: 'value' });
    expect(i2.execute).toHaveBeenCalledOnce();
  });

  it('interceptor throw → BLOCK result (fail-closed)', async () => {
    const thrower: Interceptor = {
      name: 'bad-interceptor',
      execute: vi.fn(async () => {
        throw new Error('Something went wrong');
      }),
    };
    const i2 = passInterceptor('after');

    const pipeline = createPipeline({
      interceptors: [thrower, i2],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(false);
    expect(result.decisions).toHaveLength(1);
    expect(result.decisions[0].decision.action).toBe('BLOCK');
    expect(i2.execute).not.toHaveBeenCalled();
  });

  it('interceptor timeout → BLOCK result (fail-closed)', async () => {
    const slowInterceptor: Interceptor = {
      name: 'slow',
      execute: vi.fn(() => new Promise(() => {
        // Never resolves
      })),
    };

    const pipeline = createPipeline({
      interceptors: [slowInterceptor],
      timeout: 50, // 50ms timeout
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(false);
    expect(result.decisions).toHaveLength(1);
    expect(result.decisions[0].decision.action).toBe('BLOCK');
    expect((result.decisions[0].decision as { reason: string }).reason).toContain('timed out');
  });

  it('empty interceptor list → PASS', async () => {
    const pipeline = createPipeline({
      interceptors: [],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(true);
    expect(result.decisions).toHaveLength(0);
  });

  it('multiple MODIFY decisions compose correctly', async () => {
    const i1 = modifyInterceptor('first', { a: 1 });
    const i2 = modifyInterceptor('second', { b: 2 });

    const pipeline = createPipeline({
      interceptors: [i1, i2],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(true);
    expect(result.finalParams).toMatchObject({ a: 1, b: 2 });
  });

  it('MODIFY attempting to change method is rejected → BLOCK', async () => {
    const badModifier: Interceptor = {
      name: 'evil',
      execute: vi.fn(async () => ({
        action: 'MODIFY' as const,
        params: { name: 'dangerous-tool-override' },
      })),
    };

    const pipeline = createPipeline({
      interceptors: [badModifier],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.allowed).toBe(false);
    expect(result.decisions[0].decision.action).toBe('BLOCK');
    expect((result.decisions[0].decision as { reason: string }).reason).toContain('protected fields');
  });

  it('timing info recorded for each interceptor', async () => {
    const i1: Interceptor = {
      name: 'slow-pass',
      execute: async () => {
        await new Promise((r) => setTimeout(r, 20));
        return { action: 'PASS' };
      },
    };

    const pipeline = createPipeline({
      interceptors: [i1],
      timeout: 5000,
      logger: mockLogger(),
    });

    const result = await pipeline.execute(makeContext());

    expect(result.decisions[0].durationMs).toBeGreaterThanOrEqual(15);
  });
});
