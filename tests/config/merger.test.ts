import { describe, it, expect } from 'vitest';
import { mergeConfigs } from '../../src/config/merger.js';
import { configSchema, type McpGuardConfig } from '../../src/config/schema.js';

/** Create a minimal valid config for testing */
function makeConfig(overrides: Record<string, unknown> = {}): McpGuardConfig {
  const raw = {
    servers: {
      test: {
        command: 'echo',
        args: ['hello'],
      },
    },
    ...overrides,
  };
  return configSchema.parse(raw);
}

describe('Config Merger — Floor-based merge', () => {
  // --- Happy path ---

  it('merges two simple configs (no conflicts)', () => {
    const base = makeConfig();
    const personal = makeConfig();
    const merged = mergeConfigs(base, personal);

    expect(merged.servers['test']).toBeDefined();
    expect(merged.servers['test'].command).toBe('echo');
  });

  it('personal config adds new server to base servers', () => {
    const base = makeConfig();
    const personal = makeConfig({
      servers: {
        test: { command: 'echo' },
        extra: { command: 'extra-cmd', args: [] },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test']).toBeDefined();
    expect(merged.servers['extra']).toBeDefined();
    expect(merged.servers['extra'].command).toBe('extra-cmd');
  });

  it('allowed_tools intersection narrows access', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { allowed_tools: ['read', 'write', 'delete'] } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { allowed_tools: ['read', 'write'] } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test'].policy.permissions.allowed_tools).toEqual(['read', 'write']);
  });

  it('denied_tools union expands denials', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { denied_tools: ['delete'] } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { denied_tools: ['drop'] } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test'].policy.permissions.denied_tools).toContain('delete');
    expect(merged.servers['test'].policy.permissions.denied_tools).toContain('drop');
  });

  it('rate_limit takes stricter (lower) value', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { rate_limit: { requests_per_minute: 100 } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { rate_limit: { requests_per_minute: 50 } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test'].policy.rate_limit.requests_per_minute).toBe(50);
  });

  it('PII custom_types additive (personal adds new type)', () => {
    const base = makeConfig({
      pii: {
        custom_types: {
          base_type: {
            label: 'Base Type',
            patterns: [{ regex: 'base-\\d+' }],
            actions: { request: 'redact', response: 'warn' },
          },
        },
      },
    });
    const personal = makeConfig({
      pii: {
        custom_types: {
          personal_type: {
            label: 'Personal Type',
            patterns: [{ regex: 'personal-\\d+' }],
            actions: { request: 'warn', response: 'warn' },
          },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.pii.custom_types['base_type']).toBeDefined();
    expect(merged.pii.custom_types['personal_type']).toBeDefined();
  });

  it('PII actions escalate (warn → block)', () => {
    const base = makeConfig({
      pii: { actions: { email: { request: 'warn', response: 'warn' } } },
    });
    const personal = makeConfig({
      pii: { actions: { email: { request: 'block', response: 'redact' } } },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.pii.actions['email'].request).toBe('block');
    expect(merged.pii.actions['email'].response).toBe('redact');
  });

  it('sampling: personal cannot enable if base disables', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { sampling: { enabled: false } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { sampling: { enabled: true } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test'].policy.sampling.enabled).toBe(false);
  });

  // --- NEGATIVE tests (MUST prove fail-closed) ---

  it('NEGATIVE: personal cannot relax denied_tools (remove base denial)', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { denied_tools: ['delete', 'drop'] } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { denied_tools: [] } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    // Union means base denials are preserved
    expect(merged.servers['test'].policy.permissions.denied_tools).toContain('delete');
    expect(merged.servers['test'].policy.permissions.denied_tools).toContain('drop');
  });

  it('NEGATIVE: personal cannot expand allowed_tools beyond base', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { allowed_tools: ['read'] } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { permissions: { allowed_tools: ['read', 'write', 'delete'] } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    // Intersection means only 'read' survives
    expect(merged.servers['test'].policy.permissions.allowed_tools).toEqual(['read']);
  });

  it('NEGATIVE: personal cannot increase rate_limit above base', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { rate_limit: { requests_per_minute: 50 } },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: { rate_limit: { requests_per_minute: 200 } },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    // Min(50, 200) = 50 — base is stricter
    expect(merged.servers['test'].policy.rate_limit.requests_per_minute).toBe(50);
  });

  it('NEGATIVE: locked policy ignores personal overrides entirely', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: {
            locked: true,
            permissions: { denied_tools: ['delete'] },
            rate_limit: { requests_per_minute: 10 },
          },
        },
      },
    });
    const personal = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: {
            permissions: { denied_tools: [] },
            rate_limit: { requests_per_minute: 1000 },
          },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    // Locked: base policy is used as-is
    expect(merged.servers['test'].policy.permissions.denied_tools).toEqual(['delete']);
    expect(merged.servers['test'].policy.rate_limit.requests_per_minute).toBe(10);
    expect(merged.servers['test'].policy.locked).toBe(true);
  });

  it('NEGATIVE: personal cannot raise PII confidence_threshold', () => {
    const base = makeConfig({
      pii: { confidence_threshold: 0.7 },
    });
    const personal = makeConfig({
      pii: { confidence_threshold: 0.9 },
    });

    const merged = mergeConfigs(base, personal);
    // Lower is stricter — min(0.7, 0.9) = 0.7
    expect(merged.pii.confidence_threshold).toBe(0.7);
  });

  it('NEGATIVE: personal cannot relax PII action (block → warn)', () => {
    const base = makeConfig({
      pii: { actions: { email: { request: 'block', response: 'redact' } } },
    });
    const personal = makeConfig({
      pii: { actions: { email: { request: 'warn', response: 'warn' } } },
    });

    const merged = mergeConfigs(base, personal);
    // Higher severity wins — block > warn, redact > warn
    expect(merged.pii.actions['email'].request).toBe('block');
    expect(merged.pii.actions['email'].response).toBe('redact');
  });

  it('NEGATIVE: personal cannot remove base PII custom_types', () => {
    const base = makeConfig({
      pii: {
        custom_types: {
          internal_id: {
            label: 'Internal ID',
            patterns: [{ regex: 'ID-\\d+' }],
            actions: { request: 'redact', response: 'warn' },
          },
        },
      },
    });
    const personal = makeConfig({
      pii: { custom_types: {} },
    });

    const merged = mergeConfigs(base, personal);
    // Additive — base types cannot be removed
    expect(merged.pii.custom_types['internal_id']).toBeDefined();
  });

  it('NEGATIVE: personal cannot weaken base PII custom_type patterns or actions', () => {
    const base = makeConfig({
      pii: {
        custom_types: {
          internal_id: {
            label: 'Internal ID',
            patterns: [{ regex: 'ID-\\d+' }, { regex: 'INTERNAL-\\d+' }],
            actions: { request: 'block', response: 'redact' },
          },
        },
      },
    });
    const personal = makeConfig({
      pii: {
        custom_types: {
          internal_id: {
            label: 'Weakened ID',
            // Tries to replace with a single weaker pattern and lower actions
            patterns: [{ regex: 'never-match' }],
            actions: { request: 'warn', response: 'warn' },
          },
        },
      },
    });

    const merged = mergeConfigs(base, personal);
    const mergedType = merged.pii.custom_types['internal_id'];
    // Label preserved from base
    expect(mergedType.label).toBe('Internal ID');
    // Base patterns preserved (union, not replacement)
    expect(mergedType.patterns.some((p) => p.regex === 'ID-\\d+')).toBe(true);
    expect(mergedType.patterns.some((p) => p.regex === 'INTERNAL-\\d+')).toBe(true);
    // Personal pattern added (union)
    expect(mergedType.patterns.some((p) => p.regex === 'never-match')).toBe(true);
    // Actions cannot be relaxed — block > warn, redact > warn
    expect(mergedType.actions.request).toBe('block');
    expect(mergedType.actions.response).toBe('redact');
  });

  it('NEGATIVE: personal cannot change auth config', () => {
    const base = makeConfig({
      auth: { mode: 'os' },
    });
    const personal = makeConfig({
      auth: { mode: 'api_key' },
    });

    const merged = mergeConfigs(base, personal);
    // Base wins for auth
    expect(merged.auth.mode).toBe('os');
  });

  it('NEGATIVE: personal cannot change daemon config', () => {
    const base = makeConfig({
      daemon: { log_level: 'warn', dashboard_port: 9777 },
    });
    const personal = makeConfig({
      daemon: { log_level: 'debug', dashboard_port: 1234 },
    });

    const merged = mergeConfigs(base, personal);
    // Base wins for daemon
    expect(merged.daemon.log_level).toBe('warn');
    expect(merged.daemon.dashboard_port).toBe(9777);
  });

  it('base config with no personal overrides returns base unchanged', () => {
    const base = makeConfig({
      servers: {
        test: {
          command: 'echo',
          policy: {
            permissions: { denied_tools: ['delete'] },
            rate_limit: { requests_per_minute: 50 },
          },
        },
      },
    });
    const personal = makeConfig();

    const merged = mergeConfigs(base, personal);
    expect(merged.servers['test'].policy.permissions.denied_tools).toEqual(['delete']);
    expect(merged.servers['test'].policy.rate_limit.requests_per_minute).toBe(50);
  });
});
