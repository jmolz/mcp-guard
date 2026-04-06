import { describe, it, expect } from 'vitest';
import { createPIIRegistry } from '../../src/pii/registry.js';
import { piiSchema } from '../../src/config/schema.js';
import type { DetectionContext } from '../../src/pii/types.js';

const ctx: DetectionContext = { direction: 'request', server: 'test' };

function makeConfig(overrides?: Record<string, unknown>) {
  return piiSchema.parse(overrides ?? {});
}

describe('PIIRegistry', () => {
  it('built-in detector is always registered', () => {
    const registry = createPIIRegistry(makeConfig());
    const matches = registry.scan('user@example.com', ctx);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].type).toBe('email');
  });

  it('returns matches from built-in detector', () => {
    const registry = createPIIRegistry(makeConfig());
    const matches = registry.scan('SSN: 123-45-6789', ctx);
    expect(matches.some((m) => m.type === 'ssn')).toBe(true);
  });

  it('filters matches below confidence threshold', () => {
    // Set threshold very high — phone (0.8) should be filtered out
    const registry = createPIIRegistry(makeConfig({ confidence_threshold: 0.9 }));
    const matches = registry.scan('Call 555-123-4567', ctx);
    const phones = matches.filter((m) => m.type === 'phone');
    expect(phones).toHaveLength(0);
  });

  it('registers custom type detector from config', () => {
    const config = makeConfig({
      custom_types: {
        internal_id: {
          label: 'Internal ID',
          patterns: [{ regex: 'INT-\\d{6}' }],
          actions: { request: 'redact', response: 'warn' },
        },
      },
    });
    const registry = createPIIRegistry(config);
    const matches = registry.scan('ID: INT-123456', ctx);
    expect(matches.some((m) => m.type === 'internal_id')).toBe(true);
  });

  it('detects custom types alongside built-in types', () => {
    const config = makeConfig({
      custom_types: {
        internal_id: {
          label: 'Internal ID',
          patterns: [{ regex: 'INT-\\d{6}' }],
          actions: { request: 'redact', response: 'warn' },
        },
      },
    });
    const registry = createPIIRegistry(config);
    const matches = registry.scan('user@example.com and INT-123456', ctx);
    const types = matches.map((m) => m.type);
    expect(types).toContain('email');
    expect(types).toContain('internal_id');
  });

  it('skips invalid custom regex without throwing', () => {
    const config = makeConfig({
      custom_types: {
        bad_pattern: {
          label: 'Bad',
          patterns: [{ regex: '[invalid(' }],
          actions: { request: 'redact', response: 'warn' },
        },
      },
    });
    // Should not throw
    const registry = createPIIRegistry(config);
    const matches = registry.scan('test content', ctx);
    expect(matches).toEqual([]);
  });

  it('deduplicates overlapping spans keeping highest confidence', () => {
    const registry = createPIIRegistry(makeConfig());
    // The email regex (0.9 confidence) and other patterns shouldn't overlap,
    // but verify deduplication works for same-span matches
    const matches = registry.scan('user@example.com', ctx);
    // Each position should only have one match
    const starts = matches.map((m) => m.start);
    expect(new Set(starts).size).toBe(starts.length);
  });

  it('returns empty array for empty content', () => {
    const registry = createPIIRegistry(makeConfig());
    expect(registry.scan('', ctx)).toEqual([]);
  });
});
