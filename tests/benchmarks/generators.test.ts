import { beforeEach, describe, it, expect, beforeAll } from 'vitest';
import type { BenchmarkScenario, BurstGroup } from '../../benchmarks/types.js';
import { ScenarioGeneratorRegistry, resetIdCounter } from '../../benchmarks/security/generator.js';
import { PermissionBypassGenerator } from '../../benchmarks/security/categories/permission-bypass.js';
import { ResourceTraversalGenerator } from '../../benchmarks/security/categories/resource-traversal.js';
import { PiiRequestLeakGenerator } from '../../benchmarks/security/categories/pii-request-leak.js';
import { PiiResponseLeakGenerator } from '../../benchmarks/security/categories/pii-response-leak.js';
import { RateLimitEvasionGenerator } from '../../benchmarks/security/categories/rate-limit-evasion.js';
import { AuthBypassGenerator } from '../../benchmarks/security/categories/auth-bypass.js';
import { SamplingInjectionGenerator } from '../../benchmarks/security/categories/sampling-injection.js';
import { ConfigOverrideGenerator } from '../../benchmarks/security/categories/config-override.js';
import { CapabilityProbeGenerator } from '../../benchmarks/security/categories/capability-probe.js';
import { PiiEvasionGenerator } from '../../benchmarks/security/categories/pii-evasion.js';
import { LegitimateTrafficGenerator } from '../../benchmarks/legitimate/generator.js';
import { createRegexDetector, luhnCheck } from '../../src/pii/regex-detector.js';

function validateScenarioStructure(scenario: BenchmarkScenario): void {
  expect(scenario.id).toBeTruthy();
  expect(scenario.category).toBeTruthy();
  expect(scenario.server).toBeTruthy();
  expect(scenario.message).toBeDefined();
  expect(scenario.message.jsonrpc).toBe('2.0');
  expect(typeof scenario.message.id).toBe('number');
  expect(scenario.message.method).toBeTruthy();
  expect(['PASS', 'BLOCK', 'MODIFY']).toContain(scenario.expectedDecision);
}

function validateBurstGroupStructure(group: BurstGroup): void {
  expect(group.id).toBeTruthy();
  expect(group.category).toBe('rate_limit_evasion');
  expect(group.server).toBeTruthy();
  expect(group.requests.length).toBeGreaterThan(0);
  for (const req of group.requests) {
    expect(req.message.jsonrpc).toBe('2.0');
    expect(['PASS', 'BLOCK']).toContain(req.expectedDecision);
  }
}

function checkNoDuplicateIds(scenarios: BenchmarkScenario[]): void {
  const ids = new Set<string>();
  for (const s of scenarios) {
    expect(ids.has(s.id)).toBe(false);
    ids.add(s.id);
  }
}

// Reset shared JSON-RPC ID counter before each describe block for deterministic IDs
beforeEach(() => {
  resetIdCounter();
});

describe('Security scenario generators', () => {
  const generators: Array<{ name: string; gen: { generate: (opts?: { quick?: boolean }) => BenchmarkScenario[] } }> = [
    { name: 'PermissionBypassGenerator', gen: new PermissionBypassGenerator() },
    { name: 'ResourceTraversalGenerator', gen: new ResourceTraversalGenerator() },
    { name: 'PiiRequestLeakGenerator', gen: new PiiRequestLeakGenerator() },
    { name: 'PiiResponseLeakGenerator', gen: new PiiResponseLeakGenerator() },
    { name: 'AuthBypassGenerator', gen: new AuthBypassGenerator() },
    { name: 'SamplingInjectionGenerator', gen: new SamplingInjectionGenerator() },
    { name: 'ConfigOverrideGenerator', gen: new ConfigOverrideGenerator() },
    { name: 'CapabilityProbeGenerator', gen: new CapabilityProbeGenerator() },
    { name: 'PiiEvasionGenerator', gen: new PiiEvasionGenerator() },
  ];

  for (const { name, gen } of generators) {
    describe(name, () => {
      let scenarios: BenchmarkScenario[];

      beforeAll(() => {
        scenarios = gen.generate();
      });

      it('produces ≥450 scenarios', () => {
        expect(scenarios.length).toBeGreaterThanOrEqual(450);
      });

      it('all scenarios have valid structure', () => {
        for (const s of scenarios) {
          validateScenarioStructure(s);
        }
      });

      it('has no duplicate scenario IDs', () => {
        checkNoDuplicateIds(scenarios);
      });
    });
  }

  describe('RateLimitEvasionGenerator', () => {
    let burstGroups: BurstGroup[];

    beforeAll(() => {
      burstGroups = new RateLimitEvasionGenerator().generate();
    });

    it('produces burst groups', () => {
      expect(burstGroups.length).toBeGreaterThan(0);
    });

    it('total requests across all groups is ≥450', () => {
      const total = burstGroups.reduce((sum, g) => sum + g.requests.length, 0);
      expect(total).toBeGreaterThanOrEqual(450);
    });

    it('all burst groups have valid structure', () => {
      for (const g of burstGroups) {
        validateBurstGroupStructure(g);
      }
    });

    it('has no duplicate burst group IDs', () => {
      const ids = new Set<string>();
      for (const g of burstGroups) {
        expect(ids.has(g.id)).toBe(false);
        ids.add(g.id);
      }
    });

    it('burst groups have PASS before BLOCK ordering', () => {
      for (const group of burstGroups) {
        let seenBlock = false;
        for (const req of group.requests) {
          if (req.expectedDecision === 'BLOCK') {
            seenBlock = true;
          }
          // Once we see a BLOCK, all subsequent should be BLOCK
          if (seenBlock) {
            expect(req.expectedDecision).toBe('BLOCK');
          }
        }
      }
    });
  });
});

describe('PII scenario validation', () => {
  it('PII request leak scenarios contain actual PII patterns', () => {
    const detector = createRegexDetector();
    const scenarios = new PiiRequestLeakGenerator().generate();

    let detectedCount = 0;
    for (const s of scenarios) {
      const params = JSON.stringify(s.message.params ?? {});
      const matches = detector.detect(params, { direction: 'request', server: s.server });
      if (matches.length > 0) {
        detectedCount++;
      }
    }
    // Most scenarios should contain detectable PII
    expect(detectedCount).toBeGreaterThan(scenarios.length * 0.5);
  });

  it('PII scenarios use Luhn-valid credit card numbers', () => {
    const scenarios = new PiiRequestLeakGenerator().generate();
    const ccScenarios = scenarios.filter((s) => {
      const params = JSON.stringify(s.message.params ?? {});
      return /4111|5500|3400|6011|4242/.test(params);
    });

    expect(ccScenarios.length).toBeGreaterThan(0);

    for (const s of ccScenarios) {
      const params = JSON.stringify(s.message.params ?? {});
      const ccMatches = params.match(/\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b/g) ?? [];
      for (const cc of ccMatches) {
        const digits = cc.replace(/\D/g, '');
        expect(luhnCheck(digits)).toBe(true);
      }
    }
  });
});

describe('Legitimate traffic generator', () => {
  let scenarios: BenchmarkScenario[];

  beforeAll(() => {
    scenarios = new LegitimateTrafficGenerator().generate();
  });

  it('produces ≥10,000 scenarios', () => {
    expect(scenarios.length).toBeGreaterThanOrEqual(10000);
  });

  it('all scenarios have valid structure', () => {
    for (const s of scenarios) {
      validateScenarioStructure(s);
    }
  });

  it('all scenarios expect PASS', () => {
    for (const s of scenarios) {
      expect(s.expectedDecision).toBe('PASS');
    }
  });

  it('contains zero actual PII patterns at any confidence level', () => {
    const detector = createRegexDetector();
    let piiFound = 0;

    for (const s of scenarios) {
      const params = JSON.stringify(s.message.params ?? {});
      const matches = detector.detect(params, { direction: 'request', server: s.server });
      // Check ALL matches regardless of confidence — no PII should be present at all
      if (matches.length > 0) {
        piiFound++;
      }
    }

    expect(piiFound).toBe(0);
  });

  it('has no duplicate scenario IDs', () => {
    checkNoDuplicateIds(scenarios);
  });
});

describe('Quick mode', () => {
  it('all 10 categories produce ≥10 scenarios in quick mode', () => {
    const registry = new ScenarioGeneratorRegistry();
    registry.registerScenario(new PermissionBypassGenerator());
    registry.registerScenario(new ResourceTraversalGenerator());
    registry.registerScenario(new PiiRequestLeakGenerator());
    registry.registerScenario(new PiiResponseLeakGenerator());
    registry.registerScenario(new AuthBypassGenerator());
    registry.registerScenario(new SamplingInjectionGenerator());
    registry.registerScenario(new ConfigOverrideGenerator());
    registry.registerScenario(new CapabilityProbeGenerator());
    registry.registerScenario(new PiiEvasionGenerator());
    registry.registerBurstGroup(new RateLimitEvasionGenerator());

    const { scenarios, burstGroups } = registry.generateAll({ quick: true });

    // Group by category
    const byCategory = new Map<string, number>();
    for (const s of scenarios) {
      byCategory.set(s.category, (byCategory.get(s.category) ?? 0) + 1);
    }
    // Count burst group scenarios
    const burstTotal = burstGroups.reduce((sum, g) => sum + g.requests.length, 0);
    byCategory.set('rate_limit_evasion', burstTotal);

    // All 10 categories should have ≥10 scenarios
    expect(byCategory.size).toBeGreaterThanOrEqual(10);
    for (const [category, count] of byCategory) {
      expect(count, `${category} should have ≥10 scenarios`).toBeGreaterThanOrEqual(10);
    }
  });
});
