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

// ---------------------------------------------------------------------------
// Expected decision spot-checks — 5 per category, manually verified ground truth.
// These prevent regressions in expectedDecision logic (the root cause of #13).
// ---------------------------------------------------------------------------

/**
 * Find a scenario by description substring. Throws if not found (fail-fast).
 */
function findScenario(scenarios: BenchmarkScenario[], descSubstring: string): BenchmarkScenario {
  const match = scenarios.find((s) => s.description.includes(descSubstring));
  if (!match) throw new Error(`No scenario matching "${descSubstring}"`);
  return match;
}

describe('Expected decision spot-checks', () => {
  // ---- permission_bypass ----
  describe('permission_bypass decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new PermissionBypassGenerator().generate(); });

    it('BLOCK: denied tool on its owning server', () => {
      const s = findScenario(scenarios, '"delete_file" called on owning server "filesystem"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('BLOCK: denied tool on server that denies it (cross-server)', () => {
      const s = findScenario(scenarios, '"drop_table" attempted on server "database"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: denied tool on server that does NOT deny it', () => {
      const s = findScenario(scenarios, '"delete_file" attempted on server "api-client"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: case variant (UPPER) of denied tool', () => {
      const s = findScenario(scenarios, 'Case bypass "UPPER" for "delete_file"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: prefix trick on denied tool', () => {
      const s = findScenario(scenarios, 'Prefix trick "admin-colon" for "delete_file"');
      expect(s.expectedDecision).toBe('PASS');
    });
  });

  // ---- resource_traversal ----
  describe('resource_traversal decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new ResourceTraversalGenerator().generate(); });

    it('BLOCK: traversal URI matching denied resource on filesystem', () => {
      // filesystem denies file://../../* and file://../*
      const s = scenarios.find((s) =>
        s.server === 'filesystem' && s.expectedDecision === 'BLOCK',
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('BLOCK');
    });
    it('PASS: traversal URI on server with no denied resources', () => {
      const s = scenarios.find((s) =>
        s.server === 'database' && s.description.includes('traversal'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
    it('has both BLOCK and PASS scenarios', () => {
      const blocks = scenarios.filter((s) => s.expectedDecision === 'BLOCK').length;
      const passes = scenarios.filter((s) => s.expectedDecision === 'PASS').length;
      expect(blocks).toBeGreaterThan(0);
      expect(passes).toBeGreaterThan(0);
    });
  });

  // ---- pii_request_leak ----
  describe('pii_request_leak decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new PiiRequestLeakGenerator().generate(); });

    it('BLOCK: SSN in request args', () => {
      const s = findScenario(scenarios, 'ssn PII (direct value)');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('BLOCK: credit_card in request args', () => {
      const s = findScenario(scenarios, 'credit_card PII (direct value)');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('MODIFY: email on echoing tool (filesystem:read_file:path)', () => {
      const s = scenarios.find((s) =>
        s.description.includes('email PII (direct value) in read_file on filesystem'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('MODIFY');
    });
    it('PASS: email on non-echoing tool', () => {
      const s = scenarios.find((s) =>
        s.description.includes('email PII (direct value) in git_clone on git-ops'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
    it('PASS: phone on non-echoing tool', () => {
      const s = scenarios.find((s) =>
        s.description.includes('phone PII (direct value) in install_package on shell'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
  });

  // ---- pii_response_leak ----
  describe('pii_response_leak decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new PiiResponseLeakGenerator().generate(); });

    it('all scenarios expect MODIFY (response PII always redacted)', () => {
      for (const s of scenarios) {
        expect(s.expectedDecision, s.description).toBe('MODIFY');
      }
    });
  });

  // ---- auth_bypass ----
  describe('auth_bypass decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new AuthBypassGenerator().generate(); });

    it('PASS: valid tool with invalid API key in OS mode', () => {
      const s = findScenario(scenarios, 'invalid _api_key "empty-string"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: valid tool with invalid bearer token in OS mode', () => {
      const s = findScenario(scenarios, 'invalid _bearer_token "expired-looking"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('BLOCK: tools/call without name (malformed)', () => {
      const s = findScenario(scenarios, 'tools/call without name');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('BLOCK: injection tool name with / (path-traversal)', () => {
      const s = findScenario(scenarios, 'Injection tool name "path-traversal"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: injection tool name without / (__proto__)', () => {
      const s = findScenario(scenarios, 'Injection tool name "prototype-pollution"');
      expect(s.expectedDecision).toBe('PASS');
    });
  });

  // ---- sampling_injection ----
  describe('sampling_injection decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new SamplingInjectionGenerator().generate(); });

    it('BLOCK: sampling request on non-sampling server', () => {
      const s = findScenario(scenarios, 'Blocked server: "short-hello" prompt on "filesystem"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: sampling request on sampling-server', () => {
      const s = findScenario(scenarios, 'Passing server: "short-hello" prompt on "sampling-server"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('majority are BLOCK (7/8 servers block sampling)', () => {
      const blocks = scenarios.filter((s) => s.expectedDecision === 'BLOCK').length;
      expect(blocks).toBeGreaterThan(scenarios.length * 0.5);
    });
  });

  // ---- config_override ----
  describe('config_override decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new ConfigOverrideGenerator().generate(); });

    it('BLOCK: denied tool on owning server with override arg', () => {
      const s = findScenario(scenarios, '"delete_file" on "filesystem" with override arg override:true');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: denied tool on server that does not deny it, with override arg', () => {
      const s = findScenario(scenarios, '"delete_file" on "api-client" with override arg');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: prefixed denied tool name (admin:delete_file)', () => {
      const s = findScenario(scenarios, 'Prefixed "admin:delete_file"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('BLOCK: denied tool on owning server with sudo arg', () => {
      const s = findScenario(scenarios, '"drop_table" on "database" with override arg sudo:true');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: denied tool on non-denying server with admin arg', () => {
      const s = findScenario(scenarios, '"run_command" on "filesystem" with override arg admin:true');
      expect(s.expectedDecision).toBe('PASS');
    });
  });

  // ---- capability_probe ----
  describe('capability_probe decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new CapabilityProbeGenerator().generate(); });

    it('BLOCK: denied tool probed on owning server', () => {
      const s = findScenario(scenarios, '"delete_file" probed on "filesystem"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
    it('PASS: denied tool probed on non-denying server', () => {
      const s = findScenario(scenarios, '"delete_file" probed on "api-client"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: non-existent tool', () => {
      const s = findScenario(scenarios, 'Non-existent tool "hack_system"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('PASS: near-miss tool name', () => {
      const s = findScenario(scenarios, 'Near-miss tool "delete_files"');
      expect(s.expectedDecision).toBe('PASS');
    });
    it('BLOCK: empty tool name edge case', () => {
      const s = findScenario(scenarios, 'Edge case "empty"');
      expect(s.expectedDecision).toBe('BLOCK');
    });
  });

  // ---- pii_evasion ----
  describe('pii_evasion decisions', () => {
    let scenarios: BenchmarkScenario[];
    beforeAll(() => { scenarios = new PiiEvasionGenerator().generate(); });

    it('PASS: homoglyph Cyrillic-e on email (value changed, evades regex)', () => {
      const s = scenarios.find((s) =>
        s.description.includes('homoglyph-cyrillic-e email'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
    it('PASS: base64 encoded PII (evades regex)', () => {
      const s = scenarios.find((s) =>
        s.description.includes('base64-encoded email'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
    it('BLOCK: nested JSON with SSN (detected, block type)', () => {
      const s = scenarios.find((s) =>
        s.description.includes('nested-json-1-level ssn'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('BLOCK');
    });
    it('PASS: offset-10k padding (word boundary evasion)', () => {
      const s = scenarios.find((s) =>
        s.description.includes('offset-10k email'),
      );
      expect(s).toBeDefined();
      expect(s!.expectedDecision).toBe('PASS');
    });
    it('detected technique on digit-only PII still detects (value unchanged)', () => {
      // Cyrillic-e on SSN "123-45-6789" — no 'e' chars, value unchanged → detected
      const s = scenarios.find((s) =>
        s.description.includes('homoglyph-cyrillic-e ssn') && s.server === 'filesystem',
      );
      expect(s).toBeDefined();
      // SSN is a block type, value unchanged → detected → BLOCK
      expect(s!.expectedDecision).toBe('BLOCK');
    });
  });

  // ---- rate_limit_evasion (burst groups) ----
  describe('rate_limit_evasion decisions', () => {
    let burstGroups: BurstGroup[];
    beforeAll(() => { burstGroups = new RateLimitEvasionGenerator().generate(); });

    it('burst groups have PASS requests before BLOCK requests', () => {
      for (const group of burstGroups) {
        let seenBlock = false;
        for (const req of group.requests) {
          if (req.expectedDecision === 'BLOCK') seenBlock = true;
          if (seenBlock) {
            expect(req.expectedDecision, `${group.description}`).toBe('BLOCK');
          }
        }
      }
    });
    it('each burst group contains at least one BLOCK', () => {
      for (const group of burstGroups) {
        const hasBlock = group.requests.some((r) => r.expectedDecision === 'BLOCK');
        expect(hasBlock, `${group.id} should have ≥1 BLOCK`).toBe(true);
      }
    });
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
