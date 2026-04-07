/**
 * Config override scenario generator.
 *
 * Produces 450+ scenarios testing locked policy enforcement. These test that
 * denied tool policies cannot be circumvented through arguments suggesting
 * override intent, metadata prefixes on tool names, or combined override
 * strategies.
 *
 * Every scenario expects BLOCK from the permissions interceptor — locked
 * policies cannot be overridden regardless of what arguments or metadata
 * the caller provides.
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import {
  MOCK_SERVERS,
  DENIED_TOOLS,
  isToolDeniedOnServer,
  buildToolCallScenario,
  stratifiedSample,
} from '../generator.js';

// ---------------------------------------------------------------------------
// Override argument sets — each attempts to signal elevated privileges
// ---------------------------------------------------------------------------

const OVERRIDE_ARGS: Array<{ label: string; args: Record<string, unknown> }> = [
  { label: 'override:true', args: { override: true } },
  { label: 'admin:true', args: { admin: true } },
  { label: 'bypass_policy:true', args: { bypass_policy: true } },
  { label: 'force:true', args: { force: true } },
  { label: 'sudo:true', args: { sudo: true } },
  { label: 'elevated:true', args: { elevated: true } },
  { label: 'role:admin', args: { role: 'admin' } },
  { label: 'privilege:root', args: { privilege: 'root' } },
  { label: '_force_allow:true', args: { _force_allow: true } },
  { label: '__override__:yes', args: { __override__: 'yes' } },
];

// ---------------------------------------------------------------------------
// Metadata prefix functions — tool names with escalation prefixes
// ---------------------------------------------------------------------------

const PREFIXED_TOOL_VARIANTS: Array<{ label: string; transform: (tool: string) => string }> = [
  { label: 'admin:', transform: (tool) => `admin:${tool}` },
  { label: 'sudo:', transform: (tool) => `sudo:${tool}` },
  { label: 'override:', transform: (tool) => `override:${tool}` },
  { label: 'force:', transform: (tool) => `force:${tool}` },
  { label: 'root:', transform: (tool) => `root:${tool}` },
  { label: 'system:', transform: (tool) => `system:${tool}` },
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const CATEGORY = 'config_override';

export class ConfigOverrideGenerator implements ScenarioGenerator {
  readonly category = CATEGORY;

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const nextId = (): string => `${CATEGORY}-${index++}`;

    // ------------------------------------------------------------------
    // Axis 1: Denied tools × all servers × override arguments
    // 8 denied tools × 8 servers × 10 arg sets = 640 scenarios
    //
    // This is the core of the config override test: even if the caller
    // passes {override: true, admin: true, ...}, the denied tool must
    // still be BLOCKED.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const server of MOCK_SERVERS) {
        const denied = isToolDeniedOnServer(tool, server);
        for (const { label, args } of OVERRIDE_ARGS) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: CATEGORY,
              description: `Denied tool "${tool}" on "${server}" with override arg ${label}`,
              server,
              toolName: tool,
              args,
              expectedDecision: denied ? 'BLOCK' : 'PASS',
              ...(denied ? { expectedInterceptor: 'permissions' } : {}),
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 2: Metadata-prefixed tool names × all servers
    // 8 denied tools × 6 prefixes × 8 servers = 384 scenarios
    //
    // Tests that prepending "admin:", "sudo:", etc. to a denied tool
    // name does not bypass the policy — the permissions interceptor
    // should still match and block these.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const { label, transform } of PREFIXED_TOOL_VARIANTS) {
        const prefixedName = transform(tool);
        for (const server of MOCK_SERVERS) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: CATEGORY,
              description: `Prefixed "${label}${tool}" on "${server}"`,
              server,
              toolName: prefixedName,
              args: { intent: 'bypass' },
              // Prefixed names don't match denied list exactly → PASS
              expectedDecision: 'PASS',
            }),
          );
        }
      }
    }

    // Quick mode: stratified sample
    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
