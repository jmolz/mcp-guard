/**
 * Permission bypass scenario generator.
 *
 * Produces 450+ scenarios that attempt to call denied tools through various
 * evasion techniques: case manipulation, whitespace injection, null bytes,
 * unicode tricks, prefix namespacing, cross-server calls, and argument
 * variations.
 *
 * Expected decisions are per-server: a tool is only BLOCKed on servers
 * where it is actually denied (per DENIED_TOOLS_PER_SERVER). Evasion
 * techniques (case changes, injection, prefixes) produce non-exact names
 * that never match the denied list, so they always expect PASS.
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import { DENIED_TOOLS, MOCK_SERVERS, buildToolCallScenario, isToolDeniedOnServer, stratifiedSample } from '../generator.js';

// ---------------------------------------------------------------------------
// Denied tools mapped to their owning servers
// ---------------------------------------------------------------------------

const TOOL_OWNER_MAP: Record<string, string> = {
  delete_file: 'filesystem',
  drop_table: 'database',
  execute_sql: 'database',
  git_force_push: 'git-ops',
  git_delete_branch: 'git-ops',
  run_command: 'shell',
  run_script: 'shell',
  destroy_resource: 'cloud-infra',
};

// ---------------------------------------------------------------------------
// Variation helpers
// ---------------------------------------------------------------------------

/** Produce case variations of a tool name. */
function caseVariations(name: string): Array<{ label: string; value: string }> {
  return [
    { label: 'exact', value: name },
    { label: 'UPPER', value: name.toUpperCase() },
    { label: 'MiXeD', value: mixedCase(name) },
  ];
}

/** Convert a string to alternating case: dElEtE_fIlE */
function mixedCase(s: string): string {
  return s
    .split('')
    .map((c, i) => (i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()))
    .join('');
}

/** Produce prefix/suffix evasion tricks for a tool name. */
function injectionVariations(name: string): Array<{ label: string; value: string }> {
  return [
    { label: 'leading-space', value: ` ${name}` },
    { label: 'trailing-space', value: `${name} ` },
    { label: 'leading-tab', value: `\t${name}` },
    { label: 'trailing-tab', value: `${name}\t` },
    { label: 'embedded-null', value: `${name}\x00` },
    { label: 'null-prefix', value: `\x00${name}` },
    { label: 'zwj-suffix', value: `${name}\u200D` },
    { label: 'zwj-prefix', value: `\u200D${name}` },
    { label: 'zwnj-embedded', value: `${name.slice(0, Math.floor(name.length / 2))}\u200C${name.slice(Math.floor(name.length / 2))}` },
    { label: 'bom-prefix', value: `\uFEFF${name}` },
  ];
}

/** Produce prefix/namespace evasion tricks for a tool name. */
function prefixVariations(name: string): Array<{ label: string; value: string }> {
  return [
    { label: 'admin-colon', value: `admin:${name}` },
    { label: 'dot-prefix', value: `system.${name}` },
    { label: 'slash-prefix', value: `internal/${name}` },
    { label: 'underscore-prefix', value: `__${name}` },
    { label: 'dash-prefix', value: `super-${name}` },
  ];
}

/** Produce argument variations for tool calls. */
function argumentVariations(): Array<{ label: string; args: Record<string, unknown> }> {
  return [
    { label: 'empty-args', args: {} },
    { label: 'extra-unknown-arg', args: { unknown: 'value' } },
    { label: 'missing-required', args: {} },
    { label: 'null-arg-value', args: { path: null } },
    { label: 'nested-extra', args: { meta: { bypass: true } } },
  ];
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class PermissionBypassGenerator implements ScenarioGenerator {
  readonly category = 'permission_bypass';

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const nextId = (): string => `${this.category}-${index++}`;

    // ------------------------------------------------------------------
    // Axis 1: Each denied tool on its owning server (8 combos)
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      const owner = TOOL_OWNER_MAP[tool];
      scenarios.push(
        buildToolCallScenario({
          id: nextId(),
          category: this.category,
          description: `Denied tool "${tool}" called on owning server "${owner}"`,
          server: owner,
          toolName: tool,
          args: { path: '/tmp/test' },
          expectedDecision: 'BLOCK',
          expectedInterceptor: 'permissions',
        }),
      );
    }

    // ------------------------------------------------------------------
    // Axis 2: Each denied tool on EVERY server (8 x 8 = 64 combos)
    // Tool is only blocked on the server(s) where it is actually denied.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const server of MOCK_SERVERS) {
        const denied = isToolDeniedOnServer(tool, server);
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: this.category,
            description: `Denied tool "${tool}" attempted on server "${server}"`,
            server,
            toolName: tool,
            args: { target: 'test-resource' },
            expectedDecision: denied ? 'BLOCK' : 'PASS',
            ...(denied && { expectedInterceptor: 'permissions' }),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 3: Case variations (8 tools x 3 cases x 8 servers = 192)
    // Permissions uses exact string matching, so UPPER/MiXeD never match
    // the denied list. Only the 'exact' label matches, and only on
    // servers where the tool is actually denied.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const cv of caseVariations(tool)) {
        for (const server of MOCK_SERVERS) {
          const exactAndDenied = cv.label === 'exact' && isToolDeniedOnServer(tool, server);
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: this.category,
              description: `Case bypass "${cv.label}" for "${tool}" on "${server}"`,
              server,
              toolName: cv.value,
              args: { path: '/etc/passwd' },
              expectedDecision: exactAndDenied ? 'BLOCK' : 'PASS',
              ...(exactAndDenied && { expectedInterceptor: 'permissions' }),
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 4: Prefix/suffix injection tricks (8 tools x 10 tricks = 80)
    // Each on owning server to keep count manageable; cross-server
    // coverage is already handled by axes 2 & 3.
    // Permissions uses exact string matching — whitespace, null bytes,
    // and unicode tricks all produce names that don't match, so PASS.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      const owner = TOOL_OWNER_MAP[tool];
      for (const iv of injectionVariations(tool)) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: this.category,
            description: `Injection "${iv.label}" for "${tool}" on "${owner}"`,
            server: owner,
            toolName: iv.value,
            args: { path: '/tmp/bypass' },
            expectedDecision: 'PASS',
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 4b: Injection tricks on all servers (top-3 tricks x 8 tools x 8 servers = 192)
    // Select the most dangerous injection vectors for cross-server coverage.
    // All produce non-exact names → always PASS.
    // ------------------------------------------------------------------
    const dangerousInjections = ['embedded-null', 'zwj-suffix', 'bom-prefix'] as const;
    for (const tool of DENIED_TOOLS) {
      for (const iv of injectionVariations(tool).filter((v) =>
        (dangerousInjections as readonly string[]).includes(v.label),
      )) {
        for (const server of MOCK_SERVERS) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: this.category,
              description: `Cross-server injection "${iv.label}" for "${tool}" on "${server}"`,
              server,
              toolName: iv.value,
              args: { resource: 'sensitive' },
              expectedDecision: 'PASS',
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 5: Argument variations (8 tools x 5 arg-sets = 40, on owner)
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      const owner = TOOL_OWNER_MAP[tool];
      for (const av of argumentVariations()) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: this.category,
            description: `Arg variation "${av.label}" for "${tool}" on "${owner}"`,
            server: owner,
            toolName: tool,
            args: av.args,
            expectedDecision: 'BLOCK',
            expectedInterceptor: 'permissions',
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 6: Prefix/namespace tricks (8 tools x 5 prefixes = 40, on owner)
    // Names like "admin:delete_file" don't match the denied list exactly,
    // so permissions won't block them → always PASS.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      const owner = TOOL_OWNER_MAP[tool];
      for (const pv of prefixVariations(tool)) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: this.category,
            description: `Prefix trick "${pv.label}" for "${tool}" on "${owner}"`,
            server: owner,
            toolName: pv.value,
            args: { path: '/tmp/bypass' },
            expectedDecision: 'PASS',
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 7: Prefix tricks on all servers (top-2 prefixes x 8 tools x 8 servers = 128)
    // Cross-server coverage for the most plausible namespace evasions.
    // ------------------------------------------------------------------
    const dangerousPrefixes = ['admin-colon', 'underscore-prefix'] as const;
    for (const tool of DENIED_TOOLS) {
      for (const pv of prefixVariations(tool).filter((v) =>
        (dangerousPrefixes as readonly string[]).includes(v.label),
      )) {
        for (const server of MOCK_SERVERS) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: this.category,
              description: `Cross-server prefix "${pv.label}" for "${tool}" on "${server}"`,
              server,
              toolName: pv.value,
              args: { resource: 'sensitive' },
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
