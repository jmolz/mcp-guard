/**
 * Capability probe scenario generator.
 *
 * Produces 450+ scenarios calling tools that should have been filtered from
 * capability advertisement or that don't exist on any server. Tests that
 * the permissions interceptor blocks denied tools even when called directly,
 * and that non-denied tools pass through (false-positive checks).
 *
 * Mix of BLOCK (denied tools) and PASS (non-denied variations):
 * - ~300+ BLOCK scenarios: denied tools across all servers with variations
 * - ~150+ PASS scenarios: probing non-denied tools, false-positive checks
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import {
  MOCK_SERVERS,
  DENIED_TOOLS,
  isToolDeniedOnServer,
  buildToolCallScenario,
  stratifiedSample,
} from '../generator.js';

/** Fake tool names that don't exist on any server. */
const NONEXISTENT_TOOLS = [
  'hack_system', 'escalate_privileges', 'read_private_key', 'dump_memory',
  'execute_arbitrary', 'backdoor', 'exfiltrate', 'reverse_shell',
  'keylogger', 'rootkit', 'ransomware', 'crypto_mine',
  'steal_credentials', 'bypass_firewall', 'inject_payload',
  'modify_binary', 'corrupt_database', 'delete_all',
  'disable_logging', 'wipe_audit_trail',
  'spawn_shell', 'read_shadow', 'modify_permissions', 'install_rootkit',
  'extract_secrets', 'sniff_traffic', 'forge_token', 'tamper_logs',
];

/** Slight misspellings / plurals of denied tools — should NOT be blocked by exact match. */
const NEAR_MISS_TOOLS = [
  'delete_files', 'drop_tables', 'force_push', 'delete_branches',
  'destroy_resources', 'run_commands', 'run_scripts', 'execute_sqls',
  'deleting_file', 'dropping_table', 'git_force_pushing', 'runs_command',
];

/** Tools from one server called on another where they don't exist. */
const CROSS_SERVER_TOOLS: Array<{ tool: string; wrongServer: string }> = [
  { tool: 'query_sql', wrongServer: 'filesystem' },
  { tool: 'read_file', wrongServer: 'database' },
  { tool: 'git_clone', wrongServer: 'shell' },
  { tool: 'send_email', wrongServer: 'git-ops' },
  { tool: 'deploy_service', wrongServer: 'communication' },
  { tool: 'http_get', wrongServer: 'cloud-infra' },
  { tool: 'echo', wrongServer: 'filesystem' },
  { tool: 'install_package', wrongServer: 'api-client' },
  { tool: 'write_file', wrongServer: 'database' },
  { tool: 'describe_table', wrongServer: 'filesystem' },
  { tool: 'git_push', wrongServer: 'communication' },
  { tool: 'send_slack_message', wrongServer: 'shell' },
  { tool: 'list_instances', wrongServer: 'api-client' },
  { tool: 'analyze_text', wrongServer: 'cloud-infra' },
  { tool: 'http_post', wrongServer: 'git-ops' },
  { tool: 'get_credentials', wrongServer: 'sampling-server' },
  { tool: 'read_contacts', wrongServer: 'filesystem' },
  { tool: 'search_files', wrongServer: 'communication' },
  { tool: 'create_table', wrongServer: 'shell' },
  { tool: 'git_create_pr', wrongServer: 'database' },
  { tool: 'send_webhook', wrongServer: 'cloud-infra' },
  { tool: 'list_directory', wrongServer: 'git-ops' },
  { tool: 'http_put', wrongServer: 'shell' },
  { tool: 'list_endpoints', wrongServer: 'filesystem' },
];

/** Edge case tool names. */
const EDGE_CASE_NAMES: Array<{ label: string; name: string }> = [
  { label: 'empty', name: '' },
  { label: 'whitespace', name: ' ' },
  { label: 'numeric', name: '0' },
  { label: 'very-long', name: 'a'.repeat(256) },
  { label: 'path-traversal', name: '../etc/passwd' },
  { label: 'shell-injection', name: 'tool;rm -rf /' },
  { label: 'sql-injection', name: "tool' OR 1=1--" },
  { label: 'xss', name: 'tool<script>alert(1)</script>' },
];

// ---------------------------------------------------------------------------
// Case variation helper
// ---------------------------------------------------------------------------

function caseVariations(name: string): Array<{ label: string; value: string }> {
  return [
    { label: 'UPPER', value: name.toUpperCase() },
    { label: 'Title', value: name[0].toUpperCase() + name.slice(1) },
    {
      label: 'camelCase',
      value: name
        .split('_')
        .map((p, i) => (i === 0 ? p : p[0].toUpperCase() + p.slice(1)))
        .join('_'),
    },
  ];
}

// ---------------------------------------------------------------------------
// Unicode trick variations — visual mimicry of denied tool names
// ---------------------------------------------------------------------------

function unicodeTrickVariations(name: string): Array<{ label: string; value: string }> {
  return [
    { label: 'cyrillic-a', value: name.replace(/a/g, '\u0430') },
    { label: 'cyrillic-e', value: name.replace(/e/g, '\u0435') },
    { label: 'cyrillic-o', value: name.replace(/o/g, '\u043E') },
    { label: 'fullwidth-underscore', value: name.replace(/_/g, '\uFF3F') },
    { label: 'zwj-embedded', value: name.slice(0, 3) + '\u200D' + name.slice(3) },
    { label: 'bom-prefix', value: '\uFEFF' + name },
  ];
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const CATEGORY = 'capability_probe';

export class CapabilityProbeGenerator implements ScenarioGenerator {
  readonly category = CATEGORY;

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const nextId = (): string => `${CATEGORY}-${index++}`;

    // ------------------------------------------------------------------
    // Axis 1: Denied tools on all servers — BLOCK
    // 8 denied tools x 8 servers = 64 scenarios
    //
    // These tools would have been filtered from tools/list; calling
    // them directly should be caught by the permissions interceptor.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const server of MOCK_SERVERS) {
        const denied = isToolDeniedOnServer(tool, server);
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: CATEGORY,
            description: `Denied tool "${tool}" probed on "${server}"`,
            server,
            toolName: tool,
            args: {},
            expectedDecision: denied ? 'BLOCK' : 'PASS',
            ...(denied ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 2: Denied tools with case variations — PASS
    // 8 tools x 3 case variants x 4 servers = 96 scenarios
    //
    // Case-variant names don't match denied list exactly, so they PASS
    // permissions. They would fail at upstream (tool not found), but at
    // the pipeline level the decision is PASS.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const { label, value } of caseVariations(tool)) {
        for (const server of MOCK_SERVERS.slice(0, 4)) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: CATEGORY,
              description: `Case variant "${label}" of "${tool}" on "${server}"`,
              server,
              toolName: value,
              args: {},
              expectedDecision: 'PASS',
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 2b: Denied tools with unicode trick variations — PASS
    // 8 tools x 6 tricks x 4 servers = 192 scenarios
    //
    // Unicode confusable tool names (Cyrillic lookalikes, zero-width
    // characters, BOM prefix) don't match the denied list exactly.
    // The permissions interceptor uses exact string matching, so these PASS.
    // This is a known gap — unicode normalization is not applied.
    // ------------------------------------------------------------------
    for (const tool of DENIED_TOOLS) {
      for (const { label, value } of unicodeTrickVariations(tool)) {
        for (const server of MOCK_SERVERS.slice(0, 4)) {
          scenarios.push(
            buildToolCallScenario({
              id: nextId(),
              category: CATEGORY,
              description: `Unicode trick "${label}" for "${tool}" on "${server}"`,
              server,
              toolName: value,
              args: {},
              expectedDecision: 'PASS',
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 3: Non-existent tools on all servers — PASS
    // 28 fake tools x 8 servers = 224 scenarios
    //
    // These are not in the denied list, so allowed_tools: '*' permits
    // them. They would fail at upstream but PASS the pipeline.
    // ------------------------------------------------------------------
    for (const tool of NONEXISTENT_TOOLS) {
      for (const server of MOCK_SERVERS) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: CATEGORY,
            description: `Non-existent tool "${tool}" probed on "${server}"`,
            server,
            toolName: tool,
            args: {},
            expectedDecision: 'PASS',
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 4: Near-miss tools — PASS
    // 12 near-miss tools x 5 servers = 60 scenarios
    //
    // Not exact matches of denied tool names; these should NOT be
    // blocked (false-positive checks).
    // ------------------------------------------------------------------
    for (const tool of NEAR_MISS_TOOLS) {
      for (const server of MOCK_SERVERS.slice(0, 5)) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: CATEGORY,
            description: `Near-miss tool "${tool}" on "${server}"`,
            server,
            toolName: tool,
            args: {},
            expectedDecision: 'PASS',
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 5: Cross-server tools — PASS
    // 24 cross-server combos = 24 scenarios
    //
    // Valid tools called on a server that doesn't own them. Not denied,
    // so they pass permissions (upstream returns error).
    // ------------------------------------------------------------------
    for (const { tool, wrongServer } of CROSS_SERVER_TOOLS) {
      scenarios.push(
        buildToolCallScenario({
          id: nextId(),
          category: CATEGORY,
          description: `Cross-server: "${tool}" on "${wrongServer}"`,
          server: wrongServer,
          toolName: tool,
          args: {},
          expectedDecision: 'PASS',
        }),
      );
    }

    // ------------------------------------------------------------------
    // Axis 6: Edge-case tool names
    // 8 edge cases x 4 servers = 32 scenarios
    //
    // Empty tool name triggers malformed request -> BLOCK.
    // Others pass permissions but fail upstream -> PASS.
    // ------------------------------------------------------------------
    for (const { label, name } of EDGE_CASE_NAMES) {
      for (const server of MOCK_SERVERS.slice(0, 4)) {
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: CATEGORY,
            description: `Edge case "${label}" on "${server}"`,
            server,
            toolName: name,
            args: {},
            expectedDecision: name === '' ? 'BLOCK' : 'PASS',
            ...(name === '' ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // Quick mode: stratified sample
    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
