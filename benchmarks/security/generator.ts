/**
 * Scenario generator framework for the MCP-Guard security benchmark suite.
 *
 * Provides the registry, message builders, and helpers that all 10 security
 * scenario category generators import.
 */

import type {
  BenchmarkScenario,
  BurstGroup,
  BurstGroupGenerator,
  GeneratorOptions,
  ScenarioGenerator,
} from '../types.js';

// ---------------------------------------------------------------------------
// Helper constants
// ---------------------------------------------------------------------------

/** All 8 mock server names used by the security benchmark config. */
export const MOCK_SERVERS = [
  'filesystem',
  'database',
  'api-client',
  'git-ops',
  'shell',
  'communication',
  'cloud-infra',
  'sampling-server',
] as const;

/** Tools that the security benchmark config denies (union across all servers). */
export const DENIED_TOOLS = [
  'delete_file',
  'drop_table',
  'git_force_push',
  'git_delete_branch',
  'destroy_resource',
  'run_command',
  'run_script',
  'execute_sql',
] as const;

/** Per-server denied tools — matches security-benchmark.yaml exactly. */
export const DENIED_TOOLS_PER_SERVER: Record<string, readonly string[]> = {
  filesystem: ['delete_file'],
  database: ['drop_table', 'execute_sql'],
  'api-client': [],
  'git-ops': ['git_force_push', 'git_delete_branch'],
  shell: ['run_command', 'run_script'],
  communication: [],
  'cloud-infra': ['destroy_resource'],
  'sampling-server': [],
};

/** Per-server denied resources — matches security-benchmark.yaml exactly. */
export const DENIED_RESOURCES_PER_SERVER: Record<string, readonly string[]> = {
  filesystem: ['file://../../*', 'file://../*'],
  database: [],
  'api-client': [],
  'git-ops': [],
  shell: [],
  communication: [],
  'cloud-infra': [],
  'sampling-server': [],
};

/** Check if a tool is denied on a specific server. */
export function isToolDeniedOnServer(tool: string, server: string): boolean {
  return (DENIED_TOOLS_PER_SERVER[server] ?? []).includes(tool);
}

// ---------------------------------------------------------------------------
// Auto-incrementing JSON-RPC ID
// ---------------------------------------------------------------------------

let _nextId = 1;

/** Reset the auto-incrementing ID counter (useful for deterministic tests). */
export function resetIdCounter(): void {
  _nextId = 1;
}

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

/**
 * Build a valid MCP JSON-RPC 2.0 request body with an auto-incrementing ID.
 */
export function buildMcpMessage(
  method: string,
  params: Record<string, unknown>,
): { jsonrpc: '2.0'; id: number; method: string; params: Record<string, unknown> } {
  return { jsonrpc: '2.0', id: _nextId++, method, params };
}

// ---------------------------------------------------------------------------
// Scenario builders
// ---------------------------------------------------------------------------

interface BaseScenarioOpts {
  id: string;
  category: string;
  description: string;
  server: string;
  expectedDecision: 'PASS' | 'BLOCK' | 'MODIFY';
  expectedInterceptor?: string;
}

/**
 * Build a complete `BenchmarkScenario` for a `tools/call` request.
 */
export function buildToolCallScenario(opts: BaseScenarioOpts & {
  toolName: string;
  args: Record<string, unknown>;
}): BenchmarkScenario {
  return {
    id: opts.id,
    category: opts.category,
    description: opts.description,
    server: opts.server,
    message: buildMcpMessage('tools/call', {
      name: opts.toolName,
      arguments: opts.args,
    }),
    expectedDecision: opts.expectedDecision,
    ...(opts.expectedInterceptor !== undefined && { expectedInterceptor: opts.expectedInterceptor }),
  };
}

/**
 * Build a complete `BenchmarkScenario` for a `resources/read` request.
 */
export function buildResourceReadScenario(opts: BaseScenarioOpts & {
  uri: string;
}): BenchmarkScenario {
  return {
    id: opts.id,
    category: opts.category,
    description: opts.description,
    server: opts.server,
    message: buildMcpMessage('resources/read', { uri: opts.uri }),
    expectedDecision: opts.expectedDecision,
    ...(opts.expectedInterceptor !== undefined && { expectedInterceptor: opts.expectedInterceptor }),
  };
}

/**
 * Build a complete `BenchmarkScenario` for a `sampling/createMessage` request.
 */
export function buildSamplingScenario(opts: BaseScenarioOpts & {
  params: Record<string, unknown>;
}): BenchmarkScenario {
  return {
    id: opts.id,
    category: opts.category,
    description: opts.description,
    server: opts.server,
    message: buildMcpMessage('sampling/createMessage', opts.params),
    expectedDecision: opts.expectedDecision,
    ...(opts.expectedInterceptor !== undefined && { expectedInterceptor: opts.expectedInterceptor }),
  };
}

// ---------------------------------------------------------------------------
// Stratified sampling
// ---------------------------------------------------------------------------

/**
 * Pick evenly-spaced items from an array for quick-mode stratified sampling.
 *
 * If `items.length <= maxCount`, returns the full array unchanged.
 * Otherwise selects `maxCount` items at even intervals so the sample
 * covers the beginning, middle, and end of the input.
 */
export function stratifiedSample<T>(items: T[], maxCount: number): T[] {
  if (maxCount <= 0) return [];
  if (maxCount === 1) return [items[0]];
  if (items.length <= maxCount) {
    return items;
  }

  const result: T[] = [];
  const step = (items.length - 1) / (maxCount - 1);

  for (let i = 0; i < maxCount; i++) {
    const index = Math.round(i * step);
    result.push(items[index]);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Central registry that collects scenario generators and burst-group
 * generators, then produces the full (or quick-sampled) scenario set.
 */
export class ScenarioGeneratorRegistry {
  private readonly scenarioGenerators: ScenarioGenerator[] = [];
  private readonly burstGroupGenerators: BurstGroupGenerator[] = [];

  /** Register a single-scenario generator. */
  registerScenario(gen: ScenarioGenerator): void {
    this.scenarioGenerators.push(gen);
  }

  /** Register a burst-group generator (rate-limit evasion). */
  registerBurstGroup(gen: BurstGroupGenerator): void {
    this.burstGroupGenerators.push(gen);
  }

  /**
   * Run every registered generator and return the combined output.
   *
   * `options` is forwarded to each generator so they can honour `quick` mode.
   */
  generateAll(options?: GeneratorOptions): {
    scenarios: BenchmarkScenario[];
    burstGroups: BurstGroup[];
  } {
    const scenarios: BenchmarkScenario[] = [];
    for (const gen of this.scenarioGenerators) {
      scenarios.push(...gen.generate(options));
    }

    const burstGroups: BurstGroup[] = [];
    for (const gen of this.burstGroupGenerators) {
      burstGroups.push(...gen.generate(options));
    }

    return { scenarios, burstGroups };
  }

  /** List every registered category name (scenario + burst-group). */
  getCategories(): string[] {
    const categories = new Set<string>();
    for (const gen of this.scenarioGenerators) {
      categories.add(gen.category);
    }
    for (const gen of this.burstGroupGenerators) {
      categories.add(gen.category);
    }
    return [...categories];
  }
}
