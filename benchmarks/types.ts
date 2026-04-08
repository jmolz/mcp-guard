/** Shared types for the MCP-Guard benchmark suite. */

/** A single benchmark scenario — one MCP request with an expected outcome. */
export interface BenchmarkScenario {
  id: string;
  category: string;
  description: string;
  server: string;
  message: {
    jsonrpc: '2.0';
    id: number;
    method: string;
    params?: Record<string, unknown>;
  };
  expectedDecision: 'PASS' | 'BLOCK' | 'MODIFY';
  expectedInterceptor?: string;
  /** Whether this scenario operates at the socket auth level vs MCP message level */
  level?: 'socket' | 'mcp';
}

/**
 * A burst group for rate-limit testing.
 * Rate limit scenarios are fundamentally sequential — a burst group is an
 * ordered sequence of requests where early ones PASS and later ones BLOCK.
 */
export interface BurstGroup {
  id: string;
  category: 'rate_limit_evasion';
  description: string;
  server: string;
  requests: Array<{
    message: {
      jsonrpc: '2.0';
      id: number;
      method: string;
      params?: Record<string, unknown>;
    };
    expectedDecision: 'PASS' | 'BLOCK';
    delayMs?: number;
  }>;
}

/** Result of running a single scenario. */
export interface ScenarioResult {
  scenario: BenchmarkScenario;
  actualDecision: 'PASS' | 'BLOCK' | 'MODIFY';
  actualInterceptor?: string;
  durationMs: number;
  passed: boolean;
}

/** Aggregated results for one security category. */
export interface SecurityBenchmarkResult {
  category: string;
  total: number;
  detected: number;
  missed: number;
  detectionRate: number;
  scenarios: ScenarioResult[];
}

/** Diversity metadata for legitimate traffic — used in methodology reporting. */
export interface LegitimateTrafficMetadata {
  uniqueServers: number;
  uniqueTools: number;
  nearPiiEdgeCases: number;
  requestCategories: Array<{ name: string; count: number }>;
}

/** Results from legitimate traffic testing. */
export interface LegitimateTrafficResult {
  total: number;
  passed: number;
  falsePositives: number;
  falsePositiveRate: number;
  scenarios: ScenarioResult[];
  metadata?: LegitimateTrafficMetadata;
  /** Rule of Three: 95% CI upper bound for FP rate. */
  fpUpperBound95?: number;
}

/**
 * Compute the 95% CI upper bound for a proportion.
 * When observed = 0, uses Rule of Three (3/n).
 * When observed > 0, uses Wilson score interval.
 */
export function computeFpUpperBound(observed: number, total: number): number {
  if (total === 0) return 1;
  if (observed > total) return 1;
  if (observed === 0) return Math.min(1, 3 / total);
  // Wilson score interval upper bound for 95% CI
  const z = 1.96;
  const p = observed / total;
  const denominator = 1 + (z * z) / total;
  const center = p + (z * z) / (2 * total);
  const spread = z * Math.sqrt((p * (1 - p) + (z * z) / (4 * total)) / total);
  return (center + spread) / denominator;
}

/** Latency percentile statistics. */
export interface LatencyResult {
  count: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  meanMs: number;
  minMs: number;
  maxMs: number;
}

/** Full performance benchmark results. */
export interface PerformanceBenchmarkResult {
  latency: LatencyResult;
  concurrency: Record<number, LatencyResult>;
  throughput: number;
}

/** Result of the audit log PII integrity check. */
export interface AuditIntegrityResult {
  passed: boolean;
  rawPiiFound: number;
  error?: string;
}

/** Top-level result combining all benchmark suites. */
export interface BenchmarkSuiteResult {
  timestamp: string;
  security?: SecurityBenchmarkResult[];
  auditIntegrity?: AuditIntegrityResult;
  legitimate?: LegitimateTrafficResult;
  performance?: PerformanceBenchmarkResult;
}

/** Options passed to scenario generators. */
export interface GeneratorOptions {
  /** When true, generators produce a stratified sample (~50 per category) instead of full cartesian product. */
  quick?: boolean;
}

/** Interface for security scenario generators. */
export interface ScenarioGenerator {
  category: string;
  generate(options?: GeneratorOptions): BenchmarkScenario[];
}

/** Interface for burst-group generators (rate-limit-evasion). */
export interface BurstGroupGenerator {
  category: string;
  generate(options?: GeneratorOptions): BurstGroup[];
}
