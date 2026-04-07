/**
 * Main benchmark orchestrator — runs all benchmark suites and produces unified results.
 *
 * Usage:
 *   npx tsx benchmarks/runner.ts           # Full suite
 *   npx tsx benchmarks/runner.ts --quick   # Stratified sample (~30s)
 *   npx tsx benchmarks/runner.ts --suite security
 *   npx tsx benchmarks/runner.ts --suite legitimate
 *   npx tsx benchmarks/runner.ts --suite performance
 */

import { mkdir, writeFile } from 'node:fs/promises';
import type {
  AuditIntegrityResult,
  BenchmarkSuiteResult,
  SecurityBenchmarkResult,
  LegitimateTrafficResult,
  PerformanceBenchmarkResult,
} from './types.js';
import { runSecurityBenchmark } from './security/run-security.js';
import { runLegitimateTraffic } from './legitimate/run-legitimate.js';
import { runPerformanceBenchmark } from './performance/run-performance.js';

function parseArgs(): { quick: boolean; suite?: string } {
  const args = process.argv.slice(2);
  const quick = args.includes('--quick');
  const suiteIdx = args.indexOf('--suite');
  const suite = suiteIdx >= 0 ? args[suiteIdx + 1] : undefined;
  return { quick, suite };
}

function printSecuritySummary(results: SecurityBenchmarkResult[]): void {
  console.log('\n  Category                  | Total | Detected | Rate');
  console.log('  ─────────────────────────┼───────┼──────────┼───────');
  let totalAll = 0;
  let detectedAll = 0;
  for (const r of results) {
    const rate = (r.detectionRate * 100).toFixed(1);
    const name = r.category.padEnd(25);
    console.log(`  ${name} | ${String(r.total).padStart(5)} | ${String(r.detected).padStart(8)} | ${rate}%`);
    totalAll += r.total;
    detectedAll += r.detected;
  }
  const overallRate = totalAll > 0 ? ((detectedAll / totalAll) * 100).toFixed(1) : '0.0';
  console.log('  ─────────────────────────┼───────┼──────────┼───────');
  console.log(`  ${'OVERALL'.padEnd(25)} | ${String(totalAll).padStart(5)} | ${String(detectedAll).padStart(8)} | ${overallRate}%`);
}

function printLegitSummary(result: LegitimateTrafficResult): void {
  console.log(`\n  Total requests:    ${result.total}`);
  console.log(`  False positives:   ${result.falsePositives}`);
  console.log(`  FP rate:           ${(result.falsePositiveRate * 100).toFixed(3)}%`);
}

function printPerfSummary(result: PerformanceBenchmarkResult): void {
  console.log(`\n  Latency (${result.latency.count} requests):`);
  console.log(`    p50:  ${result.latency.p50Ms.toFixed(2)} ms`);
  console.log(`    p95:  ${result.latency.p95Ms.toFixed(2)} ms`);
  console.log(`    p99:  ${result.latency.p99Ms.toFixed(2)} ms`);
  console.log(`    mean: ${result.latency.meanMs.toFixed(2)} ms`);

  console.log('\n  Concurrency:');
  for (const [level, stats] of Object.entries(result.concurrency)) {
    console.log(`    ${level} connections: p50=${stats.p50Ms.toFixed(1)}ms p95=${stats.p95Ms.toFixed(1)}ms p99=${stats.p99Ms.toFixed(1)}ms`);
  }

  console.log(`\n  Throughput: ${result.throughput} req/s`);
}

function printVerdict(
  security?: SecurityBenchmarkResult[],
  auditIntegrity?: AuditIntegrityResult,
  legitimate?: LegitimateTrafficResult,
  performance?: PerformanceBenchmarkResult,
): boolean {
  console.log('\n=== Verdict ===\n');
  let allPass = true;

  if (security) {
    const totalAll = security.reduce((s, r) => s + r.total, 0);
    const detectedAll = security.reduce((s, r) => s + r.detected, 0);
    const overallRate = totalAll > 0 ? detectedAll / totalAll : 1;
    const pass = overallRate >= 0.95;
    if (!pass) allPass = false;
    console.log(`  Detection rate: ${(overallRate * 100).toFixed(1)}% ${pass ? 'PASS' : 'FAIL'} (target: >95%)`);
  }

  if (auditIntegrity) {
    if (!auditIntegrity.passed) allPass = false;
    console.log(`  Audit integrity: ${auditIntegrity.passed ? 'PASS' : 'FAIL'}${auditIntegrity.error ? ` (${auditIntegrity.error})` : ''}`);
  }

  if (legitimate) {
    const pass = legitimate.falsePositiveRate < 0.001;
    if (!pass) allPass = false;
    console.log(`  FP rate:        ${(legitimate.falsePositiveRate * 100).toFixed(3)}% ${pass ? 'PASS' : 'FAIL'} (target: <0.1%)`);
  }

  if (performance) {
    const pass = performance.latency.p50Ms < 5;
    if (!pass) allPass = false;
    console.log(`  p50 latency:    ${performance.latency.p50Ms.toFixed(2)}ms ${pass ? 'PASS' : 'FAIL'} (target: <5ms)`);
  }

  return allPass;
}

export async function runBenchmarks(options: { quick?: boolean; suite?: string }): Promise<{ result: BenchmarkSuiteResult; passed: boolean }> {
  console.log(`\n=== MCP-Guard Benchmark Suite${options.quick ? ' (quick mode)' : ''} ===\n`);

  const genOpts = { quick: options.quick };

  let security: SecurityBenchmarkResult[] | undefined;
  let auditIntegrity: AuditIntegrityResult | undefined;
  let legitimate: LegitimateTrafficResult | undefined;
  let performance: PerformanceBenchmarkResult | undefined;

  if (!options.suite || options.suite === 'security') {
    console.log('--- Security Benchmarks ---');
    const securityRun = await runSecurityBenchmark('benchmarks/configs/security-benchmark.yaml', genOpts);
    security = securityRun.results;
    auditIntegrity = securityRun.auditIntegrity;
    printSecuritySummary(security);
  }

  if (!options.suite || options.suite === 'legitimate') {
    console.log('\n--- Legitimate Traffic ---');
    legitimate = await runLegitimateTraffic('benchmarks/configs/security-benchmark.yaml', genOpts);
    printLegitSummary(legitimate);
  }

  if (!options.suite || options.suite === 'performance') {
    console.log('\n--- Performance Benchmarks ---');
    performance = await runPerformanceBenchmark('benchmarks/configs/performance-benchmark.yaml', genOpts);
    printPerfSummary(performance);
  }

  const verdictPassed = printVerdict(security, auditIntegrity, legitimate, performance);

  const result: BenchmarkSuiteResult = {
    timestamp: new Date().toISOString(),
    security,
    auditIntegrity,
    legitimate,
    performance,
  };

  await mkdir('benchmarks/results', { recursive: true });
  await writeFile('benchmarks/results/latest.json', JSON.stringify(result, null, 2));
  console.log('\nResults written to benchmarks/results/latest.json');

  if (!verdictPassed) {
    console.log('\nBenchmark verdict: FAIL — one or more thresholds not met');
  }

  return { result, passed: verdictPassed };
}

// Direct execution
const { quick, suite } = parseArgs();
runBenchmarks({ quick, suite })
  .then(({ passed }) => {
    if (!passed) process.exitCode = 1;
  })
  .catch((err) => {
    console.error('Benchmark suite failed:', err);
    process.exit(1);
  });
