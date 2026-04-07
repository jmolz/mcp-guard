/**
 * Markdown table generation from benchmark results.
 */

import type {
  SecurityBenchmarkResult,
  PerformanceBenchmarkResult,
  BenchmarkSuiteResult,
} from '../types.js';

export function generateSecurityTable(results: SecurityBenchmarkResult[]): string {
  const header = '| Category | Scenarios | Detected | Rate | Status |';
  const sep = '|----------|-----------|----------|------|--------|';

  const rows = results.map((r) => {
    const rate = (r.detectionRate * 100).toFixed(1);
    const status = r.detectionRate >= 0.95 ? '\u2705' : '\u274c';
    return `| ${r.category} | ${r.total} | ${r.detected} | ${rate}% | ${status} |`;
  });

  // Overall row
  const totalAll = results.reduce((s, r) => s + r.total, 0);
  const detectedAll = results.reduce((s, r) => s + r.detected, 0);
  const overallRate = totalAll > 0 ? ((detectedAll / totalAll) * 100).toFixed(1) : '0.0';
  const overallStatus = totalAll > 0 && detectedAll / totalAll >= 0.95 ? '\u2705' : '\u274c';
  rows.push(`| **OVERALL** | **${totalAll}** | **${detectedAll}** | **${overallRate}%** | ${overallStatus} |`);

  return [header, sep, ...rows].join('\n');
}

export function generatePerformanceTable(perf: PerformanceBenchmarkResult): string {
  const header = '| Metric | Value | Target | Status |';
  const sep = '|--------|-------|--------|--------|';

  const rows = [
    `| p50 latency | ${perf.latency.p50Ms.toFixed(2)} ms | <5 ms | ${perf.latency.p50Ms < 5 ? '\u2705' : '\u274c'} |`,
    `| p95 latency | ${perf.latency.p95Ms.toFixed(2)} ms | — | \u2139\ufe0f |`,
    `| p99 latency | ${perf.latency.p99Ms.toFixed(2)} ms | — | \u2139\ufe0f |`,
    `| Mean latency | ${perf.latency.meanMs.toFixed(2)} ms | — | \u2139\ufe0f |`,
    `| Throughput | ${perf.throughput} req/s | — | \u2139\ufe0f |`,
  ];

  return [header, sep, ...rows].join('\n');
}

export function generateConcurrencyTable(perf: PerformanceBenchmarkResult): string {
  const header = '| Connections | p50 (ms) | p95 (ms) | p99 (ms) |';
  const sep = '|-------------|----------|----------|----------|';

  const rows = Object.entries(perf.concurrency)
    .sort(([a], [b]) => parseInt(a) - parseInt(b))
    .map(([level, stats]) =>
      `| ${level} | ${stats.p50Ms.toFixed(2)} | ${stats.p95Ms.toFixed(2)} | ${stats.p99Ms.toFixed(2)} |`,
    );

  return [header, sep, ...rows].join('\n');
}

export function generateVerdictTable(suite: BenchmarkSuiteResult): string {
  const header = '| Suite | Result | Details |';
  const sep = '|-------|--------|---------|';
  const rows: string[] = [];

  if (suite.security) {
    const totalAll = suite.security.reduce((s, r) => s + r.total, 0);
    const detectedAll = suite.security.reduce((s, r) => s + r.detected, 0);
    const rate = totalAll > 0 ? detectedAll / totalAll : 0;
    const pass = rate >= 0.95;
    rows.push(`| Security | ${pass ? '\u2705 PASS' : '\u274c FAIL'} | ${(rate * 100).toFixed(1)}% detection (target >95%) |`);
  }

  if (suite.auditIntegrity) {
    rows.push(`| Audit Integrity | ${suite.auditIntegrity.passed ? '\u2705 PASS' : '\u274c FAIL'} | ${suite.auditIntegrity.error ?? 'No raw PII in audit logs'} |`);
  }

  if (suite.legitimate) {
    const pass = suite.legitimate.falsePositiveRate < 0.001;
    rows.push(`| False Positives | ${pass ? '\u2705 PASS' : '\u274c FAIL'} | ${(suite.legitimate.falsePositiveRate * 100).toFixed(3)}% FP rate (target <0.1%) |`);
  }

  if (suite.performance) {
    const pass = suite.performance.latency.p50Ms < 5;
    rows.push(`| Performance | ${pass ? '\u2705 PASS' : '\u274c FAIL'} | p50 ${suite.performance.latency.p50Ms.toFixed(2)}ms (target <5ms) |`);
  }

  return [header, sep, ...rows].join('\n');
}

export function generateFullReport(suite: BenchmarkSuiteResult): string {
  const sections: string[] = [
    `# MCP-Guard Benchmark Report`,
    ``,
    `Generated: ${suite.timestamp}`,
    ``,
  ];

  sections.push('## Verdict', '', generateVerdictTable(suite), '');

  if (suite.security) {
    sections.push(
      '## Security Detection',
      '',
      '![Security Detection Rates](../charts/security-detection.svg)',
      '',
      generateSecurityTable(suite.security),
      '',
    );
  }

  if (suite.legitimate) {
    sections.push(
      '## False Positives',
      '',
      '![False Positive Rate](../charts/false-positive.svg)',
      '',
      `- Total requests: ${suite.legitimate.total}`,
      `- False positives: ${suite.legitimate.falsePositives}`,
      `- FP rate: ${(suite.legitimate.falsePositiveRate * 100).toFixed(3)}%`,
      '',
    );
  }

  if (suite.performance) {
    sections.push(
      '## Performance',
      '',
      '![Latency Distribution](../charts/latency.svg)',
      '',
      generatePerformanceTable(suite.performance),
      '',
      '### Concurrency Scaling',
      '',
      '![Concurrency Scaling](../charts/concurrency.svg)',
      '',
      generateConcurrencyTable(suite.performance),
      '',
    );
  }

  return sections.join('\n');
}
