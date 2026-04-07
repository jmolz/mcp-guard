import { describe, it, expect } from 'vitest';
import type {
  SecurityBenchmarkResult,
  PerformanceBenchmarkResult,
  LegitimateTrafficResult,
  BenchmarkSuiteResult,
} from '../../benchmarks/types.js';
import {
  generateSecurityChart,
  generateLatencyChart,
  generateConcurrencyChart,
  generateFalsePositiveCard,
} from '../../benchmarks/report/chart-generator.js';
import {
  generateSecurityTable,
  generatePerformanceTable,
  generateConcurrencyTable,
  generateVerdictTable,
  generateFullReport,
} from '../../benchmarks/report/table-generator.js';

const securityFixture: SecurityBenchmarkResult[] = [
  { category: 'permission_bypass', total: 500, detected: 490, missed: 10, detectionRate: 0.98, scenarios: [] },
  { category: 'pii_evasion', total: 450, detected: 440, missed: 10, detectionRate: 0.978, scenarios: [] },
  { category: 'rate_limit_evasion', total: 600, detected: 560, missed: 40, detectionRate: 0.933, scenarios: [] },
];

const performanceFixture: PerformanceBenchmarkResult = {
  latency: {
    count: 10000,
    p50Ms: 1.5,
    p95Ms: 3.2,
    p99Ms: 8.1,
    meanMs: 2.0,
    minMs: 0.3,
    maxMs: 25.0,
  },
  concurrency: {
    1: { count: 1000, p50Ms: 1.2, p95Ms: 2.5, p99Ms: 5.0, meanMs: 1.5, minMs: 0.2, maxMs: 10.0 },
    10: { count: 1000, p50Ms: 1.8, p95Ms: 4.0, p99Ms: 8.0, meanMs: 2.2, minMs: 0.3, maxMs: 15.0 },
    50: { count: 1000, p50Ms: 3.0, p95Ms: 6.5, p99Ms: 12.0, meanMs: 3.5, minMs: 0.4, maxMs: 20.0 },
  },
  throughput: 5000,
};

const legitimateFixture: LegitimateTrafficResult = {
  total: 10000,
  passed: 9999,
  falsePositives: 1,
  falsePositiveRate: 0.0001,
  scenarios: [],
};

const suiteFixture: BenchmarkSuiteResult = {
  timestamp: '2026-04-07T00:00:00.000Z',
  security: securityFixture,
  auditIntegrity: { passed: true, rawPiiFound: 0 },
  legitimate: legitimateFixture,
  performance: performanceFixture,
};

describe('chart generator', () => {
  it('generates valid SVG for security detection rates', () => {
    const svg = generateSecurityChart(securityFixture);
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg).toContain('permission_bypass');
    expect(svg).toContain('pii_evasion');
    expect(svg).toContain('rate_limit_evasion');
    expect(svg).toContain('95% target');
    expect(svg).toContain('aria-label');
  });

  it('generates valid SVG for latency distribution', () => {
    const svg = generateLatencyChart(performanceFixture);
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg).toContain('p50');
    expect(svg).toContain('p95');
    expect(svg).toContain('p99');
    expect(svg).toContain('5ms target');
  });

  it('generates valid SVG for concurrency scaling', () => {
    const svg = generateConcurrencyChart(performanceFixture);
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg).toContain('Concurrency Scaling');
  });

  it('generates false positive card SVG', () => {
    const svg = generateFalsePositiveCard(legitimateFixture);
    expect(svg).toContain('<svg');
    expect(svg).toContain('0.010%');
    expect(svg).toContain('PASS');
  });
});

describe('table generator', () => {
  it('generates valid markdown security table', () => {
    const table = generateSecurityTable(securityFixture);
    expect(table).toContain('| Category |');
    expect(table).toContain('permission_bypass');
    expect(table).toContain('OVERALL');
    const lines = table.split('\n');
    // header + separator + 3 categories + overall = 6 lines
    expect(lines.length).toBe(6);
  });

  it('generates valid markdown performance table', () => {
    const table = generatePerformanceTable(performanceFixture);
    expect(table).toContain('| Metric |');
    expect(table).toContain('p50 latency');
    expect(table).toContain('<5 ms');
  });

  it('generates concurrency table with correct levels', () => {
    const table = generateConcurrencyTable(performanceFixture);
    expect(table).toContain('| Connections |');
    expect(table).toContain('| 1 |');
    expect(table).toContain('| 10 |');
    expect(table).toContain('| 50 |');
  });

  it('generates verdict table reflecting pass/fail', () => {
    const table = generateVerdictTable(suiteFixture);
    expect(table).toContain('Security');
    expect(table).toContain('Performance');
    expect(table).toContain('PASS');
  });

  it('generates full report with all sections', () => {
    const report = generateFullReport(suiteFixture);
    expect(report).toContain('# MCP-Guard Benchmark Report');
    expect(report).toContain('## Verdict');
    expect(report).toContain('## Security Detection');
    expect(report).toContain('## False Positives');
    expect(report).toContain('## Performance');
    expect(report).toContain('### Concurrency Scaling');
  });

  it('handles partial suite data gracefully', () => {
    const partialSuite: BenchmarkSuiteResult = {
      timestamp: '2026-04-07T00:00:00.000Z',
      security: securityFixture,
    };
    const report = generateFullReport(partialSuite);
    expect(report).toContain('## Security Detection');
    expect(report).not.toContain('## Performance');
    expect(report).not.toContain('## False Positives');
  });
});
