/**
 * Report orchestrator — generates charts, tables, and combined markdown report.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import type { BenchmarkSuiteResult } from '../types.js';
import {
  generateSecurityChart,
  generateLatencyChart,
  generateConcurrencyChart,
  generateFalsePositiveCard,
} from './chart-generator.js';
import { generateFullReport } from './table-generator.js';

export async function generateReport(result: BenchmarkSuiteResult): Promise<void> {
  await mkdir('benchmarks/charts', { recursive: true });
  await mkdir('benchmarks/tables', { recursive: true });

  const filesWritten: string[] = [];

  // Generate SVG charts
  if (result.security) {
    const svg = generateSecurityChart(result.security);
    await writeFile('benchmarks/charts/security-detection.svg', svg);
    filesWritten.push('benchmarks/charts/security-detection.svg');
  }

  if (result.performance) {
    const latencySvg = generateLatencyChart(result.performance);
    await writeFile('benchmarks/charts/latency.svg', latencySvg);
    filesWritten.push('benchmarks/charts/latency.svg');

    const concurrencySvg = generateConcurrencyChart(result.performance);
    await writeFile('benchmarks/charts/concurrency.svg', concurrencySvg);
    filesWritten.push('benchmarks/charts/concurrency.svg');
  }

  if (result.legitimate) {
    const fpSvg = generateFalsePositiveCard(result.legitimate);
    await writeFile('benchmarks/charts/false-positive.svg', fpSvg);
    filesWritten.push('benchmarks/charts/false-positive.svg');
  }

  // Generate markdown tables
  const report = generateFullReport(result);
  await writeFile('benchmarks/results/REPORT.md', report);
  filesWritten.push('benchmarks/results/REPORT.md');

  // Also write individual table files
  if (result.security) {
    const { generateSecurityTable } = await import('./table-generator.js');
    await writeFile('benchmarks/tables/security.md', generateSecurityTable(result.security));
    filesWritten.push('benchmarks/tables/security.md');
  }

  if (result.performance) {
    const { generatePerformanceTable, generateConcurrencyTable } = await import('./table-generator.js');
    await writeFile('benchmarks/tables/performance.md', generatePerformanceTable(result.performance));
    filesWritten.push('benchmarks/tables/performance.md');
    await writeFile('benchmarks/tables/concurrency.md', generateConcurrencyTable(result.performance));
    filesWritten.push('benchmarks/tables/concurrency.md');
  }

  console.log(`Report generated: ${filesWritten.length} files`);
  for (const f of filesWritten) {
    console.log(`  ${f}`);
  }
}
