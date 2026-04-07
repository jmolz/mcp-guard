/**
 * SVG chart generation from benchmark results.
 * Uses template literals — no external dependencies.
 */

import type { SecurityBenchmarkResult, PerformanceBenchmarkResult, LegitimateTrafficResult } from '../types.js';

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function rateColor(rate: number): string {
  if (rate >= 0.95) return '#22c55e'; // green
  if (rate >= 0.90) return '#eab308'; // yellow
  return '#ef4444'; // red
}

export function generateSecurityChart(results: SecurityBenchmarkResult[]): string {
  const width = 800;
  const height = 40 + results.length * 36 + 30;
  const labelWidth = 200;
  const barMaxWidth = 500;
  const barHeight = 24;

  const bars = results.map((r, i) => {
    const y = 40 + i * 36;
    const barW = Math.max(1, r.detectionRate * barMaxWidth);
    const pct = (r.detectionRate * 100).toFixed(1);
    const color = rateColor(r.detectionRate);
    const label = escapeXml(r.category);

    return `    <text x="${labelWidth - 8}" y="${y + barHeight / 2 + 4}" text-anchor="end" font-size="12" fill="#334155">${label}</text>
    <rect x="${labelWidth}" y="${y}" width="${barW}" height="${barHeight}" fill="${color}" rx="3"/>
    <text x="${labelWidth + barW + 6}" y="${y + barHeight / 2 + 4}" font-size="12" fill="#64748b">${pct}%</text>`;
  }).join('\n');

  // 95% threshold line
  const thresholdX = labelWidth + 0.95 * barMaxWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" aria-label="Security Detection Rates">
  <title>Security Detection Rates</title>
  <style>text { font-family: system-ui, -apple-system, sans-serif; }</style>
  <text x="${width / 2}" y="24" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">Security Detection Rates</text>
${bars}
  <line x1="${thresholdX}" y1="32" x2="${thresholdX}" y2="${height - 10}" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="6,3"/>
  <text x="${thresholdX + 4}" y="${height - 4}" font-size="10" fill="#ef4444">95% target</text>
</svg>`;
}

export function generateLatencyChart(perf: PerformanceBenchmarkResult): string {
  const width = 800;
  const height = 400;
  const padding = { top: 50, right: 60, bottom: 60, left: 80 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const metrics = [
    { label: 'p50', value: perf.latency.p50Ms, color: '#22c55e' },
    { label: 'p95', value: perf.latency.p95Ms, color: '#eab308' },
    { label: 'p99', value: perf.latency.p99Ms, color: '#ef4444' },
    { label: 'mean', value: perf.latency.meanMs, color: '#3b82f6' },
  ];

  const maxVal = Math.max(...metrics.map((m) => m.value), 5) * 1.2;
  const barWidth = chartW / (metrics.length * 2);

  const bars = metrics.map((m, i) => {
    const x = padding.left + i * (chartW / metrics.length) + barWidth / 2;
    const barH = (m.value / maxVal) * chartH;
    const y = padding.top + chartH - barH;

    return `    <rect x="${x}" y="${y}" width="${barWidth}" height="${barH}" fill="${m.color}" rx="3"/>
    <text x="${x + barWidth / 2}" y="${y - 6}" text-anchor="middle" font-size="12" fill="#334155">${m.value.toFixed(2)}ms</text>
    <text x="${x + barWidth / 2}" y="${padding.top + chartH + 20}" text-anchor="middle" font-size="13" fill="#334155">${m.label}</text>`;
  }).join('\n');

  // 5ms threshold line for p50
  const thresholdY = padding.top + chartH - (5 / maxVal) * chartH;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" aria-label="Latency Distribution">
  <title>Latency Distribution</title>
  <style>text { font-family: system-ui, -apple-system, sans-serif; }</style>
  <text x="${width / 2}" y="30" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">Latency Distribution</text>
  <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${padding.left + chartW}" y2="${padding.top + chartH}" stroke="#cbd5e1" stroke-width="1"/>
${bars}
  <line x1="${padding.left}" y1="${thresholdY}" x2="${padding.left + chartW}" y2="${thresholdY}" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="6,3"/>
  <text x="${padding.left + chartW + 4}" y="${thresholdY + 4}" font-size="10" fill="#ef4444">5ms target</text>
</svg>`;
}

export function generateConcurrencyChart(perf: PerformanceBenchmarkResult): string {
  const width = 800;
  const height = 400;
  const padding = { top: 50, right: 80, bottom: 60, left: 80 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const levels = Object.entries(perf.concurrency)
    .map(([k, v]) => ({ level: parseInt(k, 10), stats: v }))
    .sort((a, b) => a.level - b.level);

  if (levels.length === 0) {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" aria-label="Concurrency Scaling">
  <title>Concurrency Scaling</title>
  <text x="${width / 2}" y="${height / 2}" text-anchor="middle" font-size="14" fill="#64748b">No concurrency data</text>
</svg>`;
  }

  const allValues = levels.flatMap((l) => [l.stats.p50Ms, l.stats.p95Ms]);
  const maxVal = Math.max(...allValues, 1) * 1.2;

  const series = [
    { key: 'p50Ms' as const, color: '#22c55e', label: 'p50' },
    { key: 'p95Ms' as const, color: '#ef4444', label: 'p95' },
  ];

  function toX(i: number): number {
    return padding.left + (i / Math.max(levels.length - 1, 1)) * chartW;
  }
  function toY(val: number): number {
    return padding.top + chartH - (val / maxVal) * chartH;
  }

  const lines = series.map((s) => {
    const points = levels.map((l, i) => `${toX(i)},${toY(l.stats[s.key])}`).join(' ');
    const dots = levels.map((l, i) =>
      `<circle cx="${toX(i)}" cy="${toY(l.stats[s.key])}" r="4" fill="${s.color}"/>`,
    ).join('\n    ');
    return `    <polyline points="${points}" fill="none" stroke="${s.color}" stroke-width="2"/>
    ${dots}`;
  }).join('\n');

  const xLabels = levels.map((l, i) =>
    `<text x="${toX(i)}" y="${padding.top + chartH + 20}" text-anchor="middle" font-size="12" fill="#334155">${l.level}</text>`,
  ).join('\n  ');

  const legend = series.map((s, i) =>
    `<rect x="${width - 70}" y="${padding.top + i * 22}" width="12" height="12" fill="${s.color}" rx="2"/>
  <text x="${width - 54}" y="${padding.top + i * 22 + 10}" font-size="11" fill="#334155">${s.label}</text>`,
  ).join('\n  ');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" aria-label="Concurrency Scaling">
  <title>Concurrency Scaling</title>
  <style>text { font-family: system-ui, -apple-system, sans-serif; }</style>
  <text x="${width / 2}" y="30" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">Concurrency Scaling</text>
  <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${padding.left + chartW}" y2="${padding.top + chartH}" stroke="#cbd5e1" stroke-width="1"/>
  <text x="${width / 2}" y="${height - 10}" text-anchor="middle" font-size="12" fill="#64748b">Concurrent connections</text>
${lines}
  ${xLabels}
  ${legend}
</svg>`;
}

export function generateFalsePositiveCard(legit: LegitimateTrafficResult): string {
  const width = 800;
  const height = 300;
  const rate = (legit.falsePositiveRate * 100).toFixed(3);
  const pass = legit.falsePositiveRate < 0.001;
  const color = pass ? '#22c55e' : '#ef4444';
  const status = pass ? 'PASS' : 'FAIL';

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" aria-label="False Positive Rate">
  <title>False Positive Rate: ${rate}%</title>
  <style>text { font-family: system-ui, -apple-system, sans-serif; }</style>
  <rect x="0" y="0" width="${width}" height="${height}" fill="#f8fafc" rx="8"/>
  <text x="${width / 2}" y="60" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">False Positive Rate</text>
  <text x="${width / 2}" y="150" text-anchor="middle" font-size="64" font-weight="bold" fill="${color}">${rate}%</text>
  <text x="${width / 2}" y="190" text-anchor="middle" font-size="16" fill="#64748b">${legit.falsePositives} / ${legit.total} requests incorrectly blocked</text>
  <text x="${width / 2}" y="230" text-anchor="middle" font-size="20" font-weight="bold" fill="${color}">${status}</text>
  <text x="${width / 2}" y="260" text-anchor="middle" font-size="12" fill="#94a3b8">Target: &lt;0.1%</text>
</svg>`;
}
