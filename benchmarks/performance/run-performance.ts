/**
 * Performance benchmark runner — orchestrates latency and concurrency benchmarks.
 */

import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { ensureDaemonKey } from '../../src/identity/daemon-key.js';
import type { GeneratorOptions, PerformanceBenchmarkResult } from '../types.js';
import { measureLatency } from './latency.js';
import { measureConcurrency } from './concurrency.js';

export async function runPerformanceBenchmark(
  configPath: string,
  options?: GeneratorOptions,
): Promise<PerformanceBenchmarkResult> {
  const tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-bench-perf-'));
  const socketPath = join(tempDir, 'daemon.sock');
  const keyPath = join(tempDir, 'daemon.key');
  let daemonHandle: DaemonHandle | undefined;

  try {
    await ensureDaemonKey(keyPath);

    const raw = await readFile(configPath, 'utf-8');
    const rewritten = raw
      .replace(/__SOCKET_PATH__/g, socketPath)
      .replace(/__HOME__/g, tempDir);
    const outPath = join(tempDir, 'config.yaml');
    await writeFile(outPath, rewritten);

    const config = await loadConfig(outPath);
    daemonHandle = await startDaemon(config);

    await new Promise((r) => setTimeout(r, 2000));

    const server = 'filesystem';
    const latencyCount = options?.quick ? 1000 : 10000;
    const concurrencyLevels = options?.quick ? [1, 10] : [1, 10, 50, 100];
    const requestsPerSocket = options?.quick ? 20 : 100;

    // Latency benchmark
    console.log(`  Measuring latency: ${latencyCount} requests...`);
    const latency = await measureLatency(socketPath, keyPath, server, latencyCount);
    console.log(`  Latency p50=${latency.p50Ms.toFixed(1)}ms p95=${latency.p95Ms.toFixed(1)}ms p99=${latency.p99Ms.toFixed(1)}ms`);

    // Concurrency benchmark
    console.log('  Measuring concurrency...');
    const concurrency = await measureConcurrency(socketPath, keyPath, server, concurrencyLevels, requestsPerSocket);

    // Throughput: total requests / total time from highest concurrency level
    const maxLevel = concurrencyLevels[concurrencyLevels.length - 1];
    const maxResult = concurrency[maxLevel];
    const totalRequests = maxLevel * requestsPerSocket;
    const totalTimeSec = (maxResult.meanMs * totalRequests) / (maxLevel * 1000);
    const throughput = totalTimeSec > 0 ? totalRequests / totalTimeSec : 0;

    return {
      latency,
      concurrency,
      throughput: Math.round(throughput),
    };
  } finally {
    if (daemonHandle) {
      await daemonHandle.shutdown();
    }
    await rm(tempDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*[\\/]/, ''))) {
  const quick = process.argv.includes('--quick');
  runPerformanceBenchmark('benchmarks/configs/performance-benchmark.yaml', { quick })
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((err) => {
      console.error('Performance benchmark failed:', err);
      process.exit(1);
    });
}
