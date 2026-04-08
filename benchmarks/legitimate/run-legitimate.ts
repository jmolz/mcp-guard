/**
 * Legitimate traffic runner — runs 10,000+ benign requests and measures false positive rate.
 */

import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { connectSocket, writeFramed, readFramed } from '../../tests/fixtures/framing.js';
import type { GeneratorOptions, LegitimateTrafficResult, ScenarioResult } from '../types.js';
import { LegitimateTrafficGenerator } from './generator.js';

interface McpResponse {
  type: string;
  data?: {
    jsonrpc: string;
    id?: number;
    result?: Record<string, unknown>;
    error?: { code: number; message: string };
  };
}

function inferDecision(response: McpResponse): 'PASS' | 'BLOCK' | 'MODIFY' {
  if (!response.data) return 'BLOCK';
  if (response.data.error) {
    if (response.data.error.code === -32600) return 'BLOCK';
    // Upstream errors (method not found, etc.) are not false positives
    return 'PASS';
  }
  const resultStr = JSON.stringify(response.data.result ?? {});
  if (resultStr.includes('[REDACTED')) return 'MODIFY';
  return 'PASS';
}

export async function runLegitimateTraffic(
  configPath: string,
  options?: GeneratorOptions,
): Promise<LegitimateTrafficResult> {
  const tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-bench-legit-'));
  const socketPath = join(tempDir, 'daemon.sock');
  const keyPath = join(tempDir, 'daemon.key');
  let daemonHandle: DaemonHandle | undefined;

  try {
    await ensureDaemonKey(keyPath);

    // Rewrite config paths
    const raw = await readFile(configPath, 'utf-8');
    const rewritten = raw
      .replace(/__SOCKET_PATH__/g, socketPath)
      .replace(/__HOME__/g, tempDir);
    const outPath = join(tempDir, 'config.yaml');
    await writeFile(outPath, rewritten);

    const config = await loadConfig(outPath);
    daemonHandle = await startDaemon(config);

    await new Promise((r) => setTimeout(r, 3000));

    // Authenticate a single socket for all requests (throughput optimization)
    const socket = await connectSocket(socketPath);
    const key = await readDaemonKey(keyPath);
    writeFramed(socket, { type: 'auth', key: key.toString('hex') });
    const authResp = (await readFramed(socket)) as { type: string };
    if (authResp.type !== 'auth_ok') {
      throw new Error(`Auth failed: ${JSON.stringify(authResp)}`);
    }

    const generator = new LegitimateTrafficGenerator();
    const scenarios = generator.generate(options);
    console.log(`  Running ${scenarios.length} legitimate traffic scenarios...`);

    const results: ScenarioResult[] = [];
    let falsePositives = 0;

    for (let i = 0; i < scenarios.length; i++) {
      const scenario = scenarios[i];
      const start = Date.now();
      writeFramed(socket, { type: 'mcp', server: scenario.server, data: scenario.message });
      const response = (await readFramed(socket, 10000)) as McpResponse;
      const durationMs = Date.now() - start;

      const actualDecision = inferDecision(response);
      const passed = actualDecision === scenario.expectedDecision;

      if (!passed) {
        falsePositives++;
        // Log only false positives for debugging (don't log 10K+ successes)
        console.log(`  FP: ${scenario.description} — expected ${scenario.expectedDecision}, got ${actualDecision}`);
      }

      results.push({
        scenario,
        actualDecision,
        durationMs,
        passed,
      });

      // Progress update every 2000 requests
      if ((i + 1) % 2000 === 0) {
        console.log(`  Progress: ${i + 1}/${scenarios.length} (${falsePositives} FPs so far)`);
      }
    }

    socket.destroy();

    const total = results.length;
    const fpRate = total > 0 ? falsePositives / total : 0;

    console.log(`  Completed: ${total} requests, ${falsePositives} false positives (${(fpRate * 100).toFixed(3)}%)`);

    return {
      total,
      passed: total - falsePositives,
      falsePositives,
      falsePositiveRate: fpRate,
      scenarios: results,
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
  runLegitimateTraffic('benchmarks/configs/legitimate-benchmark.yaml', { quick })
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((err) => {
      console.error('Legitimate traffic benchmark failed:', err);
      process.exit(1);
    });
}
