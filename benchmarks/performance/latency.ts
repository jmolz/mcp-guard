/**
 * Latency measurement — per-request latency overhead through the daemon.
 */

import { readDaemonKey } from '../../src/identity/daemon-key.js';
import { connectSocket, writeFramed, readFramed } from '../../tests/fixtures/framing.js';
import type { LatencyResult } from '../types.js';
import { buildMcpMessage } from '../security/generator.js';

function computePercentiles(durations: number[]): LatencyResult {
  const sorted = [...durations].sort((a, b) => a - b);
  const n = sorted.length;
  if (n === 0) {
    return { count: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0, meanMs: 0, minMs: 0, maxMs: 0 };
  }

  const p50 = sorted[Math.floor(n * 0.5)];
  const p95 = sorted[Math.floor(n * 0.95)];
  const p99 = sorted[Math.floor(n * 0.99)];
  const mean = durations.reduce((a, b) => a + b, 0) / n;

  return {
    count: n,
    p50Ms: p50,
    p95Ms: p95,
    p99Ms: p99,
    meanMs: Math.round(mean * 100) / 100,
    minMs: sorted[0],
    maxMs: sorted[n - 1],
  };
}

export async function measureLatency(
  socketPath: string,
  keyPath: string,
  server: string,
  count: number,
): Promise<LatencyResult> {
  const socket = await connectSocket(socketPath);
  const key = await readDaemonKey(keyPath);
  writeFramed(socket, { type: 'auth', key: key.toString('hex') });
  const authResp = (await readFramed(socket)) as { type: string };
  if (authResp.type !== 'auth_ok') {
    throw new Error(`Auth failed: ${JSON.stringify(authResp)}`);
  }

  const durations: number[] = [];

  for (let i = 0; i < count; i++) {
    const msg = buildMcpMessage('tools/call', {
      name: 'read_file',
      arguments: { path: '/README.md' },
    });

    const start = performance.now();
    writeFramed(socket, { type: 'mcp', server, data: msg });
    await readFramed(socket, 10000);
    const elapsed = performance.now() - start;
    durations.push(elapsed);

    if ((i + 1) % 2000 === 0) {
      console.log(`  Latency: ${i + 1}/${count} requests`);
    }
  }

  socket.destroy();
  return computePercentiles(durations);
}

export { computePercentiles };
