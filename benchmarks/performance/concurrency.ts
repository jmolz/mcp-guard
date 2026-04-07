/**
 * Concurrency measurement — performance under concurrent connections.
 */

import { readDaemonKey } from '../../src/identity/daemon-key.js';
import { connectSocket, writeFramed, readFramed } from '../../tests/fixtures/framing.js';
import type { LatencyResult } from '../types.js';
import { buildMcpMessage } from '../security/generator.js';
import { computePercentiles } from './latency.js';

async function runOnSocket(
  socketPath: string,
  keyPath: string,
  server: string,
  requestCount: number,
): Promise<number[]> {
  const socket = await connectSocket(socketPath);
  const key = await readDaemonKey(keyPath);
  writeFramed(socket, { type: 'auth', key: key.toString('hex') });
  const authResp = (await readFramed(socket)) as { type: string };
  if (authResp.type !== 'auth_ok') {
    socket.destroy();
    throw new Error('Auth failed');
  }

  const durations: number[] = [];

  for (let i = 0; i < requestCount; i++) {
    const msg = buildMcpMessage('tools/call', {
      name: 'read_file',
      arguments: { path: '/README.md' },
    });

    const start = performance.now();
    writeFramed(socket, { type: 'mcp', server, data: msg });
    await readFramed(socket, 10000);
    durations.push(performance.now() - start);
  }

  socket.destroy();
  return durations;
}

export async function measureConcurrency(
  socketPath: string,
  keyPath: string,
  server: string,
  levels: number[],
  requestsPerSocket = 100,
): Promise<Record<number, LatencyResult>> {
  const results: Record<number, LatencyResult> = {};

  for (const n of levels) {
    console.log(`  Concurrency level ${n}: ${n * requestsPerSocket} total requests...`);

    const promises = Array.from({ length: n }, () =>
      runOnSocket(socketPath, keyPath, server, requestsPerSocket),
    );

    const allDurations = await Promise.all(promises);
    const flat = allDurations.flat();

    results[n] = computePercentiles(flat);
  }

  return results;
}
