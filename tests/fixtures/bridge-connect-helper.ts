/**
 * Helper script spawned as a child process to test bridge behavior.
 * Reads socket and key paths from environment variables so the bridge
 * can connect to a test daemon with isolated temp paths.
 *
 * Usage: MCP_GUARD_TEST_SOCKET=<path> MCP_GUARD_TEST_KEY=<path> npx tsx tests/fixtures/bridge-connect-helper.ts <serverName>
 * Exit code: 0 if bridge connected successfully (stdin closed), 1 on auth failure or error
 */

import { startBridge } from '../../src/bridge/index.js';

const socketPath = process.env['MCP_GUARD_TEST_SOCKET'];
const keyPath = process.env['MCP_GUARD_TEST_KEY'];
const serverName = process.argv[2] ?? 'mock';

if (!socketPath || !keyPath) {
  process.stderr.write('Missing MCP_GUARD_TEST_SOCKET or MCP_GUARD_TEST_KEY\n');
  process.exit(2);
}

try {
  await startBridge(serverName, undefined, { socketPath, keyPath });
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Bridge error: ${message}\n`);
  process.exit(1);
}
