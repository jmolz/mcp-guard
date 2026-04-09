/**
 * Demo script: connects directly to the MCP-Guard daemon and sends a request
 * containing PII (SSN) to trigger a block. Shows the security pipeline in action.
 *
 * Usage: npx tsx demo/simulate-block.ts [config-path]
 */
import { connect, type Socket } from 'node:net';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadConfig } from '../src/config/loader.js';

const configPath = process.argv[2] ?? 'demo/demo-config.yaml';

function writeFramed(socket: Socket, data: unknown): void {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

function readFramed(socket: Socket, timeout = 10000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Read timeout'));
    }, timeout);

    function onData(chunk: Buffer) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + length) {
          cleanup();
          const json = buffer.subarray(4, 4 + length).toString('utf-8');
          resolve(JSON.parse(json));
        }
      }
    }
    function cleanup() {
      clearTimeout(timer);
      socket.removeListener('data', onData);
    }
    socket.on('data', onData);
  });
}

async function main(): Promise<void> {
  const config = await loadConfig(configPath);
  const socketPath = config.daemon.socket_path;
  const keyPath = join(config.daemon.home, 'daemon.key');
  const daemonKey = await readFile(keyPath);

  // Connect to daemon socket
  const socket = await new Promise<Socket>((resolve, reject) => {
    const s = connect(socketPath);
    s.on('connect', () => resolve(s));
    s.on('error', reject);
  });

  // Authenticate
  writeFramed(socket, { type: 'auth', key: daemonKey.toString('hex').trim() });
  const authResp = (await readFramed(socket)) as { type: string };
  if (authResp.type !== 'auth_ok') {
    console.error('Auth failed:', authResp);
    process.exit(1);
  }

  console.log('Connected to MCP-Guard daemon.');
  console.log('');

  // 1. Send a safe query first (should PASS)
  console.log('1) Safe query:');
  console.log('   query_sql({ query: "SELECT name FROM users LIMIT 5" })');
  writeFramed(socket, {
    type: 'mcp',
    server: 'database',
    data: {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'query_sql', arguments: { query: 'SELECT name FROM users LIMIT 5' } },
      id: 1,
    },
  });
  const safeResp = (await readFramed(socket)) as { type: string; data: { result?: unknown; error?: { message: string } } };
  if (safeResp.data?.result) {
    console.log('   -> PASS (allowed through)');
  } else {
    console.log('   -> Response:', JSON.stringify(safeResp.data?.error ?? safeResp));
  }
  console.log('');

  // 2. Send a query with an SSN (should be BLOCKED by PII detector)
  console.log('2) Query with SSN (PII):');
  console.log("   query_sql({ query: \"SELECT * FROM users WHERE ssn = '123-45-6789'\" })");
  writeFramed(socket, {
    type: 'mcp',
    server: 'database',
    data: {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'query_sql',
        arguments: { query: "SELECT * FROM users WHERE ssn = '123-45-6789'" },
      },
      id: 2,
    },
  });
  const piiResp = (await readFramed(socket)) as { type: string; data: { result?: unknown; error?: { message: string } } };
  if (piiResp.data?.error) {
    console.log('   -> BLOCKED:', piiResp.data.error.message);
  } else {
    console.log('   -> Response:', JSON.stringify(piiResp.data?.result));
  }
  console.log('');

  // 3. Try a denied tool (should be BLOCKED by permissions)
  console.log('3) Denied tool:');
  console.log('   drop_table({ name: "users" })');
  writeFramed(socket, {
    type: 'mcp',
    server: 'database',
    data: {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'drop_table', arguments: { name: 'users' } },
      id: 3,
    },
  });
  const deniedResp = (await readFramed(socket)) as { type: string; data: { result?: unknown; error?: { message: string } } };
  if (deniedResp.data?.error) {
    console.log('   -> BLOCKED:', deniedResp.data.error.message);
  } else {
    console.log('   -> Response:', JSON.stringify(deniedResp.data?.result));
  }

  socket.destroy();
}

main().catch((err) => {
  console.error('Error:', err.message ?? err);
  process.exit(1);
});
