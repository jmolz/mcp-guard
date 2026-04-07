/**
 * Tier 2 compatibility tests — test MCP-Guard against real open-source MCP servers.
 * These prove the proxy doesn't break real server protocols.
 *
 * These tests spawn real MCP server processes and require network access.
 * Run explicitly: MCP_GUARD_TIER2=1 pnpm vitest run tests/compat/tier2.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Socket } from 'node:net';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { writeFramed, readFramed, connectSocket } from '../fixtures/framing.js';

const TIER2_ENABLED = process.env['MCP_GUARD_TIER2'] === '1';

interface McpResponse {
  jsonrpc: string;
  id: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

interface ServerSpec {
  name: string;
  command: string;
  args: string[];
  /** Expected to have at least one tool */
  expectTools: boolean;
  /** A simple tool call to verify tools/call works */
  sampleCall?: { name: string; arguments: Record<string, unknown> };
  /** Extra env vars */
  env?: Record<string, string>;
  /** Environment variable required to run this server */
  requiredEnv?: string;
}

const SERVERS: ServerSpec[] = [
  {
    name: 'filesystem',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
    expectTools: true,
    sampleCall: { name: 'list_directory', arguments: { path: '/tmp' } },
  },
  {
    name: 'memory',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-memory'],
    expectTools: true,
    sampleCall: { name: 'create_entities', arguments: { entities: [{ name: 'test', entityType: 'test', observations: ['hello'] }] } },
  },
  {
    name: 'everything',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-everything'],
    expectTools: true,
    sampleCall: { name: 'echo', arguments: { message: 'ping' } },
  },
  {
    name: 'sequential-thinking',
    command: 'npx',
    args: ['-y', '@anthropic-ai/mcp-server-sequential-thinking'],
    expectTools: true,
    sampleCall: { name: 'sequentialthinking', arguments: { thought: 'test', nextThoughtNeeded: false, thoughtNumber: 1, totalThoughts: 1 } },
  },
  {
    name: 'fetch',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-fetch'],
    expectTools: true,
    sampleCall: { name: 'fetch', arguments: { url: 'https://example.com' } },
  },
];

describe.skipIf(!TIER2_ENABLED)('Tier 2: Real MCP server compatibility', () => {
  for (const server of SERVERS) {
    describe(server.name, () => {
      let tempDir: string;
      let socketPath: string;
      let keyPath: string;
      let daemonHandle: DaemonHandle;

      beforeAll(async () => {
        tempDir = await mkdtemp(join(tmpdir(), `mcp-guard-tier2-${server.name}-`));
        socketPath = join(tempDir, 'daemon.sock');
        keyPath = join(tempDir, 'daemon.key');

        await mkdir(tempDir, { recursive: true });
        await ensureDaemonKey(keyPath);

        const envEntries = server.env
          ? Object.entries(server.env).map(([k, v]) => `      ${k}: "${v}"`).join('\n')
          : '';

        const configYaml = `
servers:
  ${server.name}:
    transport: stdio
    command: ${server.command}
    args: ${JSON.stringify(server.args)}
${envEntries ? `    env:\n${envEntries}` : ''}
daemon:
  socket_path: "${socketPath}"
  home: "${tempDir}"
  shutdown_timeout: 5
  dashboard_port: 0
`;

        const configPath = join(tempDir, 'config.yaml');
        await writeFile(configPath, configYaml);

        const config = await loadConfig(configPath);
        daemonHandle = await startDaemon(config);

        // Give upstream server time to start (npx may need to download)
        await new Promise((r) => setTimeout(r, 5000));
      }, 30000);

      afterAll(async () => {
        if (daemonHandle) {
          await daemonHandle.shutdown();
        }
        await rm(tempDir, { recursive: true, force: true });
      });

      async function authenticatedSocket(): Promise<Socket> {
        const socket = await connectSocket(socketPath);
        const key = await readDaemonKey(keyPath);
        writeFramed(socket, { type: 'auth', key: key.toString('hex'), server: server.name });
        const response = (await readFramed(socket)) as { type: string };
        expect(response.type).toBe('auth_ok');
        return socket;
      }

      it('proxies initialize request', async () => {
        const socket = await authenticatedSocket();

        writeFramed(socket, {
          type: 'mcp',
          server: server.name,
          data: {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
              protocolVersion: '2024-11-05',
              capabilities: {},
              clientInfo: { name: 'tier2-test', version: '1.0.0' },
            },
          },
        });

        const response = (await readFramed(socket, 15000)) as { type: string; data: McpResponse };
        expect(response.type).toBe('mcp');
        expect(response.data.result).toBeDefined();
        expect(response.data.error).toBeUndefined();

        // Send initialized notification
        writeFramed(socket, {
          type: 'mcp',
          server: server.name,
          data: {
            jsonrpc: '2.0',
            method: 'notifications/initialized',
          },
        });

        socket.destroy();
      }, 20000);

      it('proxies tools/list and returns tools', async () => {
        const socket = await authenticatedSocket();

        // Initialize first
        writeFramed(socket, {
          type: 'mcp',
          server: server.name,
          data: {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
              protocolVersion: '2024-11-05',
              capabilities: {},
              clientInfo: { name: 'tier2-test', version: '1.0.0' },
            },
          },
        });
        await readFramed(socket, 15000);

        writeFramed(socket, {
          type: 'mcp',
          server: server.name,
          data: { jsonrpc: '2.0', method: 'notifications/initialized' },
        });

        // Now list tools
        writeFramed(socket, {
          type: 'mcp',
          server: server.name,
          data: {
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/list',
            params: {},
          },
        });

        const response = (await readFramed(socket, 10000)) as { type: string; data: McpResponse };
        expect(response.type).toBe('mcp');
        expect(response.data.result).toBeDefined();

        if (server.expectTools) {
          const tools = response.data.result?.tools as Array<{ name: string }> | undefined;
          expect(tools).toBeDefined();
          expect(tools!.length).toBeGreaterThan(0);
        }

        socket.destroy();
      }, 20000);

      if (server.sampleCall) {
        it('proxies one tools/call successfully', async () => {
          const socket = await authenticatedSocket();

          // Initialize
          writeFramed(socket, {
            type: 'mcp',
            server: server.name,
            data: {
              jsonrpc: '2.0',
              id: 1,
              method: 'initialize',
              params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: { name: 'tier2-test', version: '1.0.0' },
              },
            },
          });
          await readFramed(socket, 15000);

          writeFramed(socket, {
            type: 'mcp',
            server: server.name,
            data: { jsonrpc: '2.0', method: 'notifications/initialized' },
          });

          // Call tool
          writeFramed(socket, {
            type: 'mcp',
            server: server.name,
            data: {
              jsonrpc: '2.0',
              id: 3,
              method: 'tools/call',
              params: server.sampleCall,
            },
          });

          const response = (await readFramed(socket, 15000)) as { type: string; data: McpResponse };
          expect(response.type).toBe('mcp');
          expect(response.data.result).toBeDefined();
          expect(response.data.error).toBeUndefined();

          socket.destroy();
        }, 20000);
      }
    });
  }
});
