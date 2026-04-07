import { afterAll, describe, it, expect } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';

const BENCHMARK_DIR = join(import.meta.dirname, '..', '..', 'benchmarks', 'mock-servers');

/** Expected tools per mock server archetype (includes _benchmark_pii from base.ts). */
const EXPECTED_TOOLS: Record<string, string[]> = {
  filesystem: ['read_file', 'write_file', 'delete_file', 'list_directory', 'search_files', '_benchmark_pii'],
  database: ['query_sql', 'execute_sql', 'create_table', 'drop_table', 'describe_table', '_benchmark_pii'],
  'api-client': ['http_get', 'http_post', 'http_put', 'http_delete', 'list_endpoints', '_benchmark_pii'],
  'git-ops': ['git_clone', 'git_push', 'git_force_push', 'git_delete_branch', 'git_create_pr', 'git_status', '_benchmark_pii'],
  shell: ['run_command', 'run_script', 'install_package', '_benchmark_pii'],
  communication: ['send_email', 'send_slack_message', 'send_webhook', 'read_contacts', '_benchmark_pii'],
  'cloud-infra': ['deploy_service', 'destroy_resource', 'list_instances', 'get_credentials', '_benchmark_pii'],
  'sampling-server': ['echo', 'analyze_text', '_benchmark_pii'],
};

const MOCK_SERVERS = Object.keys(EXPECTED_TOOLS);

function spawnMockServer(name: string): ChildProcess {
  return spawn('npx', ['tsx', join(BENCHMARK_DIR, `${name}.ts`)], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

/** Send a JSON-RPC request to a mock server via stdio and read the response. */
async function sendJsonRpc(
  child: ChildProcess,
  method: string,
  params?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const id = Date.now();
    const request = JSON.stringify({ jsonrpc: '2.0', id, method, params: params ?? {} }) + '\n';

    let buffer = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timeout waiting for response to ${method}`));
    }, 10000);

    function onData(chunk: Buffer) {
      buffer += chunk.toString();
      // Try to parse each line
      const lines = buffer.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id || parsed.method) {
            cleanup();
            resolve(parsed);
            return;
          }
        } catch {
          // Not complete JSON yet
        }
      }
    }

    function cleanup() {
      clearTimeout(timer);
      child.stdout?.removeListener('data', onData);
    }

    child.stdout?.on('data', onData);
    child.stdin?.write(request);
  });
}

describe('Mock server archetypes', () => {
  for (const name of MOCK_SERVERS) {
    describe(name, () => {
      let child: ChildProcess;

      afterAll(() => {
        child?.kill('SIGTERM');
      });

      it('starts and responds to initialize', async () => {
        child = spawnMockServer(name);

        // Wait for server to be ready
        await new Promise((resolve) => setTimeout(resolve, 2000));

        // Check it hasn't crashed
        expect(child.exitCode).toBeNull();

        // Send initialize
        const initResponse = await sendJsonRpc(child, 'initialize', {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test', version: '1.0.0' },
        });

        expect(initResponse).toBeDefined();

        // Send initialized notification (required before tools/list)
        child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

        // Send tools/list and verify expected tools
        const toolsResponse = await sendJsonRpc(child, 'tools/list', {});
        expect(toolsResponse).toHaveProperty('result');

        const result = toolsResponse.result as { tools: Array<{ name: string }> };
        const toolNames = result.tools.map((t) => t.name).sort();
        const expected = [...EXPECTED_TOOLS[name]].sort();

        expect(toolNames).toEqual(expected);

        // Cleanup
        child.kill('SIGTERM');
        await new Promise<void>((resolve) => {
          child.on('exit', () => resolve());
          setTimeout(resolve, 3000);
        });
      }, 15000);
    });
  }
});
