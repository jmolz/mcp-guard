/**
 * Rate-limit evasion burst group generator.
 *
 * Produces ~27 burst groups containing 400+ total requests that test whether
 * the rate-limit interceptor correctly blocks requests once per-minute and
 * per-tool limits are exceeded.
 *
 * Each burst group targets a unique (server, tool) combination so groups
 * can run independently without cross-contamination.
 */

import type { BurstGroup, BurstGroupGenerator, GeneratorOptions } from '../../types.js';
import { buildMcpMessage, MOCK_SERVERS, stratifiedSample } from '../generator.js';

// ---------------------------------------------------------------------------
// Allowed tools per server (tools NOT on the denied list)
// ---------------------------------------------------------------------------

const ALLOWED_TOOLS: Record<string, string[]> = {
  filesystem: ['read_file', 'write_file', 'list_directory', 'search_files'],
  database: ['query_sql', 'describe_table', 'create_table'],
  'api-client': ['http_get', 'http_post', 'http_put', 'http_delete', 'list_endpoints'],
  'git-ops': ['git_clone', 'git_push', 'git_create_pr', 'git_status'],
  shell: ['install_package'],
  communication: ['send_email', 'send_slack_message', 'send_webhook', 'read_contacts'],
  'cloud-infra': ['deploy_service', 'list_instances', 'get_credentials'],
  'sampling-server': ['echo', 'analyze_text'],
};

// ---------------------------------------------------------------------------
// Per-tool rate limits (from security-benchmark.yaml)
// ---------------------------------------------------------------------------

interface PerToolLimit {
  server: string;
  tool: string;
  limitPerMinute: number;
}

const PER_TOOL_LIMITS: PerToolLimit[] = [
  { server: 'filesystem', tool: 'write_file', limitPerMinute: 10 },
  { server: 'database', tool: 'query_sql', limitPerMinute: 20 },
];

// ---------------------------------------------------------------------------
// Argument templates for realistic tool calls
// ---------------------------------------------------------------------------

function argsForTool(tool: string, index: number): Record<string, unknown> {
  switch (tool) {
    case 'read_file':
      return { path: `/tmp/bench/file-${index}.txt` };
    case 'write_file':
      return { path: `/tmp/bench/out-${index}.txt`, content: `data-${index}` };
    case 'list_directory':
      return { path: `/tmp/bench/dir-${index}` };
    case 'search_files':
      return { pattern: `pattern-${index}`, path: '/tmp/bench' };
    case 'query_sql':
      return { query: `SELECT * FROM t WHERE id = ${index}` };
    case 'describe_table':
      return { table: `table_${index}` };
    case 'create_table':
      return { name: `bench_${index}`, columns: ['id', 'val'] };
    case 'http_get':
      return { url: `https://api.example.com/items/${index}` };
    case 'http_post':
      return { url: 'https://api.example.com/items', body: { n: index } };
    case 'http_put':
      return { url: `https://api.example.com/items/${index}`, body: { n: index } };
    case 'http_delete':
      return { url: `https://api.example.com/items/${index}` };
    case 'list_endpoints':
      return { filter: `group-${index}` };
    case 'git_clone':
      return { url: `https://github.com/org/repo-${index}.git` };
    case 'git_push':
      return { remote: 'origin', branch: `branch-${index}` };
    case 'git_create_pr':
      return { title: `PR ${index}`, branch: `feature-${index}` };
    case 'git_status':
      return { path: `/repos/repo-${index}` };
    case 'install_package':
      return { name: `pkg-${index}`, manager: 'npm' };
    case 'send_email':
      return { to: `contact-${index}`, subject: `bench ${index}`, body: `test body ${index}` };
    case 'send_slack_message':
      return { channel: `#bench-${index}`, text: `msg ${index}` };
    case 'send_webhook':
      return { url: `https://hooks.example.com/${index}`, payload: {} };
    case 'read_contacts':
      return { query: `contact-${index}` };
    case 'deploy_service':
      return { service: `svc-${index}`, region: 'us-east-1' };
    case 'list_instances':
      return { filter: `tag:bench-${index}` };
    case 'get_credentials':
      return { service: `creds-${index}` };
    case 'echo':
      return { text: `echo-${index}` };
    case 'analyze_text':
      return { text: `Sample text for analysis run ${index}` };
    default:
      return { index };
  }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class RateLimitEvasionGenerator implements BurstGroupGenerator {
  readonly category = 'rate_limit_evasion' as const;

  generate(options?: GeneratorOptions): BurstGroup[] {
    const burstGroups: BurstGroup[] = [];
    let groupIndex = 0;

    const nextId = (): string => `${this.category}-${groupIndex++}`;

    // ---------------------------------------------------------------
    // RPM burst groups: 65 requests per (server, tool) combo.
    // First 60 PASS (at the 60 RPM limit), remaining 5 BLOCK.
    // Use up to 3 tools per server to get ~24 groups.
    // ---------------------------------------------------------------
    const RPM_LIMIT = 60;
    const RPM_BURST_SIZE = 65;

    for (const server of MOCK_SERVERS) {
      const tools = ALLOWED_TOOLS[server];
      // Skip tools with per-tool limits (they get their own burst groups below)
      const perToolNames = PER_TOOL_LIMITS
        .filter((ptl) => ptl.server === server)
        .map((ptl) => ptl.tool);

      const rpmTools = tools.filter((t) => !perToolNames.includes(t));

      // Use only ONE tool per server for RPM burst testing.
      // Rate limits have a server-level requests_per_minute bucket shared across
      // all tools. Running multiple burst groups on the same server would drain the
      // shared bucket in the first group, causing false BLOCK in subsequent groups.
      const rpmTool = rpmTools[0];
      for (const tool of rpmTool ? [rpmTool] : []) {
        const requests: BurstGroup['requests'] = [];

        for (let i = 0; i < RPM_BURST_SIZE; i++) {
          requests.push({
            message: buildMcpMessage('tools/call', {
              name: tool,
              arguments: argsForTool(tool, i),
            }),
            expectedDecision: i < RPM_LIMIT ? 'PASS' : 'BLOCK',
          });
        }

        burstGroups.push({
          id: nextId(),
          category: 'rate_limit_evasion',
          description: `RPM burst: ${RPM_BURST_SIZE} rapid "${tool}" calls on "${server}" (limit ${RPM_LIMIT}/min)`,
          server,
          requests,
        });
      }
    }

    // ---------------------------------------------------------------
    // Per-tool limit burst groups.
    // filesystem/write_file: 10/min → send 12, first 10 PASS, next 2 BLOCK
    // database/query_sql: 20/min → send 22, first 20 PASS, next 2 BLOCK
    // ---------------------------------------------------------------
    for (const ptl of PER_TOOL_LIMITS) {
      const burstSize = ptl.limitPerMinute + 2;
      const requests: BurstGroup['requests'] = [];

      for (let i = 0; i < burstSize; i++) {
        requests.push({
          message: buildMcpMessage('tools/call', {
            name: ptl.tool,
            arguments: argsForTool(ptl.tool, i),
          }),
          expectedDecision: i < ptl.limitPerMinute ? 'PASS' : 'BLOCK',
        });
      }

      burstGroups.push({
        id: nextId(),
        category: 'rate_limit_evasion',
        description: `Per-tool limit burst: ${burstSize} "${ptl.tool}" calls on "${ptl.server}" (limit ${ptl.limitPerMinute}/min)`,
        server: ptl.server,
        requests,
      });
    }

    // Quick mode: stratified sample of burst groups
    if (options?.quick) {
      return stratifiedSample(burstGroups, 10);
    }

    return burstGroups;
  }
}
