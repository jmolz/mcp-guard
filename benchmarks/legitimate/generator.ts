/**
 * Legitimate traffic generator — produces 10,000+ benign MCP requests
 * that should all PASS the interceptor pipeline. Any BLOCK is a false positive.
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../types.js';
import {
  MOCK_SERVERS,
  buildToolCallScenario,
  buildResourceReadScenario,
  buildMcpMessage,
  stratifiedSample,
} from '../security/generator.js';

/** Allowed tools per server (excludes denied tools from security config). */
const ALLOWED_TOOLS: Record<string, Array<{ name: string; args: () => Record<string, unknown> }>> = {
  filesystem: [
    { name: 'read_file', args: () => ({ path: randomPath() }) },
    // write_file has 10/min rate limit — only use read-only tools for bulk traffic
    { name: 'list_directory', args: () => ({ path: randomDir() }) },
    { name: 'search_files', args: () => ({ pattern: '*.ts', path: '/src' }) },
  ],
  database: [
    // query_sql has 20/min rate limit — avoid hitting it with bulk traffic
    { name: 'describe_table', args: () => ({ name: randomTableName() }) },
    { name: 'create_table', args: () => ({ name: randomTableName(), columns: 'id INT, name TEXT' }) },
  ],
  'api-client': [
    { name: 'http_get', args: () => ({ url: randomSafeUrl() }) },
    { name: 'http_post', args: () => ({ url: randomSafeUrl(), body: JSON.stringify({ key: randomWord() }) }) },
    { name: 'http_put', args: () => ({ url: randomSafeUrl(), body: JSON.stringify({ value: randomInt() }) }) },
    { name: 'http_delete', args: () => ({ url: randomSafeUrl() }) },
    { name: 'list_endpoints', args: () => ({}) },
  ],
  'git-ops': [
    { name: 'git_clone', args: () => ({ repo: `https://github.com/example/${randomWord()}` }) },
    { name: 'git_push', args: () => ({ remote: 'origin', branch: `feature/${randomWord()}` }) },
    { name: 'git_create_pr', args: () => ({ title: `Add ${randomWord()}`, body: randomSafeText() }) },
    { name: 'git_status', args: () => ({}) },
  ],
  shell: [
    { name: 'install_package', args: () => ({ name: randomPackageName(), manager: randomManager() }) },
  ],
  communication: [
    { name: 'send_slack_message', args: () => ({ channel: `#${randomWord()}`, message: randomSafeText() }) },
    { name: 'send_webhook', args: () => ({ url: randomSafeUrl(), payload: JSON.stringify({ event: randomWord() }) }) },
    { name: 'read_contacts', args: () => ({}) },
  ],
  'cloud-infra': [
    { name: 'deploy_service', args: () => ({ service: randomWord(), env: randomEnv() }) },
    { name: 'list_instances', args: () => ({}) },
    { name: 'get_credentials', args: () => ({ service: randomWord() }) },
  ],
  'sampling-server': [
    { name: 'echo', args: () => ({ message: randomSafeText() }) },
    { name: 'analyze_text', args: () => ({ text: randomSafeText() }) },
  ],
};

/** Resources per server. */
const RESOURCES: Record<string, string[]> = {
  filesystem: ['file://readme'],
  database: ['db://schema'],
  'api-client': ['api://spec'],
  'git-ops': ['git://log'],
};

// ---------------------------------------------------------------------------
// Safe content generators — NO PII patterns
// ---------------------------------------------------------------------------

const WORDS = [
  'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
  'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
  'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
  'yankee', 'zulu', 'widget', 'gadget', 'sprocket', 'flange', 'bracket', 'pivot',
];

const PATHS = [
  '/src/index.ts', '/README.md', '/package.json', '/tsconfig.json',
  '/src/utils/helpers.ts', '/tests/unit/app.test.ts', '/docs/guide.md',
  '/config/settings.yaml', '/lib/core.ts', '/bin/cli.ts',
];

const DIRS = ['/src', '/tests', '/docs', '/config', '/lib', '/bin', '/scripts'];

const TABLE_NAMES = [
  'users', 'orders', 'products', 'inventory', 'sessions', 'events',
  'metrics', 'logs', 'settings', 'permissions', 'roles', 'tokens',
];

const URLS = [
  'https://api.example.com/v1/items',
  'https://api.example.com/v1/users',
  'https://api.example.com/v2/search',
  'https://internal.service/health',
  'https://cdn.example.com/assets',
];

const ENVS = ['staging', 'production', 'development', 'testing', 'canary'];
const MANAGERS = ['npm', 'pnpm', 'yarn', 'pip', 'cargo'];
const PACKAGES = ['lodash', 'express', 'zod', 'vitest', 'typescript', 'react', 'axios'];

/**
 * Benign text that MUST NOT trigger PII detection.
 * Avoids: email patterns, phone patterns, SSN format, CC numbers, AWS keys, GitHub tokens.
 */
const SAFE_TEXTS = [
  'The quick brown fox jumps over the lazy dog',
  'Hello world from the benchmark suite',
  'Processing data in batch mode',
  'Configuration updated successfully',
  'Task completed without errors',
  'Deploying version 2.3.1 to staging',
  'Running integration tests on CI',
  'Optimizing database queries for performance',
  'Refactoring authentication module',
  'Added new feature flag for dark mode',
  'Build succeeded in 42 seconds',
  'Cache invalidated for region us-east',
  'Migrating schema from v3 to v4',
  'Health check passed all endpoints',
  'Metrics dashboard updated with latest data',
  'Rotating log files for archival',
  'Scaling worker pool from 4 to 8 instances',
  'Backup completed for all tables',
  'Webhook delivery confirmed',
  'Token refresh handled automatically',
];

/**
 * Edge cases that look like PII but aren't.
 * CRITICAL: Every entry MUST be verified against the regex detector to ensure
 * zero matches at confidence >= 0.8. Avoid:
 * - 10+ consecutive digits (matches phone)
 * - 13-19 digit numbers starting with 4/5/3/6 (matches CC prefix before Luhn)
 * - Strings with @ in user@domain pattern (matches email)
 * - 3-2-4 digit pattern with dashes (matches SSN)
 * - AKIA + 16 uppercase alphanumeric (matches AWS key)
 * - ghp_ + 36 alphanumeric (matches GitHub token)
 */
const NEAR_PII_TEXTS = [
  'Zip code 90210 is in Beverly Hills',
  'Version 1.2.3.4 released today',
  'Error code 12345 returned by API',
  'Build number 98765 passed',
  'Port 8080 is already in use',
  'Timeout after 30 seconds',
  'Offset 65536 exceeds buffer size',
  'RGB color value 255 128 064',
  'Latitude 37.7749 and Longitude 122.4194',
  'Process ID 42195 running on host',
  'Hash abcdef verified ok',
  'Memory 16384 MB allocated',
  'File size 1024 bytes total',
  'Transaction ID TXN-789 processed',
  'Serial SN-321 registered',
  'Contact user dot name at domain dot com',
  'Filename test.example.config',
  'Retry count 3 of 5 attempts',
  'Queue depth 42 messages pending',
  'Cluster node 7 healthy',
  'Cache hit ratio 0.95 percent',
];

let _seed = 42;
function seededRandom(): number {
  _seed = (_seed * 1103515245 + 12345) & 0x7fffffff;
  return _seed / 0x7fffffff;
}

function randomFrom<T>(arr: readonly T[]): T {
  return arr[Math.floor(seededRandom() * arr.length)];
}

function randomWord(): string { return randomFrom(WORDS); }
function randomPath(): string { return randomFrom(PATHS); }
function randomDir(): string { return randomFrom(DIRS); }
function randomTableName(): string { return randomFrom(TABLE_NAMES); }
function randomSafeUrl(): string { return randomFrom(URLS); }
function randomEnv(): string { return randomFrom(ENVS); }
function randomManager(): string { return randomFrom(MANAGERS); }
function randomPackageName(): string { return randomFrom(PACKAGES); }
function randomInt(): number { return Math.floor(seededRandom() * 10000); }

function randomSafeText(): string {
  return seededRandom() > 0.3
    ? randomFrom(SAFE_TEXTS)
    : randomFrom(NEAR_PII_TEXTS);
}

function randomSafeQuery(): string {
  const table = randomTableName();
  const queries = [
    `SELECT * FROM ${table} LIMIT 10`,
    `SELECT COUNT(*) FROM ${table}`,
    `SELECT id, name FROM ${table} WHERE id > 0`,
    `SELECT DISTINCT type FROM ${table}`,
  ];
  return randomFrom(queries);
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class LegitimateTrafficGenerator implements ScenarioGenerator {
  category = 'legitimate_traffic';

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    _seed = 42; // Reset for determinism
    const scenarios: BenchmarkScenario[] = [];
    let idx = 0;

    // 1. tools/list requests — 100 per server = 800
    for (const server of MOCK_SERVERS) {
      for (let i = 0; i < 100; i++) {
        scenarios.push({
          id: `legitimate-${idx++}`,
          category: this.category,
          description: `tools/list on ${server} (#${i})`,
          server,
          message: buildMcpMessage('tools/list', {}),
          expectedDecision: 'PASS',
        });
      }
    }

    // 2. resources/list requests — 100 per server = 800
    for (const server of MOCK_SERVERS) {
      for (let i = 0; i < 100; i++) {
        scenarios.push({
          id: `legitimate-${idx++}`,
          category: this.category,
          description: `resources/list on ${server} (#${i})`,
          server,
          message: buildMcpMessage('resources/list', {}),
          expectedDecision: 'PASS',
        });
      }
    }

    // 3. resources/read for known resources — ~400
    for (const [server, uris] of Object.entries(RESOURCES)) {
      for (const uri of uris) {
        for (let i = 0; i < 100; i++) {
          scenarios.push(buildResourceReadScenario({
            id: `legitimate-${idx++}`,
            category: this.category,
            description: `resources/read ${uri} on ${server} (#${i})`,
            server,
            uri,
            expectedDecision: 'PASS',
          }));
        }
      }
    }

    // 4. tools/call with benign params — bulk of the 10K
    // ~225 per (server, tool) combination to ensure 10K+ total
    for (const server of MOCK_SERVERS) {
      const tools = ALLOWED_TOOLS[server];
      if (!tools) continue;
      const perTool = Math.ceil(900 / tools.length);
      for (const tool of tools) {
        for (let i = 0; i < perTool; i++) {
          scenarios.push(buildToolCallScenario({
            id: `legitimate-${idx++}`,
            category: this.category,
            description: `${tool.name} on ${server} with benign args (#${i})`,
            server,
            toolName: tool.name,
            args: tool.args(),
            expectedDecision: 'PASS',
          }));
        }
      }
    }

    // 5. Near-PII edge cases — content that looks like PII but isn't
    // 21 texts × 8 servers × 3 tools = ~504
    for (const server of MOCK_SERVERS) {
      const tools = ALLOWED_TOOLS[server];
      if (!tools) continue;
      const firstTool = tools[0];
      for (const text of NEAR_PII_TEXTS) {
        // Use a tool that takes a string arg
        const args = server === 'filesystem'
          ? { path: `/docs/${text.slice(0, 20).replace(/\s/g, '-')}` }
          : server === 'database'
            ? { query: `SELECT * FROM data WHERE note = '${text}'` }
            : server === 'sampling-server'
              ? { message: text }
              : firstTool.args();

        scenarios.push(buildToolCallScenario({
          id: `legitimate-${idx++}`,
          category: this.category,
          description: `near-PII edge case on ${server}: ${text.slice(0, 40)}`,
          server,
          toolName: firstTool.name,
          args,
          expectedDecision: 'PASS',
        }));
      }
    }

    // 6. initialize handshakes — 100 per server = 800
    for (const server of MOCK_SERVERS) {
      for (let i = 0; i < 100; i++) {
        scenarios.push({
          id: `legitimate-${idx++}`,
          category: this.category,
          description: `initialize on ${server} (#${i})`,
          server,
          message: buildMcpMessage('initialize', {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'benchmark', version: '1.0.0' },
          }),
          expectedDecision: 'PASS',
        });
      }
    }

    if (options?.quick) {
      return stratifiedSample(scenarios, 500);
    }

    return scenarios;
  }
}
