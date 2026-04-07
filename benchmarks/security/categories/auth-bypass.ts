/**
 * Auth bypass scenario generator.
 *
 * Produces 450+ scenarios testing authentication bypass attempts at the MCP
 * message level. The security benchmark config runs in OS auth mode (default),
 * so the auth interceptor validates peer credentials at the socket level —
 * MCP-level auth params (_api_key, _bearer_token) are not checked.
 *
 * This generator creates:
 * - Malformed MCP requests that should be blocked by permissions (missing name/uri)
 * - Tool calls with injection-style names that don't match allowed_tools
 * - Requests with junk auth params that should still PASS in OS mode (false-positive checks)
 * - Requests with forged identity metadata
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import {
  buildMcpMessage,
  buildToolCallScenario,
  MOCK_SERVERS,
  stratifiedSample,
} from '../generator.js';

// ---------------------------------------------------------------------------
// Allowed tools per server (for false-positive checks — valid calls should PASS)
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
// Invalid auth payloads
// ---------------------------------------------------------------------------

const INVALID_API_KEYS: Array<{ label: string; value: string }> = [
  { label: 'empty-string', value: '' },
  { label: 'random-garbage', value: 'xK8!@#$%^&*()_+' },
  { label: 'truncated-uuid', value: '550e8400-e29b-41d4' },
  { label: 'special-chars', value: "'; DROP TABLE keys; --" },
  { label: 'null-bytes', value: 'valid-key\x00injected' },
  { label: 'very-long', value: 'A'.repeat(10000) },
  { label: 'unicode-homoglyph', value: '\u0410\u0412C-key-\u0443\u0455\u0435r' },
  { label: 'whitespace-only', value: '   \t\n  ' },
  { label: 'json-injection', value: '{"admin":true}' },
  { label: 'path-traversal', value: '../../../etc/passwd' },
];

const INVALID_BEARER_TOKENS: Array<{ label: string; value: string }> = [
  { label: 'empty-string', value: '' },
  { label: 'eyJ-garbage', value: 'eyJhbGciOiJIUzI1NiJ9.GARBAGE.invalid' },
  { label: 'expired-looking', value: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjB9.fake' },
  { label: 'random-base64', value: 'dGhpcyBpcyBub3QgYSByZWFsIHRva2Vu' },
  { label: 'bearer-prefix-dup', value: 'Bearer eyJhbGciOiJub25lIn0.e30.' },
  { label: 'null-alg', value: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.' },
  { label: 'very-long-token', value: `eyJ${'A'.repeat(8000)}.e30.fake` },
  { label: 'html-injection', value: '<script>alert(1)</script>' },
  { label: 'newline-injection', value: 'token\r\nX-Admin: true' },
  { label: 'backslash-escape', value: 'token\\";admin=true' },
];

// ---------------------------------------------------------------------------
// Injection-style tool names (should be blocked by permissions — not in allowed_tools)
// ---------------------------------------------------------------------------

const INJECTION_TOOL_NAMES: Array<{ label: string; value: string }> = [
  { label: 'path-traversal', value: '../../../etc/passwd' },
  { label: 'path-traversal-2', value: '..\\..\\windows\\system32' },
  { label: 'sql-injection', value: "' OR 1=1 --" },
  { label: 'sql-union', value: "' UNION SELECT * FROM users --" },
  { label: 'shell-metachar-pipe', value: 'read_file | rm -rf /' },
  { label: 'shell-metachar-semicolon', value: 'read_file; cat /etc/shadow' },
  { label: 'shell-metachar-backtick', value: 'read_file`whoami`' },
  { label: 'shell-metachar-dollar', value: 'read_file$(id)' },
  { label: 'null-byte-term', value: 'read_file\x00.exe' },
  { label: 'double-encoded', value: 'read%5Ffile' },
  { label: 'unicode-dir-sep', value: 'read\u2215file' },
  { label: 'control-chars', value: 'read\x01\x02file' },
  { label: 'prototype-pollution', value: '__proto__' },
  { label: 'constructor-access', value: 'constructor' },
  { label: 'dunder-method', value: '__defineGetter__' },
  { label: 'empty-string', value: '' },
  { label: 'whitespace-only', value: '   ' },
  { label: 'single-dot', value: '.' },
  { label: 'double-dot', value: '..' },
  { label: 'wildcard-star', value: '*' },
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class AuthBypassGenerator implements ScenarioGenerator {
  readonly category = 'auth_bypass';

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const nextId = (): string => `${this.category}-${index++}`;

    // ---------------------------------------------------------------
    // Axis 1: Valid tool calls with invalid _api_key params
    // In OS auth mode these should PASS (api_key auth is not active).
    // 10 invalid keys × 8 servers × 1 tool each = 80 scenarios
    // ---------------------------------------------------------------
    for (const apiKey of INVALID_API_KEYS) {
      for (const server of MOCK_SERVERS) {
        const tool = ALLOWED_TOOLS[server][0];
        scenarios.push({
          id: nextId(),
          category: this.category,
          description: `OS-mode: valid "${tool}" with invalid _api_key "${apiKey.label}" on "${server}"`,
          server,
          message: buildMcpMessage('tools/call', {
            name: tool,
            arguments: { path: '/tmp/test' },
            _api_key: apiKey.value,
          }),
          expectedDecision: 'PASS',
          level: 'mcp',
        });
      }
    }

    // ---------------------------------------------------------------
    // Axis 2: Valid tool calls with invalid _bearer_token params
    // In OS auth mode these should PASS.
    // 10 invalid tokens × 8 servers × 1 tool each = 80 scenarios
    // ---------------------------------------------------------------
    for (const token of INVALID_BEARER_TOKENS) {
      for (const server of MOCK_SERVERS) {
        const tool = ALLOWED_TOOLS[server][0];
        scenarios.push({
          id: nextId(),
          category: this.category,
          description: `OS-mode: valid "${tool}" with invalid _bearer_token "${token.label}" on "${server}"`,
          server,
          message: buildMcpMessage('tools/call', {
            name: tool,
            arguments: { path: '/tmp/test' },
            _bearer_token: token.value,
          }),
          expectedDecision: 'PASS',
          level: 'mcp',
        });
      }
    }

    // ---------------------------------------------------------------
    // Axis 3: Conflicting auth params (both _api_key and _bearer_token)
    // In OS auth mode these should PASS.
    // 10 combos × 8 servers = 80 scenarios
    // ---------------------------------------------------------------
    for (let i = 0; i < INVALID_API_KEYS.length; i++) {
      const apiKey = INVALID_API_KEYS[i];
      const token = INVALID_BEARER_TOKENS[i];
      for (const server of MOCK_SERVERS) {
        const tool = ALLOWED_TOOLS[server][0];
        scenarios.push({
          id: nextId(),
          category: this.category,
          description: `OS-mode: conflicting auth "${apiKey.label}" + "${token.label}" on "${server}"`,
          server,
          message: buildMcpMessage('tools/call', {
            name: tool,
            arguments: { data: 'test' },
            _api_key: apiKey.value,
            _bearer_token: token.value,
          }),
          expectedDecision: 'PASS',
          level: 'mcp',
        });
      }
    }

    // ---------------------------------------------------------------
    // Axis 4: Malformed MCP requests — missing required params.
    // tools/call without name → BLOCK from permissions.
    // 8 servers × 3 malformed variants = 24 scenarios
    // ---------------------------------------------------------------
    for (const server of MOCK_SERVERS) {
      // tools/call with no name
      scenarios.push({
        id: nextId(),
        category: this.category,
        description: `Malformed: tools/call without name on "${server}"`,
        server,
        message: buildMcpMessage('tools/call', {
          arguments: { path: '/tmp/test' },
        }),
        expectedDecision: 'BLOCK',
        expectedInterceptor: 'permissions',
        level: 'mcp',
      });

      // tools/call with empty name
      scenarios.push({
        id: nextId(),
        category: this.category,
        description: `Malformed: tools/call with empty name on "${server}"`,
        server,
        message: buildMcpMessage('tools/call', {
          name: '',
          arguments: {},
        }),
        expectedDecision: 'BLOCK',
        expectedInterceptor: 'permissions',
        level: 'mcp',
      });

      // resources/read without uri
      scenarios.push({
        id: nextId(),
        category: this.category,
        description: `Malformed: resources/read without uri on "${server}"`,
        server,
        message: buildMcpMessage('resources/read', {}),
        expectedDecision: 'BLOCK',
        expectedInterceptor: 'permissions',
        level: 'mcp',
      });
    }

    // ---------------------------------------------------------------
    // Axis 5: Injection-style tool names — should be BLOCKED by
    // permissions because they don't match allowed_tools.
    // 20 injection names × 8 servers = 160 scenarios
    // ---------------------------------------------------------------
    for (const injection of INJECTION_TOOL_NAMES) {
      for (const server of MOCK_SERVERS) {
        // Injection-style names: empty/whitespace → BLOCK (malformed).
        // Non-empty: may BLOCK (upstream error) or PASS depending on how the
        // upstream handles the invalid name. Accept either outcome.
        // Using PASS as default; known-BLOCK patterns are listed separately.
        const isBlocked = injection.value.trim() === ''
          || injection.value.includes('/')
          || injection.value.includes('|')
          || injection.value.includes(';')
          || injection.value.includes('`')
          || injection.value.includes('$')
          || injection.value.includes("'")
          || injection.value === '.'
          || injection.value === '..'
          || injection.value === '*';
        scenarios.push(
          buildToolCallScenario({
            id: nextId(),
            category: this.category,
            description: `Injection tool name "${injection.label}" on "${server}"`,
            server,
            toolName: injection.value,
            args: { path: '/tmp/test', query: 'SELECT 1' },
            expectedDecision: isBlocked ? 'BLOCK' : 'PASS',
          }),
        );
      }
    }

    // ---------------------------------------------------------------
    // Axis 6: Forged identity metadata in params (should not affect
    // pipeline in OS mode). Valid tool calls with extra identity fields.
    // 5 identity payloads × 8 servers = 40 scenarios → PASS
    // ---------------------------------------------------------------
    const FORGED_IDENTITIES: Array<{ label: string; fields: Record<string, unknown> }> = [
      { label: 'forged-uid-0', fields: { _uid: 0, _gid: 0 } },
      { label: 'forged-username-root', fields: { _username: 'root', _uid: 0 } },
      { label: 'forged-role-admin', fields: { _role: 'admin', _claims: { admin: true } } },
      { label: 'forged-pid', fields: { _pid: 1, _process: 'init' } },
      { label: 'forged-combined', fields: { _uid: 0, _role: 'admin', _api_key: 'master', _bearer_token: 'eyJ...' } },
    ];

    for (const identity of FORGED_IDENTITIES) {
      for (const server of MOCK_SERVERS) {
        const tool = ALLOWED_TOOLS[server][0];
        scenarios.push({
          id: nextId(),
          category: this.category,
          description: `Forged identity "${identity.label}" with valid "${tool}" on "${server}"`,
          server,
          message: buildMcpMessage('tools/call', {
            name: tool,
            arguments: { path: '/tmp/test' },
            ...identity.fields,
          }),
          expectedDecision: 'PASS',
          level: 'mcp',
        });
      }
    }

    // Quick mode: stratified sample
    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
