/**
 * PII Request Leak scenario generator.
 *
 * Generates 450+ scenarios that embed PII values in tool-call request
 * parameters across all 8 mock servers.  The PII interceptor should
 * either BLOCK (ssn, credit_card) or redact-then-PASS (email, phone,
 * aws_key, github_token) every request that contains PII.
 *
 * Request-side redaction is transparent to the client: the PII is
 * removed before the request reaches the upstream server, but the
 * client receives a normal response.  From the benchmark runner's
 * perspective (which observes from the client side), redact-action
 * PII types result in a PASS decision.
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import { buildToolCallScenario, MOCK_SERVERS, stratifiedSample } from '../generator.js';

// ---------------------------------------------------------------------------
// PII test values — all verified against the regex patterns in
// src/pii/regex-detector.ts.  Credit cards pass Luhn.
// ---------------------------------------------------------------------------

const PII_SAMPLES: Record<string, string[]> = {
  email: [
    'test@example.com',
    'user.name+tag@domain.co.uk',
    'admin@company.org',
    'a.b.c@test.io',
    'first.last@sub.domain.com',
  ],
  phone: [
    '+1-555-123-4567',
    '(555) 987-6543',
    '555.123.4567',
    '+15551234567',
    '1-800-555-0199',
  ],
  ssn: [
    '123-45-6789',
    '234-56-7890',
    '345-67-8901',
    '456-78-9012',
    '567-89-0123',
  ],
  credit_card: [
    '4111111111111111',
    '5500000000000004',
    '340000000000009',
    '6011000000000004',
    '4242424242424242',
  ],
  aws_key: [
    'AKIAIOSFODNN7EXAMPLE',
    'AKIAI44QH8DHBEXAMPLE',
    'AKIAIX2GCBYA3EXAMPLE',
    'AKIAJF5GH7T2NEXAMPLE',
    'AKIAIRN7AQFM5KEXAMPLE',
  ],
  github_token: [
    'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
    'ghp_1234567890abcdefABCDEF1234567890ab',
    'gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
    'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
    'ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
  ],
};

// ---------------------------------------------------------------------------
// Request-side PII actions from security-benchmark.yaml
// ---------------------------------------------------------------------------

/** PII types whose request action is 'block' → expectedDecision BLOCK */
const BLOCK_TYPES = new Set(['ssn', 'credit_card']);

/** PII types whose request action is 'redact' → expectedDecision PASS
 *  Request-side redaction is transparent: the client sees a normal response.
 *  Redaction is verified post-run via the audit log integrity check. */
const REDACT_TYPES = new Set(['email', 'phone', 'aws_key', 'github_token']);

function expectedDecisionForType(piiType: string): 'BLOCK' | 'PASS' {
  if (BLOCK_TYPES.has(piiType)) return 'BLOCK';
  if (REDACT_TYPES.has(piiType)) return 'PASS';
  // Fail-closed: unknown types block
  return 'BLOCK';
}

// ---------------------------------------------------------------------------
// Allowed tools per server (must NOT be in the server's denied_tools list)
// ---------------------------------------------------------------------------

const SERVER_TOOLS: Record<string, { tool: string; argName: string }[]> = {
  filesystem: [
    { tool: 'read_file', argName: 'path' },
    { tool: 'list_directory', argName: 'path' },
  ],
  database: [
    { tool: 'query_sql', argName: 'query' },
    { tool: 'describe_table', argName: 'table' },
  ],
  'api-client': [
    { tool: 'http_get', argName: 'url' },
  ],
  'git-ops': [
    { tool: 'git_clone', argName: 'url' },
    { tool: 'git_status', argName: 'path' },
  ],
  shell: [
    { tool: 'install_package', argName: 'name' },
  ],
  communication: [
    { tool: 'send_email', argName: 'body' },
    { tool: 'send_slack_message', argName: 'message' },
  ],
  'cloud-infra': [
    { tool: 'deploy_service', argName: 'config' },
    { tool: 'list_instances', argName: 'filter' },
  ],
  'sampling-server': [
    { tool: 'echo', argName: 'text' },
  ],
};

// ---------------------------------------------------------------------------
// Parameter position strategies — how PII is embedded in tool args
// ---------------------------------------------------------------------------

type EmbedStrategy = 'direct' | 'concatenated' | 'json_string';

interface EmbedResult {
  args: Record<string, unknown>;
  label: string;
}

function embedPii(
  argName: string,
  piiValue: string,
  strategy: EmbedStrategy,
): EmbedResult {
  switch (strategy) {
    case 'direct':
      return {
        args: { [argName]: piiValue },
        label: 'direct value',
      };
    case 'concatenated':
      return {
        args: { [argName]: `Please process the following: ${piiValue} and return results` },
        label: 'concatenated in text',
      };
    case 'json_string':
      return {
        args: { [argName]: JSON.stringify({ data: piiValue, action: 'process' }) },
        label: 'wrapped in JSON string',
      };
  }
}

const EMBED_STRATEGIES: EmbedStrategy[] = ['direct', 'concatenated', 'json_string'];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const CATEGORY = 'pii_request_leak';

export class PiiRequestLeakGenerator implements ScenarioGenerator {
  readonly category = CATEGORY;

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const piiTypes = Object.keys(PII_SAMPLES);

    for (const piiType of piiTypes) {
      const samples = PII_SAMPLES[piiType];
      const decision = expectedDecisionForType(piiType);

      for (const server of MOCK_SERVERS) {
        const tools = SERVER_TOOLS[server];
        if (!tools) continue;

        for (const { tool, argName } of tools) {
          for (const piiValue of samples) {
            for (const strategy of EMBED_STRATEGIES) {
              const { args, label } = embedPii(argName, piiValue, strategy);

              scenarios.push(
                buildToolCallScenario({
                  id: `${CATEGORY}-${index}`,
                  category: CATEGORY,
                  description:
                    `${piiType} PII (${label}) in ${tool} on ${server} — ` +
                    `expect ${decision}`,
                  server,
                  toolName: tool,
                  args,
                  expectedDecision: decision,
                  expectedInterceptor: 'pii-detect',
                }),
              );
              index++;
            }
          }
        }
      }
    }

    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
