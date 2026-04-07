/**
 * PII Response Leak scenario generator.
 *
 * Generates 450+ scenarios that call `_benchmark_pii` on each mock server.
 * This tool unconditionally returns a response containing all 6 PII types.
 * The response-side PII interceptor should detect and redact the sensitive
 * values, resulting in a MODIFY decision for every scenario (because at
 * least ssn, credit_card, aws_key, and github_token have response action
 * 'redact', which triggers MODIFY even though email and phone are 'warn').
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import { buildToolCallScenario, MOCK_SERVERS, stratifiedSample } from '../generator.js';

// ---------------------------------------------------------------------------
// PII types present in every _benchmark_pii response
// ---------------------------------------------------------------------------

const RESPONSE_PII_TYPES = [
  'email',
  'phone',
  'ssn',
  'credit_card',
  'aws_key',
  'github_token',
] as const;

// ---------------------------------------------------------------------------
// Response-side actions from security-benchmark.yaml:
//   email→warn, phone→warn, ssn→redact, credit_card→redact,
//   aws_key→redact, github_token→redact
//
// Since _benchmark_pii returns ALL PII types, and at least 4 of 6 trigger
// 'redact', the overall pipeline decision is always MODIFY.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Variation axes for dummy arguments
// ---------------------------------------------------------------------------

/** Different dummy argument sets to vary request content across scenarios. */
const DUMMY_ARG_SETS: Array<{ label: string; args: Record<string, unknown> }> = [
  { label: 'default trigger', args: { trigger: 'all' } },
  { label: 'verbose mode', args: { trigger: 'all', verbose: true } },
  { label: 'with limit', args: { trigger: 'all', limit: 100 } },
  { label: 'with offset', args: { trigger: 'all', offset: 0 } },
  { label: 'compact mode', args: { trigger: 'all', format: 'compact' } },
  { label: 'with context', args: { trigger: 'all', context: 'benchmark-test' } },
  { label: 'with timestamp', args: { trigger: 'all', timestamp: '2025-01-01T00:00:00Z' } },
  { label: 'with metadata', args: { trigger: 'all', meta: { run: 'bench' } } },
  { label: 'with filter', args: { trigger: 'all', filter: 'none' } },
  { label: 'with depth', args: { trigger: 'all', depth: 3 } },
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const CATEGORY = 'pii_response_leak';

export class PiiResponseLeakGenerator implements ScenarioGenerator {
  readonly category = CATEGORY;

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    for (const server of MOCK_SERVERS) {
      for (const piiType of RESPONSE_PII_TYPES) {
        for (const argSet of DUMMY_ARG_SETS) {
          scenarios.push(
            buildToolCallScenario({
              id: `${CATEGORY}-${index}`,
              category: CATEGORY,
              description:
                `Response ${piiType} PII via _benchmark_pii on ${server} ` +
                `(${argSet.label}) — expect MODIFY`,
              server,
              toolName: '_benchmark_pii',
              args: argSet.args,
              expectedDecision: 'MODIFY',
              expectedInterceptor: 'pii-detect',
            }),
          );
          index++;
        }
      }
    }

    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
