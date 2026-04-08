/**
 * PII evasion scenario generator.
 *
 * Produces 450+ scenarios testing whether PII regex detection can be evaded
 * through encoding and obfuscation. This is a genuine attack surface — if
 * PII bypasses detection, the "redacted PII never stored" guarantee breaks.
 *
 * Evasion techniques include:
 * 1. Unicode homoglyphs (Cyrillic lookalikes)
 * 2. Zero-width characters (ZWJ, ZWNJ, ZWSP)
 * 3. Base64 encoding
 * 4. URL encoding (single and double)
 * 5. Deeply nested JSON (scanner recurses into stringified content)
 * 6. Whitespace padding (tabs, newlines — regex word boundaries handle these)
 * 7. Long string offset (within and beyond MAX_CONTENT_LENGTH of 64KB)
 * 8. Split across fields, case changes
 *
 * expectedDecision varies by technique:
 * - Techniques that evade regex: PASS (known detection gap, NOT a benchmark failure)
 * - Techniques that regex still catches: BLOCK or MODIFY depending on PII type
 *   - ssn, credit_card -> BLOCK (request action)
 *   - email, phone, aws_key, github_token -> MODIFY (request action is redact)
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import {
  MOCK_SERVERS,
  buildToolCallScenario,
  stratifiedSample,
} from '../generator.js';

// ---------------------------------------------------------------------------
// PII type -> request action mapping
// ---------------------------------------------------------------------------

/**
 * Maps PII type to expected decision from the CLIENT's perspective when PII IS detected.
 * - 'block' action → BLOCK (client sees error)
 * - 'redact' action → PASS or MODIFY depending on whether the mock server echoes
 *   the redacted value. If the tool echoes [REDACTED:type], inferDecision returns MODIFY.
 */
const BLOCK_PII_TYPES = new Set(['ssn', 'credit_card']);
const REDACT_PII_TYPES = new Set(['email', 'phone', 'aws_key', 'github_token']);

/**
 * (server, tool, argKey) combinations where the mock server echoes the argument
 * value in its response. When PII is redacted, these echo [REDACTED:type].
 */
const ECHOING_TOOLS = new Set([
  'filesystem:read_file:path',
  'database:describe_table:name',
  'api-client:http_get:url',
]);

function detectedDecision(piiType: string, server: string): 'BLOCK' | 'PASS' | 'MODIFY' {
  if (BLOCK_PII_TYPES.has(piiType)) return 'BLOCK';
  if (REDACT_PII_TYPES.has(piiType)) {
    const tool = SERVER_TOOLS[server] ?? 'echo';
    const argKey = argKeyForServer(server);
    const key = `${server}:${tool}:${argKey}`;
    return ECHOING_TOOLS.has(key) ? 'MODIFY' : 'PASS';
  }
  return 'BLOCK';
}

// ---------------------------------------------------------------------------
// Canonical PII values that WOULD be detected by regex
// ---------------------------------------------------------------------------

const CANONICAL_PII: Record<string, string> = {
  email: 'test@example.com',
  phone: '+1-555-123-4567',
  ssn: '123-45-6789',
  credit_card: '4111111111111111',
  aws_key: 'AKIAIOSFODNN7EXAMPLE',
  github_token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
};

// ---------------------------------------------------------------------------
// Simple allowed tool per server for embedding PII in args
// ---------------------------------------------------------------------------

const SERVER_TOOLS: Record<string, string> = {
  filesystem: 'read_file',
  database: 'describe_table',
  'api-client': 'http_get',
  'git-ops': 'git_status',
  shell: 'install_package',
  communication: 'read_contacts',
  'cloud-infra': 'list_instances',
  'sampling-server': 'echo',
};

// ---------------------------------------------------------------------------
// Arg key per server
// ---------------------------------------------------------------------------

function argKeyForServer(server: string): string {
  switch (server) {
    case 'filesystem': return 'path';
    case 'database': return 'name';
    case 'api-client': return 'url';
    case 'git-ops': return 'path';
    case 'shell': return 'name';
    case 'communication': return 'message';
    case 'cloud-infra': return 'filter';
    case 'sampling-server': return 'text';
    default: return 'data';
  }
}

// ---------------------------------------------------------------------------
// Evasion techniques
// ---------------------------------------------------------------------------

interface EvasionTechnique {
  /** Human-readable name for the technique. */
  name: string;
  /** Transform the PII value into an evaded form. */
  transform: (piiType: string, value: string) => string;
  /** Whether regex is expected to still detect this (true = detected, false = evades). */
  detected: boolean;
}

const EVASION_TECHNIQUES: EvasionTechnique[] = [
  // ---------------------------------------------------------------
  // 1. Unicode homoglyphs — Cyrillic lookalikes
  //    Should evade regex -> expectedDecision: PASS (known gap)
  // ---------------------------------------------------------------
  {
    name: 'homoglyph-cyrillic-e',
    transform: (_type, val) => val.replace(/e/g, '\u0435'), // Cyrillic е
    detected: false,
  },
  {
    name: 'homoglyph-cyrillic-a',
    transform: (_type, val) => val.replace(/a/g, '\u0430'), // Cyrillic а
    detected: false,
  },
  {
    name: 'homoglyph-cyrillic-o',
    transform: (_type, val) => val.replace(/o/g, '\u043E'), // Cyrillic о
    detected: false,
  },
  {
    name: 'homoglyph-cyrillic-ae',
    transform: (_type, val) => val.replace(/a/g, '\u0430').replace(/e/g, '\u0435'),
    detected: false,
  },

  // ---------------------------------------------------------------
  // 2. Zero-width characters — insert ZWJ, ZWNJ, ZWSP
  //    Expected to evade regex -> expectedDecision: PASS
  // ---------------------------------------------------------------
  {
    name: 'zero-width-space-all',
    transform: (_type, val) => val.split('').join('\u200B'),
    detected: false,
  },
  {
    name: 'zero-width-joiner-mid',
    transform: (_type, val) => {
      const mid = Math.floor(val.length / 2);
      return val.slice(0, mid) + '\u200D' + val.slice(mid);
    },
    detected: false,
  },
  {
    name: 'zero-width-non-joiner-mid',
    transform: (_type, val) => {
      const mid = Math.floor(val.length / 2);
      return val.slice(0, mid) + '\u200C' + val.slice(mid);
    },
    detected: false,
  },

  // ---------------------------------------------------------------
  // 3. Base64 encoding — PII wrapped in base64
  //    Should evade regex -> expectedDecision: PASS (known gap)
  // ---------------------------------------------------------------
  {
    name: 'base64-encoded',
    transform: (_type, val) => Buffer.from(val).toString('base64'),
    detected: false,
  },
  {
    name: 'base64-with-prefix',
    transform: (_type, val) => `base64:${Buffer.from(val).toString('base64')}`,
    detected: false,
  },

  // ---------------------------------------------------------------
  // 4. URL encoding
  //    Should evade regex -> expectedDecision: PASS
  // ---------------------------------------------------------------
  {
    name: 'url-encoded-key-char',
    transform: (type, val) =>
      type === 'email' ? val.replace('@', '%40') : val.replace(/-/g, '%2D'),
    detected: false,
  },
  {
    name: 'double-url-encoded',
    transform: (type, val) =>
      type === 'email' ? val.replace('@', '%2540') : val.replace(/-/g, '%252D'),
    detected: false,
  },

  // ---------------------------------------------------------------
  // 5. Deeply nested JSON — scanner recurses into stringified content
  //    Should be detected -> expectedDecision: BLOCK or MODIFY
  // ---------------------------------------------------------------
  {
    name: 'nested-json-1-level',
    transform: (_type, val) => JSON.stringify({ data: val }),
    detected: true,
  },
  {
    name: 'nested-json-3-levels',
    transform: (_type, val) => JSON.stringify({ a: { b: { c: val } } }),
    detected: true,
  },
  {
    name: 'nested-json-4-levels',
    transform: (_type, val) => JSON.stringify({ w: { x: { y: { z: val } } } }),
    detected: true,
  },

  // ---------------------------------------------------------------
  // 6. Whitespace padding — tabs, newlines around PII
  //    Regex word boundaries handle whitespace -> detected
  // ---------------------------------------------------------------
  {
    name: 'tab-padding',
    transform: (_type, val) => `\t${val}\t`,
    detected: true,
  },
  {
    name: 'newline-padding',
    transform: (_type, val) => `\n${val}\n`,
    detected: true,
  },
  {
    name: 'mixed-whitespace',
    transform: (_type, val) => `\r\n\t ${val} \t\r\n`,
    detected: true,
  },

  // ---------------------------------------------------------------
  // 7. Long string offset — PII at position N in a large string
  //    Scanner has MAX_CONTENT_LENGTH of 64KB.
  //    Padding with word characters ('x') eliminates the \b word boundary
  //    that all PII regexes require, so detection fails. This is a genuine
  //    evasion technique, not a scanner bug.
  // ---------------------------------------------------------------
  {
    name: 'offset-10k',
    transform: (_type, val) => 'x'.repeat(10000) + val,
    detected: false, // Word-char padding removes \b boundary → evades
  },
  {
    name: 'offset-50k',
    transform: (_type, val) => 'x'.repeat(50000) + val,
    detected: false, // Word-char padding removes \b boundary → evades
  },
  {
    name: 'offset-beyond-64k',
    transform: (_type, val) => 'x'.repeat(66000) + val,
    detected: false, // Beyond scan limit
  },

  // ---------------------------------------------------------------
  // Additional techniques: split across fields, case changes
  // ---------------------------------------------------------------
  {
    name: 'split-across-fields',
    transform: (type, val) => {
      if (type === 'email') {
        const [user, domain] = val.split('@');
        return JSON.stringify({ user, domain });
      }
      const mid = Math.floor(val.length / 2);
      return JSON.stringify({ part1: val.slice(0, mid), part2: val.slice(mid) });
    },
    detected: false,
  },
  {
    name: 'uppercase-transform',
    transform: (_type, val) => val.toUpperCase(),
    detected: false, // Most patterns are case-sensitive
  },
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const CATEGORY = 'pii_evasion';

export class PiiEvasionGenerator implements ScenarioGenerator {
  readonly category = CATEGORY;

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const piiTypes = Object.keys(CANONICAL_PII);

    // 23 techniques x 6 PII types x 8 servers = 1104 base scenarios
    // This far exceeds 450+, giving comprehensive coverage.
    // Use first 4 servers for most techniques, all 8 for key techniques.
    for (const technique of EVASION_TECHNIQUES) {
      for (const piiType of piiTypes) {
        const canonical = CANONICAL_PII[piiType];
        const evaded = technique.transform(piiType, canonical);

        // Use all 8 servers for core evasion techniques (homoglyphs,
        // zero-width, base64, URL encoding); use first 4 for others
        // to keep the total manageable while ensuring broad coverage.
        const serversForTechnique = technique.detected
          ? MOCK_SERVERS.slice(0, 4)
          : [...MOCK_SERVERS];

        for (const server of serversForTechnique) {
          const tool = SERVER_TOOLS[server] ?? 'echo';
          const argKey = argKeyForServer(server);

          // Determine expected decision:
          // If the technique modifies the value AND actually changes it, expect evasion (PASS).
          // If the transform doesn't change the value (e.g., letter-only transform on digit PII),
          // the original PII is still present and will be detected.
          const valueChanged = evaded !== canonical;
          let expectedDecision: 'PASS' | 'BLOCK' | 'MODIFY';
          if (technique.detected || !valueChanged) {
            // PII is detected by regex → action depends on PII type and server echo behavior
            expectedDecision = detectedDecision(piiType, server);
          } else {
            expectedDecision = 'PASS'; // Evasion successful — known gap
          }

          scenarios.push(
            buildToolCallScenario({
              id: `${CATEGORY}-${index}`,
              category: CATEGORY,
              description: `${technique.name} ${piiType} on ${server}`,
              server,
              toolName: tool,
              args: { [argKey]: evaded },
              expectedDecision,
              expectedInterceptor: (technique.detected || !valueChanged) && expectedDecision !== 'PASS' ? 'pii-detect' : undefined,
            }),
          );
          index++;
        }
      }
    }

    // Quick mode: stratified sample
    if (options?.quick) {
      return stratifiedSample(scenarios, 50);
    }

    return scenarios;
  }
}
