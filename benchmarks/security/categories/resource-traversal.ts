/**
 * Resource traversal scenario generator.
 *
 * Produces 450+ scenarios that attempt path traversal attacks via
 * `resources/read` requests. Covers encoding evasion, URI scheme case
 * tricks, backslash variants, extra URI components, and cross-server
 * testing.
 *
 * Every scenario expects BLOCK from the permissions interceptor.
 */

import type { BenchmarkScenario, GeneratorOptions, ScenarioGenerator } from '../../types.js';
import { MOCK_SERVERS, DENIED_RESOURCES_PER_SERVER, buildResourceReadScenario, stratifiedSample } from '../generator.js';

/**
 * Check if a URI would be blocked by the denied_resources patterns on a server.
 * Uses the same glob → regex conversion as MCP-Guard's permissions interceptor:
 * `*` maps to `[^/]*` (single-level match, not recursive).
 */
function matchesDeniedResource(uri: string, server: string): boolean {
  const patterns = DENIED_RESOURCES_PER_SERVER[server] ?? [];
  for (const pattern of patterns) {
    // Convert glob to regex: escape special chars, then convert * to [^/]*
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    const regexStr = '^' + escaped.replace(/\*/g, '[^/]*') + '$';
    try {
      const regex = new RegExp(regexStr);
      if (regex.test(uri)) return true;
    } catch {
      // Invalid regex — pattern doesn't match
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Base traversal targets
// ---------------------------------------------------------------------------

/** Common traversal targets an attacker would pursue. */
const TRAVERSAL_TARGETS = [
  { path: '../../etc/passwd', label: 'passwd' },
  { path: '../secret', label: 'secret' },
  { path: '../../.env', label: 'dotenv' },
  { path: '../../../root/.ssh/id_rsa', label: 'ssh-key' },
  { path: '../../etc/shadow', label: 'shadow' },
  { path: '../../../home/user/.bashrc', label: 'bashrc' },
  { path: '../../proc/self/environ', label: 'proc-environ' },
  { path: '../../../var/log/auth.log', label: 'auth-log' },
  { path: '../../etc/hosts', label: 'hosts' },
  { path: '../../../tmp/credentials.json', label: 'credentials' },
  { path: '../../.git/config', label: 'git-config' },
  { path: '../../../etc/kubernetes/admin.conf', label: 'k8s-admin' },
  { path: '../../.aws/credentials', label: 'aws-creds' },
  { path: '../../../etc/ssl/private/server.key', label: 'ssl-key' },
  { path: '../../database.sqlite', label: 'sqlite-db' },
] as const;

// ---------------------------------------------------------------------------
// Encoding variation helpers
// ---------------------------------------------------------------------------

interface EncodingVariation {
  label: string;
  transform: (path: string) => string;
}

/** Produce encoding-evasion variations of a traversal path. */
const ENCODING_VARIATIONS: EncodingVariation[] = [
  {
    label: 'raw',
    transform: (p) => p,
  },
  {
    label: 'url-encoded-dots',
    // ../  -> %2e%2e%2f
    transform: (p) => p.replace(/\.\.\//g, '%2e%2e%2f'),
  },
  {
    label: 'url-encoded-slash-only',
    // ../  -> ..%2f
    transform: (p) => p.replace(/\.\.\//g, '..%2f'),
  },
  {
    label: 'double-encoded',
    // ../  -> %252e%252e%252f
    transform: (p) => p.replace(/\.\.\//g, '%252e%252e%252f'),
  },
  {
    label: 'null-byte-suffix',
    transform: (p) => `${p}%00`,
  },
  {
    label: 'null-byte-before-ext',
    transform: (p) => `${p}%00.txt`,
  },
  {
    label: 'backslash',
    // ../  -> ..\
    transform: (p) => p.replace(/\.\.\//g, '..\\'),
  },
  {
    label: 'mixed-slash',
    // ../  -> ..\/ (alternating)
    transform: (p) => {
      let toggle = false;
      return p.replace(/\.\.\//g, () => {
        toggle = !toggle;
        return toggle ? '..\\/': '../';
      });
    },
  },
  {
    label: 'overlong-utf8-dot',
    // Use %c0%ae as overlong UTF-8 encoding of '.'
    transform: (p) => p.replace(/\.\.\//g, '%c0%ae%c0%ae/'),
  },
  {
    label: 'unicode-fullwidth-dot',
    // Use fullwidth full stop U+FF0E
    transform: (p) => p.replace(/\.\.\//g, '\uFF0E\uFF0E/'),
  },
];

// ---------------------------------------------------------------------------
// URI scheme case variations
// ---------------------------------------------------------------------------

const SCHEME_CASES = [
  { label: 'lowercase', scheme: 'file:' },
  { label: 'UPPERCASE', scheme: 'FILE:' },
  { label: 'TitleCase', scheme: 'File:' },
  { label: 'mIxEdCaSe', scheme: 'fIlE:' },
] as const;

// ---------------------------------------------------------------------------
// Extra URI component tricks
// ---------------------------------------------------------------------------

interface UriComponentTrick {
  label: string;
  transform: (uri: string) => string;
}

const URI_COMPONENT_TRICKS: UriComponentTrick[] = [
  {
    label: 'query-string',
    transform: (uri) => `${uri}?bypass=true`,
  },
  {
    label: 'fragment',
    transform: (uri) => `${uri}#section1`,
  },
  {
    label: 'query-and-fragment',
    transform: (uri) => `${uri}?a=1#top`,
  },
  {
    label: 'port-in-authority',
    // Inject a port into the URI authority: file://localhost:8080/../../...
    transform: (uri) => uri.replace('file://', 'file://localhost:8080/'),
  },
  {
    label: 'userinfo-in-authority',
    transform: (uri) => uri.replace('file://', 'file://user:pass@host/'),
  },
  {
    label: 'double-slash-padding',
    transform: (uri) => uri.replace('file://', 'file:////'),
  },
  {
    label: 'trailing-dot-segment',
    transform: (uri) => `${uri}/.`,
  },
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class ResourceTraversalGenerator implements ScenarioGenerator {
  readonly category = 'resource_traversal';

  generate(options?: GeneratorOptions): BenchmarkScenario[] {
    const scenarios: BenchmarkScenario[] = [];
    let index = 0;

    const nextId = (): string => `${this.category}-${index++}`;

    // ------------------------------------------------------------------
    // Axis 1 x 2: Base traversal paths with encoding variations
    // on filesystem server (15 targets x 10 encodings = 150)
    // ------------------------------------------------------------------
    for (const target of TRAVERSAL_TARGETS) {
      for (const enc of ENCODING_VARIATIONS) {
        const encodedPath = enc.transform(target.path);
        const uri = `file://${encodedPath}`;
        const blocked = matchesDeniedResource(uri, 'filesystem');
        scenarios.push(
          buildResourceReadScenario({
            id: nextId(),
            category: this.category,
            description: `Traversal to ${target.label} with ${enc.label} encoding on filesystem`,
            server: 'filesystem',
            uri,
            expectedDecision: blocked ? 'BLOCK' : 'PASS',
            ...(blocked ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 3: URI scheme case variations
    // (15 targets x 4 scheme cases = 60, on filesystem)
    // ------------------------------------------------------------------
    for (const target of TRAVERSAL_TARGETS) {
      for (const sc of SCHEME_CASES) {
        const uri = `${sc.scheme}//${target.path}`;
        const blocked = matchesDeniedResource(uri, 'filesystem');
        scenarios.push(
          buildResourceReadScenario({
            id: nextId(),
            category: this.category,
            description: `Scheme case "${sc.label}" traversal to ${target.label} on filesystem`,
            server: 'filesystem',
            uri,
            expectedDecision: blocked ? 'BLOCK' : 'PASS',
            ...(blocked ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 4: Cross-server traversal (all 8 servers)
    // Use the top-5 most critical targets with raw encoding.
    // (5 targets x 8 servers = 40)
    // ------------------------------------------------------------------
    const criticalTargets = TRAVERSAL_TARGETS.slice(0, 5);
    for (const target of criticalTargets) {
      for (const server of MOCK_SERVERS) {
        const uri = `file://${target.path}`;
        const hasDeniedResources = (DENIED_RESOURCES_PER_SERVER[server] ?? []).length > 0;
        scenarios.push(
          buildResourceReadScenario({
            id: nextId(),
            category: this.category,
            description: `Cross-server traversal to ${target.label} on "${server}"`,
            server,
            uri,
            expectedDecision: hasDeniedResources ? 'BLOCK' : 'PASS',
            ...(hasDeniedResources ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 4b: Cross-server with encoding tricks
    // (3 dangerous encodings x 5 targets x 8 servers = 120)
    // ------------------------------------------------------------------
    const dangerousEncodings = ENCODING_VARIATIONS.filter((e) =>
      ['double-encoded', 'null-byte-suffix', 'backslash'].includes(e.label),
    );
    for (const enc of dangerousEncodings) {
      for (const target of criticalTargets) {
        for (const server of MOCK_SERVERS) {
          const uri = `file://${enc.transform(target.path)}`;
          const hasDeniedResources = (DENIED_RESOURCES_PER_SERVER[server] ?? []).length > 0;
          scenarios.push(
            buildResourceReadScenario({
              id: nextId(),
              category: this.category,
              description: `Cross-server ${enc.label} traversal to ${target.label} on "${server}"`,
              server,
              uri,
              expectedDecision: hasDeniedResources ? 'BLOCK' : 'PASS',
              ...(hasDeniedResources ? { expectedInterceptor: 'permissions' } : {}),
            }),
          );
        }
      }
    }

    // ------------------------------------------------------------------
    // Axis 5: Extra URI component tricks
    // (7 tricks x 15 targets = 105, on filesystem)
    // ------------------------------------------------------------------
    for (const trick of URI_COMPONENT_TRICKS) {
      for (const target of TRAVERSAL_TARGETS) {
        const baseUri = `file://${target.path}`;
        const uri = trick.transform(baseUri);
        const blocked = matchesDeniedResource(uri, 'filesystem');
        scenarios.push(
          buildResourceReadScenario({
            id: nextId(),
            category: this.category,
            description: `URI trick "${trick.label}" traversal to ${target.label} on filesystem`,
            server: 'filesystem',
            uri,
            expectedDecision: blocked ? 'BLOCK' : 'PASS',
            ...(blocked ? { expectedInterceptor: 'permissions' } : {}),
          }),
        );
      }
    }

    // ------------------------------------------------------------------
    // Axis 3 x 4: Scheme cases on all servers (top-3 targets)
    // (4 schemes x 3 targets x 8 servers = 96)
    // ------------------------------------------------------------------
    const topTargets = TRAVERSAL_TARGETS.slice(0, 3);
    for (const sc of SCHEME_CASES) {
      for (const target of topTargets) {
        for (const server of MOCK_SERVERS) {
          const uri = `${sc.scheme}//${target.path}`;
          const hasDeniedResources = (DENIED_RESOURCES_PER_SERVER[server] ?? []).length > 0;
          scenarios.push(
            buildResourceReadScenario({
              id: nextId(),
              category: this.category,
              description: `Scheme "${sc.label}" traversal to ${target.label} on "${server}"`,
              server,
              uri,
              expectedDecision: hasDeniedResources ? 'BLOCK' : 'PASS',
              ...(hasDeniedResources ? { expectedInterceptor: 'permissions' } : {}),
            }),
          );
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
