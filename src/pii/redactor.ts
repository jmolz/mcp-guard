import type { PIIMatch, PIIMatchSafe, ScanResult } from './types.js';

/**
 * Replace PII matches in a string with redaction markers.
 * Returns a NEW string — the original is not mutated.
 * Processes spans in reverse order to preserve offsets.
 * Overlapping matches: sort by start, skip matches that overlap with a previous one.
 */
export function redactString(content: string, matches: PIIMatch[]): string {
  if (matches.length === 0) return content;

  // Sort by start, deduplicate overlapping spans (keep earlier match)
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  const nonOverlapping: PIIMatch[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      nonOverlapping.push(m);
      lastEnd = m.end;
    }
  }

  // Process in reverse to preserve offsets
  let result = content;
  for (let i = nonOverlapping.length - 1; i >= 0; i--) {
    const m = nonOverlapping[i];
    const marker = `[REDACTED:${m.type}]`;
    result = result.slice(0, m.start) + marker + result.slice(m.end);
  }

  return result;
}

/**
 * Recursively walk a JSON-compatible value, scanning every string with the
 * provided detector function, collecting matches, and optionally redacting.
 *
 * Returns { matches, redacted } where:
 * - matches: all PIIMatch found, with `path` indicating where in the structure
 * - redacted: deep clone with matched spans replaced (original untouched)
 */
export function scanAndRedact(
  value: unknown,
  detect: (content: string) => PIIMatch[],
  shouldRedact: boolean,
): ScanResult {
  const allMatches: Array<PIIMatchSafe & { path: string }> = [];

  function walk(val: unknown, path: string): unknown {
    if (typeof val === 'string') {
      const matches = detect(val);
      for (const m of matches) {
        // Strip value field — only type, confidence, start, end, path survive
        allMatches.push({ type: m.type, confidence: m.confidence, start: m.start, end: m.end, path });
      }
      if (shouldRedact && matches.length > 0) {
        return redactString(val, matches);
      }
      return val;
    }

    if (Array.isArray(val)) {
      return val.map((item, i) => walk(item, path ? `${path}[${i}]` : `[${i}]`));
    }

    if (val !== null && typeof val === 'object') {
      const result: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(val)) {
        result[key] = walk(child, path ? `${path}.${key}` : key);
      }
      return result;
    }

    // Numbers, booleans, null — return as-is
    return val;
  }

  const redacted = walk(value, '');

  return { matches: allMatches, redacted };
}
