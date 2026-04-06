import type { PIIDetector, PIIMatch, DetectionContext } from './types.js';
import type { PIIConfig } from '../config/schema.js';
import { createRegexDetector, MAX_CONTENT_LENGTH } from './regex-detector.js';
import { createLogger } from '../logger.js';

export interface PIIRegistry {
  /** Run all detectors against the content, return aggregated matches above confidence threshold */
  scan(content: string, ctx: DetectionContext): PIIMatch[];
}

const logger = createLogger({ component: 'pii-registry' });

/**
 * Create a PII registry with the built-in regex detector plus any custom types from config.
 * Custom regex patterns are compiled at creation time, not per-scan.
 */
export function createPIIRegistry(config: PIIConfig): PIIRegistry {
  const detectors: PIIDetector[] = [createRegexDetector()];

  // Register custom detectors from config
  for (const [typeName, customType] of Object.entries(config.custom_types)) {
    const compiledPatterns: RegExp[] = [];

    for (const pattern of customType.patterns) {
      try {
        compiledPatterns.push(new RegExp(pattern.regex, 'g'));
      } catch {
        logger.warn('Invalid custom PII regex, skipping', {
          type: typeName,
          regex: pattern.regex,
        });
      }
    }

    if (compiledPatterns.length > 0) {
      detectors.push({
        name: `custom:${typeName}`,
        detect(content: string, _ctx: DetectionContext): PIIMatch[] {
          const matches: PIIMatch[] = [];
          for (const regex of compiledPatterns) {
            regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = regex.exec(content)) !== null) {
              matches.push({
                type: typeName,
                value: match[0],
                confidence: 0.85,
                start: match.index,
                end: match.index + match[0].length,
              });
            }
          }
          return matches;
        },
      });
    }
  }

  const confidenceThreshold = config.confidence_threshold;

  return {
    scan(content: string, ctx: DetectionContext): PIIMatch[] {
      if (!content || content.length === 0) return [];

      // Cap input length once for all detectors (prevents ReDoS in custom patterns)
      const scanContent = content.length > MAX_CONTENT_LENGTH
        ? content.slice(0, MAX_CONTENT_LENGTH)
        : content;

      const allMatches: PIIMatch[] = [];

      for (const detector of detectors) {
        const matches = detector.detect(scanContent, ctx);
        allMatches.push(...matches);
      }

      // Filter by confidence threshold
      const filtered = allMatches.filter((m) => m.confidence >= confidenceThreshold);

      // Sort by start position
      filtered.sort((a, b) => a.start - b.start);

      // Deduplicate overlapping spans — keep highest confidence
      const deduped: PIIMatch[] = [];
      for (const m of filtered) {
        const overlapping = deduped.findIndex(
          (existing) => m.start < existing.end && m.end > existing.start,
        );
        if (overlapping === -1) {
          deduped.push(m);
        } else if (m.confidence >= deduped[overlapping].confidence) {
          deduped[overlapping] = m;
        }
      }

      return deduped;
    },
  };
}
