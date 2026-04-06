import type { PIIDetector, PIIMatch, DetectionContext } from './types.js';

/** Max content length to scan — prevents catastrophic backtracking */
export const MAX_CONTENT_LENGTH = 65536;

interface PatternDef {
  type: string;
  regex: RegExp;
  confidence: number;
  validate?: (match: string) => boolean;
}

/**
 * Standard Luhn algorithm for credit card checksum validation.
 * Returns true if the digit string passes the Luhn check.
 */
export function luhnCheck(digits: string): boolean {
  const cleaned = digits.replace(/\D/g, '');
  if (cleaned.length === 0) return false;

  let sum = 0;
  let alternate = false;

  for (let i = cleaned.length - 1; i >= 0; i--) {
    let n = parseInt(cleaned[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

const PATTERNS: PatternDef[] = [
  {
    type: 'email',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    confidence: 0.9,
  },
  {
    type: 'phone',
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    confidence: 0.8,
    validate: (match: string) => {
      // Must have at least 10 digits to be a phone number
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15;
    },
  },
  {
    type: 'ssn',
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    confidence: 0.95,
  },
  {
    type: 'credit_card',
    // Matches common card prefixes: Visa (4), Mastercard (5[1-5], 2[2-7]),
    // Amex (3[47]), Discover (6011, 65, 644-649)
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}|4[4-9]\d))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b/g,
    confidence: 0.95,
    validate: (match: string) => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhnCheck(digits);
    },
  },
  {
    type: 'aws_key',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    confidence: 0.95,
  },
  {
    type: 'github_token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g,
    confidence: 0.95,
  },
];

/**
 * Create the built-in regex-based PII detector.
 * Patterns are compiled once at module load, not per-call.
 */
export function createRegexDetector(): PIIDetector {
  return {
    name: 'regex',

    detect(content: string, _ctx: DetectionContext): PIIMatch[] {
      if (!content || content.length === 0) return [];

      // Cap input length to prevent catastrophic backtracking
      const scanContent = content.length > MAX_CONTENT_LENGTH
        ? content.slice(0, MAX_CONTENT_LENGTH)
        : content;

      const matches: PIIMatch[] = [];

      for (const pattern of PATTERNS) {
        // Reset lastIndex for global regexes
        pattern.regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.regex.exec(scanContent)) !== null) {
          const value = match[0];

          // Run optional validation (e.g., Luhn for credit cards)
          if (pattern.validate && !pattern.validate(value)) {
            continue;
          }

          matches.push({
            type: pattern.type,
            value,
            confidence: pattern.confidence,
            start: match.index,
            end: match.index + value.length,
          });
        }
      }

      // Sort by start position
      matches.sort((a, b) => a.start - b.start);
      return matches;
    },
  };
}
