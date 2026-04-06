import { describe, it, expect } from 'vitest';
import { createRegexDetector, luhnCheck, MAX_CONTENT_LENGTH } from '../../src/pii/regex-detector.js';
import type { DetectionContext } from '../../src/pii/types.js';

const detector = createRegexDetector();
const ctx: DetectionContext = { direction: 'request', server: 'test' };

describe('luhnCheck', () => {
  it('returns true for valid card numbers', () => {
    expect(luhnCheck('4111111111111111')).toBe(true); // Visa
    expect(luhnCheck('5500000000000004')).toBe(true); // Mastercard
    expect(luhnCheck('378282246310005')).toBe(true);  // Amex
  });

  it('returns false for invalid card numbers', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
    expect(luhnCheck('1234567890123456')).toBe(false);
  });

  it('returns false for non-digit input', () => {
    expect(luhnCheck('')).toBe(false);
  });
});

describe('RegexDetector — email', () => {
  it('detects standard email', () => {
    const matches = detector.detect('Contact user@example.com for info', ctx);
    expect(matches).toHaveLength(1);
    expect(matches[0].type).toBe('email');
    expect(matches[0].value).toBe('user@example.com');
    expect(matches[0].confidence).toBe(0.9);
  });

  it('detects email with subdomain', () => {
    const matches = detector.detect('Email user@mail.example.com', ctx);
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe('user@mail.example.com');
  });

  it('rejects non-email strings', () => {
    const matches = detector.detect('not an email at all', ctx);
    const emails = matches.filter((m) => m.type === 'email');
    expect(emails).toHaveLength(0);
  });

  it('rejects partial matches like @example.com', () => {
    const matches = detector.detect('@example.com', ctx);
    const emails = matches.filter((m) => m.type === 'email');
    expect(emails).toHaveLength(0);
  });
});

describe('RegexDetector — phone', () => {
  it('detects US format', () => {
    const matches = detector.detect('Call 555-123-4567', ctx);
    const phones = matches.filter((m) => m.type === 'phone');
    expect(phones).toHaveLength(1);
  });

  it('detects international format', () => {
    const matches = detector.detect('Call +1-555-123-4567', ctx);
    const phones = matches.filter((m) => m.type === 'phone');
    expect(phones).toHaveLength(1);
  });

  it('rejects short numbers', () => {
    const matches = detector.detect('Number: 12345', ctx);
    const phones = matches.filter((m) => m.type === 'phone');
    expect(phones).toHaveLength(0);
  });
});

describe('RegexDetector — SSN', () => {
  it('detects standard format', () => {
    const matches = detector.detect('SSN: 123-45-6789', ctx);
    const ssns = matches.filter((m) => m.type === 'ssn');
    expect(ssns).toHaveLength(1);
    expect(ssns[0].confidence).toBe(0.95);
  });

  it('rejects invalid format (wrong grouping)', () => {
    const matches = detector.detect('Not SSN: 123-456-789', ctx);
    const ssns = matches.filter((m) => m.type === 'ssn');
    expect(ssns).toHaveLength(0);
  });

  it('rejects all-zeros area (000-xx-xxxx)', () => {
    const matches = detector.detect('Invalid: 000-12-3456', ctx);
    const ssns = matches.filter((m) => m.type === 'ssn');
    expect(ssns).toHaveLength(0);
  });
});

describe('RegexDetector — credit card', () => {
  it('detects valid Visa with Luhn', () => {
    const matches = detector.detect('Card: 4111111111111111', ctx);
    const cards = matches.filter((m) => m.type === 'credit_card');
    expect(cards).toHaveLength(1);
    expect(cards[0].confidence).toBe(0.95);
  });

  it('detects valid Mastercard with Luhn', () => {
    const matches = detector.detect('Card: 5500000000000004', ctx);
    const cards = matches.filter((m) => m.type === 'credit_card');
    expect(cards).toHaveLength(1);
  });

  it('rejects number failing Luhn check', () => {
    const matches = detector.detect('Card: 4111111111111112', ctx);
    const cards = matches.filter((m) => m.type === 'credit_card');
    expect(cards).toHaveLength(0);
  });

  it('rejects too-short numbers', () => {
    const matches = detector.detect('Number: 411111', ctx);
    const cards = matches.filter((m) => m.type === 'credit_card');
    expect(cards).toHaveLength(0);
  });
});

describe('RegexDetector — AWS key', () => {
  it('detects AKIA prefix pattern', () => {
    const matches = detector.detect('Key: AKIAIOSFODNN7EXAMPLE', ctx);
    const aws = matches.filter((m) => m.type === 'aws_key');
    expect(aws).toHaveLength(1);
    expect(aws[0].confidence).toBe(0.95);
  });

  it('rejects non-AKIA strings', () => {
    const matches = detector.detect('Key: NOTAKEY1234567890AB', ctx);
    const aws = matches.filter((m) => m.type === 'aws_key');
    expect(aws).toHaveLength(0);
  });
});

describe('RegexDetector — GitHub token', () => {
  it('detects ghp_ prefix', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const matches = detector.detect(`Token: ${token}`, ctx);
    const gh = matches.filter((m) => m.type === 'github_token');
    expect(gh).toHaveLength(1);
  });

  it('detects gho_, ghu_, ghs_, ghr_ prefixes', () => {
    for (const prefix of ['gho_', 'ghu_', 'ghs_', 'ghr_']) {
      const token = prefix + 'b'.repeat(36);
      const matches = detector.detect(`Token: ${token}`, ctx);
      const gh = matches.filter((m) => m.type === 'github_token');
      expect(gh).toHaveLength(1);
    }
  });

  it('rejects random strings', () => {
    const matches = detector.detect('Token: notavalidtoken', ctx);
    const gh = matches.filter((m) => m.type === 'github_token');
    expect(gh).toHaveLength(0);
  });
});

describe('RegexDetector — input safety', () => {
  it('truncates content exceeding MAX_CONTENT_LENGTH', () => {
    // Place an email beyond the max length — it should NOT be detected
    const padding = 'x'.repeat(MAX_CONTENT_LENGTH);
    const content = padding + 'user@example.com';
    const matches = detector.detect(content, ctx);
    const emails = matches.filter((m) => m.type === 'email');
    expect(emails).toHaveLength(0);
  });

  it('returns empty array for empty string', () => {
    expect(detector.detect('', ctx)).toEqual([]);
  });

  it('returns empty array for content with no PII', () => {
    expect(detector.detect('Hello, world! This is a normal message.', ctx)).toEqual([]);
  });
});
