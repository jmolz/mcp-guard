import { describe, it, expect } from 'vitest';
import { redactString, scanAndRedact } from '../../src/pii/redactor.js';
import type { PIIMatch } from '../../src/pii/types.js';

describe('redactString', () => {
  it('replaces single match with [REDACTED:type]', () => {
    const matches: PIIMatch[] = [
      { type: 'email', value: 'user@example.com', confidence: 0.9, start: 8, end: 24 },
    ];
    const result = redactString('Contact user@example.com today', matches);
    expect(result).toBe('Contact [REDACTED:email] today');
  });

  it('replaces multiple non-overlapping matches', () => {
    const content = 'SSN 123-45-6789 email user@test.com';
    const matches: PIIMatch[] = [
      { type: 'ssn', value: '123-45-6789', confidence: 0.95, start: 4, end: 15 },
      { type: 'email', value: 'user@test.com', confidence: 0.9, start: 22, end: 35 },
    ];
    const result = redactString(content, matches);
    expect(result).toBe('SSN [REDACTED:ssn] email [REDACTED:email]');
  });

  it('handles overlapping matches — earlier match wins', () => {
    const matches: PIIMatch[] = [
      { type: 'email', value: 'user@ex', confidence: 0.9, start: 0, end: 7 },
      { type: 'phone', value: '@ex.com', confidence: 0.8, start: 4, end: 11 },
    ];
    const result = redactString('user@ex.com', matches);
    expect(result).toBe('[REDACTED:email].com');
  });

  it('returns string unchanged when no matches', () => {
    expect(redactString('hello world', [])).toBe('hello world');
  });

  it('does not mutate the original string', () => {
    const original = 'Contact user@example.com';
    const matches: PIIMatch[] = [
      { type: 'email', value: 'user@example.com', confidence: 0.9, start: 8, end: 24 },
    ];
    redactString(original, matches);
    expect(original).toBe('Contact user@example.com');
  });
});

describe('scanAndRedact', () => {
  const detectEmails = (content: string): PIIMatch[] => {
    const regex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    const matches: PIIMatch[] = [];
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      matches.push({
        type: 'email',
        value: match[0],
        confidence: 0.9,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
    return matches;
  };

  it('scans flat object and redacts string values', () => {
    const input = { message: 'Contact user@example.com', count: 5 };
    const result = scanAndRedact(input, detectEmails, true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe('email');
    const redacted = result.redacted as Record<string, unknown>;
    expect(redacted['message']).toBe('Contact [REDACTED:email]');
    expect(redacted['count']).toBe(5);
  });

  it('scans nested objects deeply', () => {
    const input = { outer: { inner: { text: 'Email: user@test.com' } } };
    const result = scanAndRedact(input, detectEmails, true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].path).toBe('outer.inner.text');
  });

  it('scans arrays of strings', () => {
    const input = ['user@a.com', 'hello', 'admin@b.com'];
    const result = scanAndRedact(input, detectEmails, true);
    expect(result.matches).toHaveLength(2);
    const redacted = result.redacted as string[];
    expect(redacted[0]).toBe('[REDACTED:email]');
    expect(redacted[1]).toBe('hello');
    expect(redacted[2]).toBe('[REDACTED:email]');
  });

  it('skips numbers, booleans, and null', () => {
    const input = { num: 42, bool: true, nil: null, str: 'test@test.com' };
    const result = scanAndRedact(input, detectEmails, true);
    expect(result.matches).toHaveLength(1);
    const redacted = result.redacted as Record<string, unknown>;
    expect(redacted['num']).toBe(42);
    expect(redacted['bool']).toBe(true);
    expect(redacted['nil']).toBe(null);
  });

  it('returns matches but unmodified clone when shouldRedact is false', () => {
    const input = { msg: 'user@example.com' };
    const result = scanAndRedact(input, detectEmails, false);
    expect(result.matches).toHaveLength(1);
    const redacted = result.redacted as Record<string, unknown>;
    expect(redacted['msg']).toBe('user@example.com');
  });

  it('tracks correct JSON paths', () => {
    const input = { a: { b: ['test@test.com'] } };
    const result = scanAndRedact(input, detectEmails, true);
    expect(result.matches[0].path).toBe('a.b[0]');
  });

  it('does not mutate the original object', () => {
    const input = { msg: 'user@example.com', nested: { text: 'admin@test.com' } };
    const clone = JSON.parse(JSON.stringify(input));
    scanAndRedact(input, detectEmails, true);
    expect(input).toEqual(clone);
  });
});
