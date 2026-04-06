import type Database from 'better-sqlite3-multiple-ciphers';

export interface RateLimitConfig {
  maxTokens: number;
  refillRate: number; // tokens per second
}

export interface RateLimitStore {
  /** Try to consume one token. Returns true if allowed, false if rate limited. */
  tryConsume(key: string, config: RateLimitConfig): boolean;
  /** Get remaining tokens for a key */
  getRemaining(key: string): number | null;
  /** Clean up expired entries */
  cleanup(olderThan: Date): void;
}

export function createRateLimitStore(db: Database.Database): RateLimitStore {
  const upsertStmt = db.prepare(`
    INSERT INTO rate_limits (key, tokens, max_tokens, refill_rate, last_refill, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
    ON CONFLICT(key) DO UPDATE SET
      tokens = excluded.tokens,
      max_tokens = excluded.max_tokens,
      refill_rate = excluded.refill_rate,
      last_refill = excluded.last_refill,
      updated_at = excluded.updated_at
  `);

  // Update tokens and updated_at only — preserves last_refill for denied requests
  const updateTokensStmt = db.prepare(`
    UPDATE rate_limits SET tokens = ?, updated_at = datetime('now') WHERE key = ?
  `);

  const selectStmt = db.prepare(`
    SELECT tokens, max_tokens, refill_rate, last_refill
    FROM rate_limits WHERE key = ?
  `);

  const deleteStmt = db.prepare(`
    DELETE FROM rate_limits WHERE updated_at < ?
  `);

  const tryConsumeTransaction = db.transaction(
    (key: string, config: RateLimitConfig): boolean => {
      const row = selectStmt.get(key) as
        | { tokens: number; max_tokens: number; refill_rate: number; last_refill: string }
        | undefined;

      if (!row) {
        // First request — initialize with maxTokens - 1 (consuming one)
        upsertStmt.run(key, config.maxTokens - 1, config.maxTokens, config.refillRate);
        return true;
      }

      // Calculate token refill — clamp to CURRENT config ceiling,
      // not the persisted max_tokens (handles tightened limits)
      const lastRefill = new Date(row.last_refill + 'Z').getTime();
      const now = Date.now();
      const elapsedSeconds = (now - lastRefill) / 1000;
      const effectiveMax = Math.min(row.max_tokens, config.maxTokens);
      const refilled = Math.min(
        effectiveMax,
        row.tokens + elapsedSeconds * config.refillRate,
      );

      if (refilled < 1) {
        // Rate limited — update token count but preserve last_refill
        // so the refill clock continues accumulating correctly
        updateTokensStmt.run(refilled, key);
        return false;
      }

      // Consume one token
      upsertStmt.run(key, refilled - 1, config.maxTokens, config.refillRate);
      return true;
    },
  );

  return {
    tryConsume(key: string, config: RateLimitConfig): boolean {
      return tryConsumeTransaction(key, config);
    },

    getRemaining(key: string): number | null {
      const row = selectStmt.get(key) as
        | { tokens: number; refill_rate: number; max_tokens: number; last_refill: string }
        | undefined;
      if (!row) return null;

      const lastRefill = new Date(row.last_refill + 'Z').getTime();
      const now = Date.now();
      const elapsedSeconds = (now - lastRefill) / 1000;
      return Math.min(row.max_tokens, row.tokens + elapsedSeconds * row.refill_rate);
    },

    cleanup(olderThan: Date): void {
      deleteStmt.run(olderThan.toISOString());
    },
  };
}
