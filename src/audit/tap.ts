import type { AuditEntry, AuditStore } from './store.js';
import type { Logger } from '../logger.js';
import type { McpGuardConfig } from '../config/schema.js';
import { formatAuditEntry } from './stdout-logger.js';

export interface AuditTap {
  record(entry: AuditEntry): void;
}

/**
 * Structural audit tap — observes every message from outside the interceptor pipeline.
 * Cannot be skipped by pipeline errors, timeouts, or misconfig.
 *
 * Audit failures must never block requests — log the error and continue.
 */
export function createAuditTap(
  store: AuditStore,
  logger: Logger,
  config: McpGuardConfig,
): AuditTap {
  return {
    record(entry: AuditEntry): void {
      if (!config.audit.enabled) {
        return;
      }

      // Write to SQLite
      try {
        store.write(entry);
      } catch (err) {
        logger.error('Audit store write failed', { error: String(err) });
      }

      // Write structured JSON to stdout if enabled
      if (config.audit.stdout) {
        try {
          process.stdout.write(formatAuditEntry(entry) + '\n');
        } catch (err) {
          logger.error('Audit stdout write failed', { error: String(err) });
        }
      }
    },
  };
}
