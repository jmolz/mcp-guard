import type Database from 'better-sqlite3-multiple-ciphers';
import { createAuditStore, type AuditLogRow, type AuditFilters } from './store.js';

/**
 * Query audit logs directly from SQLite (for CLI use).
 * Delegates to AuditStore.query() to avoid duplicating query logic.
 */
export function queryAuditLogs(db: Database.Database, filters: AuditFilters): AuditLogRow[] {
  const store = createAuditStore(db);
  return store.query(filters);
}

export function formatAuditRow(row: AuditLogRow): string {
  const status = row.allowed ? '\x1b[32mALLOW\x1b[0m' : '\x1b[31mBLOCK\x1b[0m';
  const blockInfo = row.blocked_by ? ` [${row.blocked_by}: ${row.block_reason}]` : '';
  const tool = row.tool_or_resource ? ` → ${row.tool_or_resource}` : '';
  const latency = row.latency_ms !== null ? ` (${row.latency_ms.toFixed(1)}ms)` : '';

  return `${row.timestamp} ${status} ${row.identity_username}@${row.server} ${row.method}${tool}${blockInfo}${latency}`;
}
