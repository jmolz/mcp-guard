import type Database from 'better-sqlite3-multiple-ciphers';
import type { AuditLogRow, AuditFilters } from './store.js';

/**
 * Query audit logs directly from SQLite (for CLI use).
 * This opens a read-only connection to the database.
 */
export function queryAuditLogs(db: Database.Database, filters: AuditFilters): AuditLogRow[] {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filters.server) {
    conditions.push('server = ?');
    params.push(filters.server);
  }

  if (filters.user) {
    conditions.push('identity_username = ?');
    params.push(filters.user);
  }

  if (filters.method) {
    conditions.push('method = ?');
    params.push(filters.method);
  }

  if (filters.type === 'allow') {
    conditions.push('allowed = 1');
  } else if (filters.type === 'block') {
    conditions.push('allowed = 0');
  }

  if (filters.last) {
    const modifier = parseTimeModifier(filters.last);
    if (modifier) {
      conditions.push("timestamp >= datetime('now', ?)");
      params.push(modifier);
    }
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = filters.limit ?? 100;

  const sql = `SELECT * FROM audit_logs ${where} ORDER BY timestamp DESC LIMIT ?`;
  params.push(limit);

  return db.prepare(sql).all(...params) as AuditLogRow[];
}

export function formatAuditRow(row: AuditLogRow): string {
  const status = row.allowed ? '\x1b[32mALLOW\x1b[0m' : '\x1b[31mBLOCK\x1b[0m';
  const blockInfo = row.blocked_by ? ` [${row.blocked_by}: ${row.block_reason}]` : '';
  const tool = row.tool_or_resource ? ` → ${row.tool_or_resource}` : '';
  const latency = row.latency_ms !== null ? ` (${row.latency_ms.toFixed(1)}ms)` : '';

  return `${row.timestamp} ${status} ${row.identity_username}@${row.server} ${row.method}${tool}${blockInfo}${latency}`;
}

function parseTimeModifier(duration: string): string | null {
  const match = duration.match(/^(\d+)(m|h|d)$/);
  if (!match) return null;

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 'm': return `-${value} minutes`;
    case 'h': return `-${value} hours`;
    case 'd': return `-${value} days`;
    default: return null;
  }
}
