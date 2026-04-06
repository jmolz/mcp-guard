import type Database from 'better-sqlite3-multiple-ciphers';
import type { ResolvedIdentity, PipelineResult } from '../interceptors/types.js';

export interface AuditEntry {
  bridgeId: string;
  server: string;
  method: string;
  direction: 'request' | 'response';
  identity: ResolvedIdentity;
  toolOrResource?: string;
  paramsSummary?: string;
  pipelineResult: PipelineResult;
  latencyMs?: number;
}

export interface AuditFilters {
  server?: string;
  last?: string;
  user?: string;
  method?: string;
  type?: 'allow' | 'block';
  limit?: number;
}

export interface AuditStore {
  write(entry: AuditEntry): void;
  query(filters: AuditFilters): AuditLogRow[];
  cleanup(olderThanDays: number): number;
}

export interface AuditLogRow {
  id: number;
  timestamp: string;
  bridge_id: string;
  server: string;
  method: string;
  direction: string;
  identity_uid: number;
  identity_username: string;
  identity_roles: string;
  tool_or_resource: string | null;
  params_summary: string | null;
  interceptor_decisions: string;
  allowed: number;
  blocked_by: string | null;
  block_reason: string | null;
  latency_ms: number | null;
}

export function createAuditStore(db: Database.Database): AuditStore {
  const insertStmt = db.prepare(`
    INSERT INTO audit_logs (
      bridge_id, server, method, direction,
      identity_uid, identity_username, identity_roles,
      tool_or_resource, params_summary,
      interceptor_decisions, allowed, blocked_by, block_reason, latency_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const cleanupStmt = db.prepare(`
    DELETE FROM audit_logs WHERE timestamp < datetime('now', ?)
  `);

  return {
    write(entry: AuditEntry): void {
      const blockedDecision = entry.pipelineResult.decisions.find(
        (d) => d.decision.action === 'BLOCK',
      );

      insertStmt.run(
        entry.bridgeId,
        entry.server,
        entry.method,
        entry.direction,
        entry.identity.uid,
        entry.identity.username,
        JSON.stringify(entry.identity.roles),
        entry.toolOrResource ?? null,
        entry.paramsSummary ?? null,
        JSON.stringify(
          entry.pipelineResult.decisions.map((d) => ({
            name: d.interceptor,
            action: d.decision.action,
            reason: d.decision.action === 'BLOCK' ? d.decision.reason : undefined,
            durationMs: d.durationMs,
          })),
        ),
        entry.pipelineResult.allowed ? 1 : 0,
        blockedDecision?.interceptor ?? null,
        blockedDecision?.decision.action === 'BLOCK' ? blockedDecision.decision.reason : null,
        entry.latencyMs ?? null,
      );
    },

    query(filters: AuditFilters): AuditLogRow[] {
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
    },

    cleanup(olderThanDays: number): number {
      const result = cleanupStmt.run(`-${olderThanDays} days`);
      return result.changes;
    },
  };
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
