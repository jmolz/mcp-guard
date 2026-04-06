import type { AuditEntry } from './store.js';

/**
 * Format an audit entry as single-line JSON for structured stdout logging.
 * Designed for container log pipelines (ELK, Datadog, etc.).
 */
export function formatAuditEntry(entry: AuditEntry): string {
  const blockedDecision = entry.pipelineResult.decisions.find(
    (d) => d.decision.action === 'BLOCK',
  );

  return JSON.stringify({
    type: 'audit',
    timestamp: new Date().toISOString(),
    server: entry.server,
    method: entry.method,
    direction: entry.direction,
    identity: entry.identity.username,
    roles: entry.identity.roles,
    allowed: entry.pipelineResult.allowed,
    blocked_by: blockedDecision?.interceptor ?? null,
    block_reason: blockedDecision?.decision.action === 'BLOCK'
      ? blockedDecision.decision.reason
      : null,
    tool_or_resource: entry.toolOrResource ?? null,
    latency_ms: entry.latencyMs ?? null,
  });
}
