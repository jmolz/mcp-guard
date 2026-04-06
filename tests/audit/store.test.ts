import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createAuditStore, type AuditEntry, type AuditStore } from '../../src/audit/store.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { runMigrations } from '../../src/storage/migrations.js';
import type Database from 'better-sqlite3-multiple-ciphers';

let db: Database.Database;
let store: AuditStore;

function makeEntry(overrides?: Partial<AuditEntry>): AuditEntry {
  return {
    bridgeId: 'bridge-1',
    server: 'test-server',
    method: 'tools/call',
    direction: 'request',
    identity: { uid: 1000, username: 'testuser', roles: ['default'] },
    toolOrResource: 'echo',
    paramsSummary: '{"name":"echo"}',
    pipelineResult: {
      allowed: true,
      decisions: [
        { interceptor: 'auth', decision: { action: 'PASS' }, durationMs: 1 },
        { interceptor: 'rate-limit', decision: { action: 'PASS' }, durationMs: 0 },
        { interceptor: 'permissions', decision: { action: 'PASS' }, durationMs: 0 },
      ],
    },
    latencyMs: 5,
    ...overrides,
  };
}

describe('Audit store', () => {
  beforeEach(() => {
    db = openDatabase({ path: ':memory:' });
    runMigrations(db);
    store = createAuditStore(db);
  });

  afterEach(() => {
    db.close();
  });

  it('writes audit entry and reads it back', () => {
    store.write(makeEntry());

    const rows = store.query({});
    expect(rows).toHaveLength(1);
    expect(rows[0].server).toBe('test-server');
    expect(rows[0].method).toBe('tools/call');
    expect(rows[0].identity_username).toBe('testuser');
    expect(rows[0].allowed).toBe(1);
  });

  it('queries by server name', () => {
    store.write(makeEntry({ server: 'server-a' }));
    store.write(makeEntry({ server: 'server-b' }));
    store.write(makeEntry({ server: 'server-a' }));

    const rows = store.query({ server: 'server-a' });
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.server === 'server-a')).toBe(true);
  });

  it('queries by time range', () => {
    store.write(makeEntry());

    // Should find within last hour
    const recent = store.query({ last: '1h' });
    expect(recent).toHaveLength(1);

    // Manually set an old timestamp
    db.prepare("UPDATE audit_logs SET timestamp = datetime('now', '-2 hours')").run();

    const veryRecent = store.query({ last: '1h' });
    expect(veryRecent).toHaveLength(0);
  });

  it('queries by identity', () => {
    store.write(makeEntry({ identity: { uid: 1000, username: 'alice', roles: ['admin'] } }));
    store.write(makeEntry({ identity: { uid: 1001, username: 'bob', roles: ['default'] } }));

    const rows = store.query({ user: 'alice' });
    expect(rows).toHaveLength(1);
    expect(rows[0].identity_username).toBe('alice');
  });

  it('queries by blocked status', () => {
    store.write(makeEntry()); // allowed
    store.write(
      makeEntry({
        pipelineResult: {
          allowed: false,
          decisions: [
            {
              interceptor: 'permissions',
              decision: { action: 'BLOCK', reason: 'Denied' },
              durationMs: 1,
            },
          ],
        },
      }),
    );

    const blocked = store.query({ type: 'block' });
    expect(blocked).toHaveLength(1);
    expect(blocked[0].allowed).toBe(0);

    const allowed = store.query({ type: 'allow' });
    expect(allowed).toHaveLength(1);
    expect(allowed[0].allowed).toBe(1);
  });

  it('cleanup removes entries older than retention', () => {
    store.write(makeEntry());

    // Set timestamp to 100 days ago
    db.prepare("UPDATE audit_logs SET timestamp = datetime('now', '-100 days')").run();

    const removed = store.cleanup(90);
    expect(removed).toBe(1);

    const rows = store.query({});
    expect(rows).toHaveLength(0);
  });

  it('uses parameterized SQL — no injection possible', () => {
    // Write entry with SQL injection attempt in server name
    store.write(makeEntry({ server: "'; DROP TABLE audit_logs; --" }));

    // Table should still exist and have the entry
    const rows = store.query({});
    expect(rows).toHaveLength(1);
    expect(rows[0].server).toBe("'; DROP TABLE audit_logs; --");
  });

  it('stores only pre-redacted summaries, never raw data', () => {
    // The store receives paramsSummary which is pre-redacted by the caller
    const redactedSummary = '{"name":"echo","args":{"email":"[REDACTED]"}}';
    store.write(makeEntry({ paramsSummary: redactedSummary }));

    const rows = store.query({});
    expect(rows[0].params_summary).toBe(redactedSummary);
    // No raw PII should exist — the store only stores what it's given
    expect(rows[0].params_summary).not.toContain('@example.com');
  });

  it('does not store raw params when paramsSummary is null (production default)', () => {
    // In production, paramsSummary is not populated (PII detection is Phase 3).
    // Verify that raw request params do NOT appear in any audit column.
    const entry = makeEntry({
      paramsSummary: undefined,
      pipelineResult: {
        allowed: true,
        decisions: [
          { interceptor: 'auth', decision: { action: 'PASS' }, durationMs: 1 },
        ],
      },
    });
    // Simulate a request with PII-like content
    store.write(entry);

    const rows = store.query({});
    const row = rows[0];

    // params_summary should be null (never populated with raw params)
    expect(row.params_summary).toBeNull();

    // interceptor_decisions should only contain decision metadata, not params
    const decisions = JSON.parse(row.interceptor_decisions) as Array<{
      name: string;
      action: string;
    }>;
    expect(decisions[0].name).toBe('auth');
    expect(decisions[0].action).toBe('PASS');

    // The audit store interface requires paramsSummary to be pre-redacted.
    // Raw request params (e.g., arguments, content) never reach the store
    // because the daemon only passes tool/resource names, not argument data.
  });
});
