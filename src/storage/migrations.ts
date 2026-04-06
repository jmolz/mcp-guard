import type Database from 'better-sqlite3-multiple-ciphers';
import { StorageError } from '../errors.js';

interface Migration {
  name: string;
  up(db: Database.Database): void;
}

const migrations: Migration[] = [
  {
    name: '001-schema-migrations',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          name TEXT PRIMARY KEY,
          applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      `);
    },
  },
  {
    name: '002-daemon-state',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS daemon_state (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      `);
    },
  },
  {
    name: '003-audit-logs',
    up(db) {
      db.exec(`
        CREATE TABLE audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp TEXT NOT NULL DEFAULT (datetime('now')),
          bridge_id TEXT NOT NULL,
          server TEXT NOT NULL,
          method TEXT NOT NULL,
          direction TEXT NOT NULL CHECK(direction IN ('request', 'response')),
          identity_uid INTEGER NOT NULL,
          identity_username TEXT NOT NULL,
          identity_roles TEXT NOT NULL,
          tool_or_resource TEXT,
          params_summary TEXT,
          interceptor_decisions TEXT NOT NULL,
          allowed INTEGER NOT NULL,
          blocked_by TEXT,
          block_reason TEXT,
          latency_ms REAL,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX idx_audit_server ON audit_logs(server);
        CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX idx_audit_method ON audit_logs(method);
        CREATE INDEX idx_audit_identity ON audit_logs(identity_username);
      `);
    },
  },
  {
    name: '004-rate-limits',
    up(db) {
      db.exec(`
        CREATE TABLE rate_limits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT NOT NULL UNIQUE,
          tokens REAL NOT NULL,
          max_tokens REAL NOT NULL,
          refill_rate REAL NOT NULL,
          last_refill TEXT NOT NULL DEFAULT (datetime('now')),
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      `);
    },
  },
];

export function runMigrations(db: Database.Database): void {
  // Ensure schema_migrations table exists for the first migration
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  const applied = new Set(
    db
      .prepare('SELECT name FROM schema_migrations')
      .all()
      .map((row) => (row as { name: string }).name),
  );

  for (const migration of migrations) {
    if (applied.has(migration.name)) {
      continue;
    }

    const transaction = db.transaction(() => {
      migration.up(db);
      db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(migration.name);
    });

    try {
      transaction();
    } catch (err) {
      throw new StorageError(`Migration '${migration.name}' failed: ${String(err)}`);
    }
  }
}
