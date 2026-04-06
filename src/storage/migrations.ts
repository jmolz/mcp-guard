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
