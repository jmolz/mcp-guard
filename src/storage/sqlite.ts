import Database from 'better-sqlite3-multiple-ciphers';
import { chmodSync } from 'node:fs';
import { StorageError } from '../errors.js';

export interface DatabaseOptions {
  path: string;
  encryptionKey?: string;
}

export function openDatabase(options: DatabaseOptions): Database.Database {
  try {
    const db = new Database(options.path);

    if (options.encryptionKey) {
      db.pragma(`key='${options.encryptionKey}'`);
    }

    db.pragma('journal_mode = WAL');
    db.pragma('busy_timeout = 5000');
    db.pragma('foreign_keys = ON');

    if (options.path !== ':memory:') {
      chmodSync(options.path, 0o600);
    }

    return db;
  } catch (err) {
    throw new StorageError(`Failed to open database: ${options.path} — ${String(err)}`);
  }
}

export function closeDatabase(db: Database.Database): void {
  try {
    checkpointWal(db);
    db.close();
  } catch (err) {
    throw new StorageError(`Failed to close database: ${String(err)}`);
  }
}

export function checkpointWal(db: Database.Database): void {
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
  } catch (err) {
    throw new StorageError(`WAL checkpoint failed: ${String(err)}`);
  }
}
