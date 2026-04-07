import Database from 'better-sqlite3-multiple-ciphers';
import { chmodSync } from 'node:fs';
import { hkdfSync } from 'node:crypto';
import { StorageError } from '../errors.js';

export interface DatabaseOptions {
  path: string;
  encryptionKey?: string;
}

export function deriveDbEncryptionKey(daemonKey: Buffer): string {
  const derived = hkdfSync('sha256', daemonKey, 'mcp-guard', 'mcp-guard-db-encryption', 32);
  return Buffer.from(derived).toString('hex');
}

export function openDatabase(options: DatabaseOptions): Database.Database {
  try {
    const db = new Database(options.path);

    if (options.encryptionKey) {
      if (!/^[a-f0-9]+$/i.test(options.encryptionKey)) {
        throw new StorageError('Encryption key must be hex-encoded');
      }
      db.pragma(`key="x'${options.encryptionKey}'"`);
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
