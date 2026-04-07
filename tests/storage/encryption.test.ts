import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { deriveDbEncryptionKey, openDatabase } from '../../src/storage/sqlite.js';
import type Database from 'better-sqlite3-multiple-ciphers';

let tempDir: string;
let dbs: Database.Database[] = [];

describe('SQLCipher Key Derivation', () => {
  afterEach(async () => {
    for (const db of dbs) {
      try { db.close(); } catch { /* ignore */ }
    }
    dbs = [];
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('deriveDbEncryptionKey produces consistent 64-char hex key', () => {
    const daemonKey = randomBytes(32);
    const key1 = deriveDbEncryptionKey(daemonKey);
    const key2 = deriveDbEncryptionKey(daemonKey);

    expect(key1).toBe(key2);
    expect(key1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('different daemon keys produce different DB keys', () => {
    const key1 = deriveDbEncryptionKey(randomBytes(32));
    const key2 = deriveDbEncryptionKey(randomBytes(32));

    expect(key1).not.toBe(key2);
  });

  it('encrypted database can be opened with correct key', async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-enc-'));
    const dbPath = join(tempDir, 'encrypted.db');
    const daemonKey = randomBytes(32);
    const encKey = deriveDbEncryptionKey(daemonKey);

    // Create encrypted DB and write data
    const db1 = openDatabase({ path: dbPath, encryptionKey: encKey });
    dbs.push(db1);
    db1.prepare('CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)').run();
    db1.prepare('INSERT INTO test (value) VALUES (?)').run('secret');
    db1.close();
    dbs = [];

    // Re-open with same key
    const db2 = openDatabase({ path: dbPath, encryptionKey: encKey });
    dbs.push(db2);
    const row = db2.prepare('SELECT value FROM test').get() as { value: string };
    expect(row.value).toBe('secret');
  });

  it('encrypted database CANNOT be opened with wrong key', async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-enc-'));
    const dbPath = join(tempDir, 'encrypted.db');
    const encKey = deriveDbEncryptionKey(randomBytes(32));

    // Create encrypted DB
    const db1 = openDatabase({ path: dbPath, encryptionKey: encKey });
    dbs.push(db1);
    db1.prepare('CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)').run();
    db1.prepare('INSERT INTO test (value) VALUES (?)').run('secret');
    db1.close();
    dbs = [];

    // Try to open with different key — fails at open time because
    // SQLCipher validates the key during PRAGMA journal_mode = WAL
    const wrongKey = deriveDbEncryptionKey(randomBytes(32));
    expect(() => {
      openDatabase({ path: dbPath, encryptionKey: wrongKey });
    }).toThrow();
  });

  it('unencrypted database works normally (no encryption key)', async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-enc-'));
    const dbPath = join(tempDir, 'plain.db');

    const db = openDatabase({ path: dbPath });
    dbs.push(db);
    db.prepare('CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)').run();
    db.prepare('INSERT INTO test (value) VALUES (?)').run('hello');
    const row = db.prepare('SELECT value FROM test').get() as { value: string };

    expect(row.value).toBe('hello');
  });
});
