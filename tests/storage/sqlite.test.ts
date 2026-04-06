import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { openDatabase, closeDatabase, checkpointWal } from '../../src/storage/sqlite.js';
import { runMigrations } from '../../src/storage/migrations.js';
import { StorageError } from '../../src/errors.js';

describe('SQLite storage', () => {
  const tempDirs: string[] = [];

  async function makeTempDir() {
    const dir = await mkdtemp(join(tmpdir(), 'mcp-guard-db-'));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(async () => {
    for (const dir of tempDirs) {
      await rm(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
  });

  it('opens database in WAL mode', async () => {
    const dir = await makeTempDir();
    const db = openDatabase({ path: join(dir, 'test.db') });
    const mode = db.pragma('journal_mode', { simple: true });
    expect(mode).toBe('wal');
    db.close();
  });

  it('sets 0600 permissions on database file', async () => {
    const dir = await makeTempDir();
    const dbPath = join(dir, 'test.db');
    const db = openDatabase({ path: dbPath });
    const stats = await stat(dbPath);
    expect(stats.mode & 0o777).toBe(0o600);
    db.close();
  });

  it('runs migrations on fresh database', () => {
    const db = openDatabase({ path: ':memory:' });
    runMigrations(db);

    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all()
      .map((r) => (r as { name: string }).name);

    expect(tables).toContain('schema_migrations');
    expect(tables).toContain('daemon_state');
    expect(tables).toContain('audit_logs');
    expect(tables).toContain('rate_limits');
    db.close();
  });

  it('skips already-applied migrations', () => {
    const db = openDatabase({ path: ':memory:' });
    runMigrations(db);
    runMigrations(db); // Run twice — should not throw

    const count = db.prepare('SELECT COUNT(*) as c FROM schema_migrations').get() as { c: number };
    expect(count.c).toBe(4); // 001, 002, 003, 004
    db.close();
  });

  it('checkpoint WAL works', async () => {
    const dir = await makeTempDir();
    const db = openDatabase({ path: join(dir, 'test.db') });
    runMigrations(db);
    // Should not throw
    checkpointWal(db);
    db.close();
  });

  it('closeDatabase checkpoints and closes', async () => {
    const dir = await makeTempDir();
    const db = openDatabase({ path: join(dir, 'test.db') });
    runMigrations(db);
    closeDatabase(db);
    // Accessing after close should throw
    expect(() => db.prepare('SELECT 1')).toThrow();
  });

  it('throws StorageError on invalid path', () => {
    expect(() => openDatabase({ path: '/nonexistent/dir/test.db' })).toThrow(StorageError);
  });
});
