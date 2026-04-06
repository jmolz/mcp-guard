import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat, chmod, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ensureDaemonKey, readDaemonKey, verifyDaemonKey } from '../../src/identity/daemon-key.js';
import { AuthError } from '../../src/errors.js';
import { DAEMON_KEY_BYTES } from '../../src/constants.js';

describe('daemon-key', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('ensureDaemonKey', () => {
    it('creates key file on first run', async () => {
      const keyPath = join(tempDir, 'daemon.key');
      const key = await ensureDaemonKey(keyPath);
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(DAEMON_KEY_BYTES);
    });

    it('sets 0600 permissions on key file', async () => {
      const keyPath = join(tempDir, 'daemon.key');
      await ensureDaemonKey(keyPath);
      const stats = await stat(keyPath);
      expect(stats.mode & 0o777).toBe(0o600);
    });

    it('returns existing key on subsequent runs', async () => {
      const keyPath = join(tempDir, 'daemon.key');
      const key1 = await ensureDaemonKey(keyPath);
      const key2 = await ensureDaemonKey(keyPath);
      expect(key1.equals(key2)).toBe(true);
    });

    it('creates parent directory if needed', async () => {
      const keyPath = join(tempDir, 'subdir', 'daemon.key');
      const key = await ensureDaemonKey(keyPath);
      expect(key.length).toBe(DAEMON_KEY_BYTES);
    });
  });

  describe('readDaemonKey', () => {
    it('reads existing key', async () => {
      const keyPath = join(tempDir, 'daemon.key');
      const written = await ensureDaemonKey(keyPath);
      const read = await readDaemonKey(keyPath);
      expect(written.equals(read)).toBe(true);
    });

    it('throws AuthError when key file does not exist', async () => {
      const keyPath = join(tempDir, 'nonexistent.key');
      await expect(readDaemonKey(keyPath)).rejects.toThrow(AuthError);
    });

    it('throws AuthError when key file has wrong permissions', async () => {
      const keyPath = join(tempDir, 'insecure.key');
      await writeFile(keyPath, randomBytes(DAEMON_KEY_BYTES), { mode: 0o644 });
      await expect(readDaemonKey(keyPath)).rejects.toThrow(AuthError);
      await expect(readDaemonKey(keyPath)).rejects.toThrow('insecure permissions');
    });
  });

  describe('ensureDaemonKey permission enforcement', () => {
    it('throws AuthError when existing key has wrong permissions', async () => {
      const keyPath = join(tempDir, 'daemon.key');
      // Create key with correct permissions first, then weaken
      await writeFile(keyPath, randomBytes(DAEMON_KEY_BYTES), { mode: 0o600 });
      await chmod(keyPath, 0o644);
      await expect(ensureDaemonKey(keyPath)).rejects.toThrow(AuthError);
      await expect(ensureDaemonKey(keyPath)).rejects.toThrow('insecure permissions');
    });
  });

  describe('verifyDaemonKey', () => {
    it('returns true for matching keys', () => {
      const key = Buffer.alloc(DAEMON_KEY_BYTES, 0xaa);
      expect(verifyDaemonKey(key, Buffer.from(key))).toBe(true);
    });

    it('returns false for mismatched keys', () => {
      const key1 = Buffer.alloc(DAEMON_KEY_BYTES, 0xaa);
      const key2 = Buffer.alloc(DAEMON_KEY_BYTES, 0xbb);
      expect(verifyDaemonKey(key1, key2)).toBe(false);
    });

    it('returns false for different length keys', () => {
      const key1 = Buffer.alloc(DAEMON_KEY_BYTES, 0xaa);
      const key2 = Buffer.alloc(16, 0xaa);
      expect(verifyDaemonKey(key1, key2)).toBe(false);
    });
  });
});
