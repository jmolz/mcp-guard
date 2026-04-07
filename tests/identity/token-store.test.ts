import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createTokenStore, type StoredToken } from '../../src/identity/token-store.js';

describe('Token Store', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-token-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeToken(overrides?: Partial<StoredToken>): StoredToken {
    return {
      access_token: 'test-access-token-123',
      refresh_token: 'test-refresh-token-456',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      scope: 'openid profile',
      ...overrides,
    };
  }

  it('saves and loads token — round-trips correctly', async () => {
    const store = createTokenStore(tempDir);
    const token = makeToken();

    await store.save('default', token);
    const loaded = await store.load('default');

    expect(loaded).not.toBeNull();
    expect(loaded!.access_token).toBe(token.access_token);
    expect(loaded!.refresh_token).toBe(token.refresh_token);
    expect(loaded!.expires_at).toBe(token.expires_at);
    expect(loaded!.scope).toBe(token.scope);
  });

  it('returns null for non-existent token', async () => {
    const store = createTokenStore(tempDir);
    const loaded = await store.load('nonexistent');
    expect(loaded).toBeNull();
  });

  it('removes token — subsequent load returns null', async () => {
    const store = createTokenStore(tempDir);
    await store.save('to-remove', makeToken());

    await store.remove('to-remove');
    const loaded = await store.load('to-remove');
    expect(loaded).toBeNull();
  });

  it('remove is idempotent — no error on non-existent token', async () => {
    const store = createTokenStore(tempDir);
    await expect(store.remove('does-not-exist')).resolves.toBeUndefined();
  });

  it('lists saved token names', async () => {
    const store = createTokenStore(tempDir);
    await store.save('token-a', makeToken());
    await store.save('token-b', makeToken());

    const names = await store.list();
    expect(names).toContain('token-a');
    expect(names).toContain('token-b');
    expect(names.length).toBe(2);
  });

  it('list returns empty array when no tokens exist', async () => {
    const store = createTokenStore(tempDir);
    const names = await store.list();
    expect(names).toEqual([]);
  });

  it('sets 0o600 file permissions on token files', async () => {
    const store = createTokenStore(tempDir);
    await store.save('perms-test', makeToken());

    const tokenPath = join(tempDir, 'oauth-tokens', 'perms-test.json');
    const stats = await stat(tokenPath);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('restores 0o600 permissions when overwriting a file with broader permissions', async () => {
    const store = createTokenStore(tempDir);
    await store.save('overwrite-test', makeToken());

    // Widen permissions to simulate external modification
    const tokenPath = join(tempDir, 'oauth-tokens', 'overwrite-test.json');
    await chmod(tokenPath, 0o644);

    // Verify permissions are now broader
    const beforeStats = await stat(tokenPath);
    expect(beforeStats.mode & 0o777).toBe(0o644);

    // Save again — should restore 0o600
    await store.save('overwrite-test', makeToken({ access_token: 'updated-token' }));

    const afterStats = await stat(tokenPath);
    expect(afterStats.mode & 0o777).toBe(0o600);
  });

  it('creates token directory with 0o700 permissions', async () => {
    const store = createTokenStore(tempDir);
    await store.save('dir-test', makeToken());

    const dirPath = join(tempDir, 'oauth-tokens');
    const stats = await stat(dirPath);
    expect(stats.mode & 0o777).toBe(0o700);
  });
});
