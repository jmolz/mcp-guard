import { readFile, writeFile, unlink, readdir, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { OAUTH_TOKEN_DIR, OAUTH_TOKEN_FILE_MODE } from '../constants.js';
import { OAuthError } from '../errors.js';

export interface StoredToken {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_at: number; // Unix epoch seconds
  scope: string;
  server?: string;
}

export interface TokenStore {
  save(name: string, token: StoredToken): Promise<void>;
  load(name: string): Promise<StoredToken | null>;
  remove(name: string): Promise<void>;
  list(): Promise<string[]>;
}

export function createTokenStore(home: string): TokenStore {
  const tokenDir = join(home, OAUTH_TOKEN_DIR);

  async function ensureDir(): Promise<void> {
    await mkdir(tokenDir, { recursive: true, mode: 0o700 });
  }

  function tokenPath(name: string): string {
    // Sanitize name to prevent path traversal
    const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
    return join(tokenDir, `${safeName}.json`);
  }

  return {
    async save(name: string, token: StoredToken): Promise<void> {
      await ensureDir();
      const path = tokenPath(name);
      await writeFile(path, JSON.stringify(token), { mode: OAUTH_TOKEN_FILE_MODE });
      // Ensure 0600 even when overwriting an existing file with broader permissions
      await chmod(path, OAUTH_TOKEN_FILE_MODE);
    },

    async load(name: string): Promise<StoredToken | null> {
      const path = tokenPath(name);
      try {
        const data = await readFile(path, 'utf-8');
        return JSON.parse(data) as StoredToken;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
          return null;
        }
        throw new OAuthError(`Failed to read token: ${err instanceof Error ? err.message : String(err)}`);
      }
    },

    async remove(name: string): Promise<void> {
      const path = tokenPath(name);
      try {
        await unlink(path);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
          return; // Idempotent
        }
        throw new OAuthError(`Failed to remove token: ${err instanceof Error ? err.message : String(err)}`);
      }
    },

    async list(): Promise<string[]> {
      try {
        const files = await readdir(tokenDir);
        return files
          .filter((f) => f.endsWith('.json'))
          .map((f) => f.replace(/\.json$/, ''));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
          return [];
        }
        throw new OAuthError(`Failed to list tokens: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  };
}
