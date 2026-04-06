import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile, mkdir, stat, chmod } from 'node:fs/promises';
import { dirname } from 'node:path';
import { AuthError } from '../errors.js';
import { DEFAULT_DAEMON_KEY_PATH, DAEMON_KEY_BYTES } from '../constants.js';

export async function ensureDaemonKey(keyPath?: string): Promise<Buffer> {
  const path = keyPath ?? DEFAULT_DAEMON_KEY_PATH;

  try {
    const existing = await readFile(path);
    return existing;
  } catch {
    // Key doesn't exist — generate it
  }

  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });

  const key = randomBytes(DAEMON_KEY_BYTES);
  await writeFile(path, key, { mode: 0o600 });

  return key;
}

export async function readDaemonKey(keyPath?: string): Promise<Buffer> {
  const path = keyPath ?? DEFAULT_DAEMON_KEY_PATH;

  try {
    const stats = await stat(path);
    const mode = stats.mode & 0o777;
    if (mode !== 0o600) {
      throw new AuthError(
        `Daemon key has insecure permissions: ${mode.toString(8)} (expected 600): ${path}`,
      );
    }
    return await readFile(path);
  } catch (err) {
    if (err instanceof AuthError) throw err;
    throw new AuthError(`Daemon key not found: ${path}`);
  }
}

export function verifyDaemonKey(presented: Buffer, expected: Buffer): boolean {
  if (presented.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(presented, expected);
}

export async function ensureKeyPermissions(keyPath?: string): Promise<void> {
  const path = keyPath ?? DEFAULT_DAEMON_KEY_PATH;
  await chmod(path, 0o600);
}
