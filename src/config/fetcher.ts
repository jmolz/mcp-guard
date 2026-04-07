import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { ConfigError } from '../errors.js';
import { EXTENDS_FETCH_TIMEOUT } from '../constants.js';

export interface FetchResult {
  yaml: string;
  fromCache: boolean;
}

export function computeSha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

export async function fetchBaseConfig(
  url: string,
  expectedSha256: string,
  cacheDir: string,
): Promise<FetchResult> {
  const cacheFile = join(cacheDir, `${expectedSha256}.yaml`);

  // Try fetching from remote
  let fetchError: Error | undefined;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(EXTENDS_FETCH_TIMEOUT),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const yaml = await response.text();
    const actualHash = computeSha256(yaml);

    if (actualHash.toLowerCase() !== expectedSha256.toLowerCase()) {
      throw new ConfigError(
        `Base config SHA-256 mismatch — expected ${expectedSha256}, got ${actualHash}. ` +
        `The remote config at ${url} may have been tampered with or updated without a hash change.`,
      );
    }

    // Cache the verified config
    await mkdir(cacheDir, { recursive: true, mode: 0o700 });
    await writeFile(cacheFile, yaml, { mode: 0o600 });

    return { yaml, fromCache: false };
  } catch (err) {
    if (err instanceof ConfigError) {
      // Hash mismatch is fatal — never fall back to cache
      throw err;
    }
    fetchError = err as Error;
  }

  // Fetch failed — try cache
  let cachedYaml: string;
  try {
    cachedYaml = await readFile(cacheFile, 'utf-8');
  } catch {
    throw new ConfigError(
      `Failed to fetch base config from ${url} (${fetchError?.message}) and no cached copy exists. ` +
      `Cannot start without a verified base config.`,
    );
  }

  // Re-verify cached copy
  const cachedHash = computeSha256(cachedYaml);
  if (cachedHash.toLowerCase() !== expectedSha256.toLowerCase()) {
    throw new ConfigError(
      `Cached base config has invalid SHA-256 — expected ${expectedSha256}, got ${cachedHash}. ` +
      `Cache may be corrupted.`,
    );
  }

  return { yaml: cachedYaml, fromCache: true };
}
