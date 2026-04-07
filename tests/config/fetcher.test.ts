import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdtemp, rm, readFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fetchBaseConfig, computeSha256 } from '../../src/config/fetcher.js';

let tempDir: string;
let cacheDir: string;
let server: Server;
let serverPort: number;

function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<number> {
  return new Promise((resolve) => {
    server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      }
    });
  });
}

function stopServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      server.close(() => resolve());
    } else {
      resolve();
    }
  });
}

const sampleYaml = `servers:
  test:
    command: echo
    args: ["hello"]
`;

const sampleHash = computeSha256(sampleYaml);

describe('Config Fetcher', () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-fetcher-'));
    cacheDir = join(tempDir, 'cache');
  });

  afterEach(async () => {
    await stopServer();
    await rm(tempDir, { recursive: true, force: true });
  });

  it('computeSha256 returns correct hex hash', () => {
    const hash = computeSha256('hello world');
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    // Known SHA-256 of "hello world"
    expect(hash).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  it('fetches remote config and returns YAML', async () => {
    serverPort = await startServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/yaml' });
      res.end(sampleYaml);
    });

    const result = await fetchBaseConfig(
      `http://127.0.0.1:${serverPort}/config.yaml`,
      sampleHash,
      cacheDir,
    );

    expect(result.yaml).toBe(sampleYaml);
    expect(result.fromCache).toBe(false);
  });

  it('verifies SHA-256 matches (success)', async () => {
    serverPort = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(sampleYaml);
    });

    const result = await fetchBaseConfig(
      `http://127.0.0.1:${serverPort}/config.yaml`,
      sampleHash,
      cacheDir,
    );

    expect(result.yaml).toBe(sampleYaml);
  });

  it('rejects SHA-256 mismatch — ConfigError', async () => {
    serverPort = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(sampleYaml);
    });

    await expect(
      fetchBaseConfig(
        `http://127.0.0.1:${serverPort}/config.yaml`,
        'a'.repeat(64), // wrong hash
        cacheDir,
      ),
    ).rejects.toThrow('SHA-256 mismatch');
  });

  it('caches fetched config locally', async () => {
    serverPort = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(sampleYaml);
    });

    await fetchBaseConfig(
      `http://127.0.0.1:${serverPort}/config.yaml`,
      sampleHash,
      cacheDir,
    );

    const cached = await readFile(join(cacheDir, `${sampleHash}.yaml`), 'utf-8');
    expect(cached).toBe(sampleYaml);
  });

  it('uses cache when fetch fails', async () => {
    // Pre-populate cache
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, `${sampleHash}.yaml`), sampleYaml);

    // Server that always 500s
    serverPort = await startServer((_req, res) => {
      res.writeHead(500);
      res.end('Internal Server Error');
    });

    const result = await fetchBaseConfig(
      `http://127.0.0.1:${serverPort}/config.yaml`,
      sampleHash,
      cacheDir,
    );

    expect(result.yaml).toBe(sampleYaml);
    expect(result.fromCache).toBe(true);
  });

  it('fails when fetch fails AND no cache exists (fail-closed)', async () => {
    serverPort = await startServer((_req, res) => {
      res.writeHead(500);
      res.end('nope');
    });

    await expect(
      fetchBaseConfig(
        `http://127.0.0.1:${serverPort}/config.yaml`,
        sampleHash,
        cacheDir,
      ),
    ).rejects.toThrow('no cached copy exists');
  });

  it('rejects cached config with wrong hash (corruption detection)', async () => {
    // Pre-populate cache with corrupted content
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, `${sampleHash}.yaml`), 'corrupted content');

    serverPort = await startServer((_req, res) => {
      res.writeHead(500);
      res.end('down');
    });

    await expect(
      fetchBaseConfig(
        `http://127.0.0.1:${serverPort}/config.yaml`,
        sampleHash,
        cacheDir,
      ),
    ).rejects.toThrow('invalid SHA-256');
  });

  it('handles fetch timeout', async () => {
    serverPort = await startServer((_req, _res) => {
      // Never respond — let it time out
    });

    await expect(
      fetchBaseConfig(
        `http://127.0.0.1:${serverPort}/config.yaml`,
        sampleHash,
        cacheDir,
      ),
    ).rejects.toThrow('no cached copy exists');
  }, 15000);

  it('creates cache directory if it does not exist', async () => {
    const deepCacheDir = join(tempDir, 'deep', 'nested', 'cache');

    serverPort = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(sampleYaml);
    });

    await fetchBaseConfig(
      `http://127.0.0.1:${serverPort}/config.yaml`,
      sampleHash,
      deepCacheDir,
    );

    const cached = await readFile(join(deepCacheDir, `${sampleHash}.yaml`), 'utf-8');
    expect(cached).toBe(sampleYaml);
  });

  it('hash mismatch on live fetch is fatal — does not fall back to cache', async () => {
    // Pre-populate cache with valid content
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, `${sampleHash}.yaml`), sampleYaml);

    // Server returns different content (hash won't match)
    serverPort = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('tampered content');
    });

    await expect(
      fetchBaseConfig(
        `http://127.0.0.1:${serverPort}/config.yaml`,
        sampleHash,
        cacheDir,
      ),
    ).rejects.toThrow('SHA-256 mismatch');
  });
});
