import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createConfigWatcher, type ConfigWatcher } from '../../src/config/watcher.js';
import { configSchema, type McpGuardConfig } from '../../src/config/schema.js';
import type { Logger } from '../../src/logger.js';

let tempDir: string;
let watcher: ConfigWatcher | undefined;

const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

function makeConfig(): McpGuardConfig {
  return configSchema.parse({
    servers: { test: { command: 'echo' } },
  });
}

function writeValidConfig(path: string, extra = ''): Promise<void> {
  return writeFile(
    path,
    `servers:
  test:
    command: echo
${extra}`,
  );
}

describe('Config Watcher', () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-watcher-'));
  });

  afterEach(async () => {
    watcher?.stop();
    watcher = undefined;
    await rm(tempDir, { recursive: true, force: true });
  });

  it('triggers onChange when file changes', async () => {
    const configPath = join(tempDir, 'config.yaml');
    await writeValidConfig(configPath);
    const initialConfig = makeConfig();

    let callCount = 0;
    let receivedNew: McpGuardConfig | undefined;

    watcher = createConfigWatcher(
      configPath,
      (newConfig) => {
        callCount++;
        receivedNew = newConfig;
      },
      silentLogger,
      initialConfig,
    );

    // Modify the file
    await new Promise((r) => setTimeout(r, 100));
    await writeValidConfig(configPath, '    args: ["modified"]');

    // Wait for debounce + reload
    await new Promise((r) => setTimeout(r, 500));

    expect(callCount).toBeGreaterThanOrEqual(1);
    expect(receivedNew).toBeDefined();
    expect(receivedNew!.servers['test'].args).toContain('modified');
  }, 5000);

  it('rejects invalid config — callback NOT called', async () => {
    const configPath = join(tempDir, 'config.yaml');
    await writeValidConfig(configPath);
    const initialConfig = makeConfig();

    let callCount = 0;

    watcher = createConfigWatcher(
      configPath,
      () => { callCount++; },
      silentLogger,
      initialConfig,
    );

    await new Promise((r) => setTimeout(r, 100));
    // Write invalid YAML (missing servers)
    await writeFile(configPath, 'invalid: true\n');

    await new Promise((r) => setTimeout(r, 500));

    expect(callCount).toBe(0);
  }, 5000);

  it('stop() prevents further callbacks', async () => {
    const configPath = join(tempDir, 'config.yaml');
    await writeValidConfig(configPath);
    const initialConfig = makeConfig();

    let callCount = 0;

    watcher = createConfigWatcher(
      configPath,
      () => { callCount++; },
      silentLogger,
      initialConfig,
    );

    watcher.stop();
    watcher = undefined;

    await new Promise((r) => setTimeout(r, 100));
    await writeValidConfig(configPath, '    args: ["changed"]');
    await new Promise((r) => setTimeout(r, 500));

    expect(callCount).toBe(0);
  }, 5000);

  it('passes both new and old config to callback', async () => {
    const configPath = join(tempDir, 'config.yaml');
    await writeValidConfig(configPath);
    const initialConfig = makeConfig();

    let receivedOld: McpGuardConfig | undefined;
    let receivedNew: McpGuardConfig | undefined;

    watcher = createConfigWatcher(
      configPath,
      (newConfig, oldConfig) => {
        receivedNew = newConfig;
        receivedOld = oldConfig;
      },
      silentLogger,
      initialConfig,
    );

    await new Promise((r) => setTimeout(r, 100));
    await writeValidConfig(configPath, '    args: ["v2"]');
    await new Promise((r) => setTimeout(r, 500));

    expect(receivedOld).toBeDefined();
    expect(receivedNew).toBeDefined();
    expect(receivedNew!.servers['test'].args).toContain('v2');
  }, 5000);
});
