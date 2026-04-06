import { describe, it, expect, afterEach } from 'vitest';
import { join } from 'node:path';
import { loadConfig } from '../../src/config/loader.js';
import { ConfigError } from '../../src/errors.js';

const FIXTURES = join(import.meta.dirname, '..', 'fixtures', 'configs');

describe('loadConfig', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('loads valid config and returns typed object', async () => {
    const config = await loadConfig(join(FIXTURES, 'valid.yaml'));
    expect(config.servers).toBeDefined();
    expect(config.servers['mock']).toBeDefined();
    expect(config.servers['mock'].command).toBe('node');
    expect(config.servers['mock'].transport).toBe('stdio');
  });

  it('applies default values for optional fields', async () => {
    const config = await loadConfig(join(FIXTURES, 'valid.yaml'));
    expect(config.daemon.log_level).toBe('info');
    expect(config.daemon.shutdown_timeout).toBe(30);
    expect(config.servers['mock'].args).toEqual(['mock-server.js']);
    expect(config.servers['mock'].env).toEqual({});
  });

  it('rejects invalid config (missing servers) with ConfigError', async () => {
    await expect(
      loadConfig(join(FIXTURES, 'invalid-missing-servers.yaml')),
    ).rejects.toThrow(ConfigError);
  });

  it('interpolates environment variables', async () => {
    process.env['TEST_GITHUB_TOKEN'] = 'test-token-123';
    const config = await loadConfig(join(FIXTURES, 'env-vars.yaml'));
    expect(config.servers['github'].env['GITHUB_TOKEN']).toBe('test-token-123');
  });

  it('throws ConfigError on unresolved environment variable', async () => {
    delete process.env['TEST_GITHUB_TOKEN'];
    await expect(loadConfig(join(FIXTURES, 'env-vars.yaml'))).rejects.toThrow(ConfigError);
    await expect(loadConfig(join(FIXTURES, 'env-vars.yaml'))).rejects.toThrow(
      'Unresolved environment variable',
    );
  });

  it('throws ConfigError when config file does not exist', async () => {
    await expect(loadConfig('/nonexistent/path.yaml')).rejects.toThrow(ConfigError);
    await expect(loadConfig('/nonexistent/path.yaml')).rejects.toThrow('Config file not found');
  });

  it('loads from custom path', async () => {
    const config = await loadConfig(join(FIXTURES, 'valid.yaml'));
    expect(config).toBeDefined();
    expect(config.servers).toBeDefined();
  });
});
