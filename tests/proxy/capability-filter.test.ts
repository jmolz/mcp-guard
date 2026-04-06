import { describe, it, expect } from 'vitest';
import { filterToolsList, filterResourcesList } from '../../src/proxy/capability-filter.js';
import { configSchema, type ServerConfig } from '../../src/config/schema.js';
import type { ResolvedIdentity } from '../../src/interceptors/types.js';

const identity: ResolvedIdentity = { uid: 1000, username: 'testuser', roles: ['default'] };

function makeServerConfig(policy?: Record<string, unknown>): ServerConfig {
  const config = configSchema.parse({
    servers: {
      test: {
        command: 'echo',
        transport: 'stdio',
        policy: policy ?? {},
      },
    },
  });
  return config.servers['test'];
}

function makeConfig() {
  return configSchema.parse({
    servers: { test: { command: 'echo', transport: 'stdio' } },
  });
}

describe('filterToolsList', () => {
  it('removes denied tools', () => {
    const serverConfig = makeServerConfig({ permissions: { denied_tools: ['dangerous'] } });
    const tools = [
      { name: 'safe', description: 'Safe tool' },
      { name: 'dangerous', description: 'Dangerous tool' },
      { name: 'echo', description: 'Echo' },
    ];

    const filtered = filterToolsList(tools, serverConfig, identity, makeConfig());
    expect(filtered.map((t) => t.name)).toEqual(['safe', 'echo']);
  });

  it('removes tools not in allowed list', () => {
    const serverConfig = makeServerConfig({ permissions: { allowed_tools: ['echo'] } });
    const tools = [
      { name: 'echo', description: 'Echo' },
      { name: 'add', description: 'Add' },
    ];

    const filtered = filterToolsList(tools, serverConfig, identity, makeConfig());
    expect(filtered.map((t) => t.name)).toEqual(['echo']);
  });

  it('removes tools matching wildcard deny', () => {
    const serverConfig = makeServerConfig({ permissions: { denied_tools: ['delete_*'] } });
    const tools = [
      { name: 'create_user', description: '' },
      { name: 'delete_user', description: '' },
      { name: 'delete_file', description: '' },
    ];

    const filtered = filterToolsList(tools, serverConfig, identity, makeConfig());
    expect(filtered.map((t) => t.name)).toEqual(['create_user']);
  });

  it('passes all tools when no permissions configured', () => {
    const serverConfig = makeServerConfig();
    const tools = [{ name: 'a' }, { name: 'b' }, { name: 'c' }];

    const filtered = filterToolsList(tools, serverConfig, identity, makeConfig());
    expect(filtered).toHaveLength(3);
  });
});

describe('filterResourcesList', () => {
  it('removes denied resources', () => {
    const serverConfig = makeServerConfig({
      permissions: { denied_resources: ['secret://*'] },
    });
    const resources = [
      { uri: 'public://data', name: 'Data' },
      { uri: 'secret://passwords', name: 'Passwords' },
    ];

    const filtered = filterResourcesList(resources, serverConfig, identity, makeConfig());
    expect(filtered.map((r) => r.uri)).toEqual(['public://data']);
  });

  it('removes resources not in allowed list', () => {
    const serverConfig = makeServerConfig({
      permissions: { allowed_resources: ['public://*'] },
    });
    const resources = [
      { uri: 'public://data', name: 'Data' },
      { uri: 'private://internal', name: 'Internal' },
    ];

    const filtered = filterResourcesList(resources, serverConfig, identity, makeConfig());
    expect(filtered.map((r) => r.uri)).toEqual(['public://data']);
  });
});
