import { describe, it, expect } from 'vitest';
import { resolveEffectivePermissions, resolveEffectiveRateLimit } from '../../src/interceptors/effective-policy.js';
import { configSchema } from '../../src/config/schema.js';
import type { McpGuardConfig, PermissionsConfig, RateLimitConfig } from '../../src/config/schema.js';
import type { ResolvedIdentity } from '../../src/interceptors/types.js';

function makeConfig(roles: Record<string, { permissions?: Partial<PermissionsConfig>; rate_limit?: Partial<RateLimitConfig> }>): McpGuardConfig {
  const authRoles: Record<string, unknown> = {};
  for (const [name, cfg] of Object.entries(roles)) {
    authRoles[name] = {
      permissions: cfg.permissions ?? {},
      rate_limit: cfg.rate_limit ?? {},
    };
  }
  return configSchema.parse({
    servers: { test: { command: 'echo' } },
    auth: { roles: authRoles },
  });
}

function makeIdentity(roles: string[]): ResolvedIdentity {
  return { uid: 1000, username: 'testuser', roles };
}

describe('resolveEffectivePermissions', () => {
  it('server allowed_tools: ["*"] + role allowed_tools: ["read_*"] restricts to read_*', () => {
    const config = makeConfig({ reader: { permissions: { allowed_tools: ['read_*'] } } });
    const serverPerms: PermissionsConfig = { allowed_tools: ['*'], denied_tools: [], denied_resources: [] };

    const effective = resolveEffectivePermissions(serverPerms, makeIdentity(['reader']), config);

    // Both allow-lists must be independently satisfied
    expect(effective.allowed_tools_lists).toHaveLength(2);
    expect(effective.allowed_tools_lists[0]).toEqual(['*']);
    expect(effective.allowed_tools_lists[1]).toEqual(['read_*']);
  });

  it('unions denied_tools from server and role', () => {
    const config = makeConfig({ reader: { permissions: { denied_tools: ['delete_*'] } } });
    const serverPerms: PermissionsConfig = { denied_tools: ['drop_*'], denied_resources: [] };

    const effective = resolveEffectivePermissions(serverPerms, makeIdentity(['reader']), config);

    expect(effective.denied_tools).toContain('drop_*');
    expect(effective.denied_tools).toContain('delete_*');
  });

  it('role with no config does not affect effective permissions', () => {
    const config = makeConfig({});
    const serverPerms: PermissionsConfig = { allowed_tools: ['echo'], denied_tools: ['rm'], denied_resources: [] };

    const effective = resolveEffectivePermissions(serverPerms, makeIdentity(['unknown']), config);

    expect(effective.allowed_tools_lists).toHaveLength(1);
    expect(effective.denied_tools).toEqual(['rm']);
  });

  it('multiple roles accumulate restrictions', () => {
    const config = makeConfig({
      reader: { permissions: { allowed_tools: ['read_*', 'list_*'] } },
      auditor: { permissions: { denied_tools: ['write_*'] } },
    });
    const serverPerms: PermissionsConfig = { denied_tools: [], denied_resources: [] };

    const effective = resolveEffectivePermissions(serverPerms, makeIdentity(['reader', 'auditor']), config);

    expect(effective.allowed_tools_lists).toHaveLength(1); // only reader has allowed_tools
    expect(effective.denied_tools).toContain('write_*');
  });
});

describe('resolveEffectiveRateLimit', () => {
  it('takes stricter (lower) top-level rate limit', () => {
    const config = makeConfig({ reader: { rate_limit: { requests_per_minute: 10 } } });
    const serverLimit: RateLimitConfig = { requests_per_minute: 100, tool_limits: {} };

    const effective = resolveEffectiveRateLimit(serverLimit, makeIdentity(['reader']), config);

    expect(effective.requests_per_minute).toBe(10);
  });

  it('merges per-tool rate limits from roles', () => {
    const config = makeConfig({
      restricted: {
        rate_limit: {
          tool_limits: { 'dangerous_tool': { requests_per_minute: 2 } },
        },
      },
    });
    const serverLimit: RateLimitConfig = {
      requests_per_minute: 100,
      tool_limits: { 'dangerous_tool': { requests_per_minute: 10 } },
    };

    const effective = resolveEffectiveRateLimit(serverLimit, makeIdentity(['restricted']), config);

    expect(effective.tool_limits['dangerous_tool'].requests_per_minute).toBe(2);
  });

  it('adds role tool_limits not present in server config', () => {
    const config = makeConfig({
      restricted: {
        rate_limit: {
          tool_limits: { 'new_tool': { requests_per_minute: 5 } },
        },
      },
    });
    const serverLimit: RateLimitConfig = { tool_limits: {} };

    const effective = resolveEffectiveRateLimit(serverLimit, makeIdentity(['restricted']), config);

    expect(effective.tool_limits['new_tool'].requests_per_minute).toBe(5);
  });
});
