import { describe, it, expect } from 'vitest';
import { resolveOAuthIdentity } from '../../src/identity/roles.js';
import { configSchema } from '../../src/config/schema.js';
import type { McpGuardConfig } from '../../src/config/schema.js';

function makeOAuthConfig(claimsMapping: Record<string, string[]> = {}): McpGuardConfig {
  return configSchema.parse({
    servers: { test: { command: 'echo', transport: 'stdio' } },
    auth: {
      mode: 'oauth',
      oauth: {
        issuer: 'https://auth.example.com',
        client_id: 'test-client',
        claims_to_roles: {
          claim_name: 'roles',
          mapping: claimsMapping,
        },
      },
    },
  });
}

describe('resolveOAuthIdentity', () => {
  it('maps array-valued role claim to roles', () => {
    const config = makeOAuthConfig({ admin: ['admin'], viewer: ['reader'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-1', roles: ['admin', 'viewer'] },
      config,
    );

    expect(identity.roles).toContain('admin');
    expect(identity.roles).toContain('reader');
    expect(identity.authMode).toBe('oauth');
    expect(identity.oauthSubject).toBe('user-1');
  });

  it('maps string-valued role claim', () => {
    const config = makeOAuthConfig({ admin: ['admin'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-2', roles: 'admin' },
      config,
    );

    expect(identity.roles).toEqual(['admin']);
  });

  it('returns empty roles when no claim values match mapping (fail-closed)', () => {
    const config = makeOAuthConfig({ admin: ['admin'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-3', roles: ['unknown-role'] },
      config,
    );

    expect(identity.roles).toEqual([]);
  });

  it('returns empty roles when role claim is entirely missing (fail-closed)', () => {
    const config = makeOAuthConfig({ admin: ['admin'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-4' },
      config,
    );

    expect(identity.roles).toEqual([]);
  });

  it('maps mixed claim values — only mapped values produce roles', () => {
    const config = makeOAuthConfig({ admin: ['admin'], editor: ['editor'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-5', roles: ['admin', 'unknown', 'editor'] },
      config,
    );

    expect(identity.roles).toContain('admin');
    expect(identity.roles).toContain('editor');
    expect(identity.roles).not.toContain('unknown');
    expect(identity.roles).not.toContain('default');
  });

  it('uses sub claim as username', () => {
    const config = makeOAuthConfig();
    const identity = resolveOAuthIdentity(
      { sub: 'jane@example.com' },
      config,
    );

    expect(identity.username).toBe('jane@example.com');
  });

  it('falls back to oauth-user when sub is missing', () => {
    const config = makeOAuthConfig();
    const identity = resolveOAuthIdentity({}, config);

    expect(identity.username).toBe('oauth-user');
  });

  it('deduplicates roles when multiple claim values map to the same role', () => {
    const config = makeOAuthConfig({ admin: ['admin'], super_admin: ['admin'] });
    const identity = resolveOAuthIdentity(
      { sub: 'user-7', roles: ['admin', 'super_admin'] },
      config,
    );

    expect(identity.roles).toEqual(['admin']);
  });

  it('sets uid to -1 and authMode to oauth', () => {
    const config = makeOAuthConfig();
    const identity = resolveOAuthIdentity({ sub: 'user-8' }, config);

    expect(identity.uid).toBe(-1);
    expect(identity.authMode).toBe('oauth');
  });
});
