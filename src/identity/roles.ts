import { userInfo } from 'node:os';
import type { McpGuardConfig } from '../config/schema.js';
import type { ResolvedIdentity } from '../interceptors/types.js';

/**
 * Resolve OAuth JWT claims into a username and role list.
 *
 * Maps the configured claim (default: 'roles') through config.auth.oauth.claims_to_roles.mapping
 * to produce project-level role names. If no claims map, returns empty roles (fail-closed —
 * the auth interceptor will BLOCK with OAUTH_NO_ROLES).
 */
export function resolveOAuthIdentity(
  claims: Record<string, unknown>,
  config: McpGuardConfig,
): ResolvedIdentity {
  const sub = typeof claims['sub'] === 'string' ? claims['sub'] : 'oauth-user';
  const oauthConfig = config.auth.oauth;

  if (!oauthConfig) {
    // No OAuth config = no role mapping possible = fail-closed (empty roles → BLOCK)
    return { uid: -1, username: sub, roles: [], authMode: 'oauth', oauthSubject: sub };
  }

  const claimName = oauthConfig.claims_to_roles.claim_name;
  const claimValue = claims[claimName];
  const mapping = oauthConfig.claims_to_roles.mapping;

  // Claim value can be a string or array of strings
  const claimValues: string[] = Array.isArray(claimValue)
    ? claimValue.filter((v): v is string => typeof v === 'string')
    : typeof claimValue === 'string'
      ? [claimValue]
      : [];

  // Map claim values through the mapping to get roles
  const roles: string[] = [];
  for (const value of claimValues) {
    const mapped = mapping[value];
    if (mapped) {
      roles.push(...mapped);
    }
  }

  // Deduplicate
  const uniqueRoles = [...new Set(roles)];

  // Fail-closed: in OAuth mode, if no claims map to configured roles, return empty roles.
  // The auth interceptor will BLOCK on empty roles (OAUTH_NO_ROLES).
  // This prevents valid JWTs with unmapped claims from getting default access.
  return {
    uid: -1,
    username: sub,
    roles: uniqueRoles,
    authMode: 'oauth',
    oauthSubject: sub,
  };
}

/**
 * Resolve OS identity (uid/pid) into a username and role list.
 *
 * Role resolution: config.auth.roles is keyed by role name, each containing
 * permissions and rate_limit. A username is assigned a role if the role key
 * matches their username (Phase 2 convention). If no match, ['default'].
 *
 * Phase 4 will add explicit user→role mappings via OAuth claims.
 */
export function resolveIdentity(
  uid: number,
  pid: number | undefined,
  config: McpGuardConfig,
): ResolvedIdentity {
  const username = resolveUsername(uid);
  const roles = resolveRoles(username, config);

  return { uid, pid, username, roles };
}

function resolveUsername(uid: number): string {
  try {
    const info = userInfo();
    if (info.uid === uid) {
      return info.username;
    }
  } catch {
    // userInfo() can fail on some platforms
  }
  return `uid:${uid}`;
}

function resolveRoles(username: string, config: McpGuardConfig): string[] {
  // Collect all role names where the username matches the role key
  // Phase 2 convention: role keys that match the username are assigned
  const matchedRoles: string[] = [];
  for (const roleName of Object.keys(config.auth.roles)) {
    if (roleName === username) {
      matchedRoles.push(roleName);
    }
  }

  return matchedRoles.length > 0 ? matchedRoles : ['default'];
}
