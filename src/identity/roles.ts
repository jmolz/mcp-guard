import { userInfo } from 'node:os';
import type { McpGuardConfig } from '../config/schema.js';
import type { ResolvedIdentity } from '../interceptors/types.js';

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
