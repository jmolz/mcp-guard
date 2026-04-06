import { userInfo } from 'node:os';
import type { McpGuardConfig } from '../config/schema.js';
import type { ResolvedIdentity } from '../interceptors/types.js';

/**
 * Resolve OS identity (uid/pid) into a username and role list.
 *
 * In OS auth mode (Phase 2), roles come from config.auth.roles keyed by username.
 * If the user has no explicit role mapping, they get ['default'].
 */
export function resolveIdentity(
  uid: number,
  pid: number | undefined,
  config: McpGuardConfig,
): ResolvedIdentity {
  const username = resolveUsername(uid);

  // Check if this username has a role definition in config
  const hasRoleConfig = username in config.auth.roles;
  const roles = hasRoleConfig ? [username] : ['default'];

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
