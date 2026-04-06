import type { McpGuardConfig, ServerConfig } from '../config/schema.js';
import type { ResolvedIdentity } from '../interceptors/types.js';
import { matchesAny } from '../interceptors/permissions.js';

/**
 * Filter tools/list response to remove denied tools.
 * Uses the same matching logic as the permission interceptor.
 */
// _identity and _config are scaffolding for Phase 4 role-based capability filtering
export function filterToolsList(
  tools: Array<{ name: string; [key: string]: unknown }>,
  serverConfig: ServerConfig,
  _identity: ResolvedIdentity,
  _config: McpGuardConfig,
): Array<{ name: string; [key: string]: unknown }> {
  const permissions = serverConfig.policy.permissions;

  return tools.filter((tool) => {
    // If denied, remove
    if (matchesAny(tool.name, permissions.denied_tools)) {
      return false;
    }

    // If allowed_tools is set and tool is not in it, remove
    if (permissions.allowed_tools && !matchesAny(tool.name, permissions.allowed_tools)) {
      return false;
    }

    return true;
  });
}

/**
 * Filter resources/list response to remove denied resources.
 */
export function filterResourcesList(
  resources: Array<{ uri: string; [key: string]: unknown }>,
  serverConfig: ServerConfig,
  _identity: ResolvedIdentity,
  _config: McpGuardConfig,
): Array<{ uri: string; [key: string]: unknown }> {
  const permissions = serverConfig.policy.permissions;

  return resources.filter((resource) => {
    if (matchesAny(resource.uri, permissions.denied_resources)) {
      return false;
    }

    if (permissions.allowed_resources && !matchesAny(resource.uri, permissions.allowed_resources)) {
      return false;
    }

    return true;
  });
}
