import type { McpGuardConfig, ServerConfig } from '../config/schema.js';
import type { ResolvedIdentity } from '../interceptors/types.js';
import { matchesAny } from '../interceptors/permissions.js';
import { resolveEffectivePermissions } from '../interceptors/effective-policy.js';

/**
 * Filter the initialize response to remove sampling capability if disabled.
 * Returns a modified capabilities object (new object, not mutated).
 */
export function filterCapabilities(
  capabilities: Record<string, unknown>,
  serverConfig: ServerConfig,
): Record<string, unknown> {
  if (!serverConfig.policy.sampling.enabled && 'sampling' in capabilities) {
    const { sampling: _, ...rest } = capabilities;
    return rest;
  }
  return capabilities;
}

/**
 * Filter tools/list response to remove denied tools.
 * Uses the same matching logic as the permission interceptor.
 */
export function filterToolsList(
  tools: Array<{ name: string; [key: string]: unknown }>,
  serverConfig: ServerConfig,
  identity: ResolvedIdentity,
  config: McpGuardConfig,
): Array<{ name: string; [key: string]: unknown }> {
  // Merge server-level + role-level permissions for capability filtering
  const permissions = resolveEffectivePermissions(serverConfig.policy.permissions, identity, config);

  return tools.filter((tool) => {
    if (matchesAny(tool.name, permissions.denied_tools)) {
      return false;
    }

    // Tool must match ALL allow-lists
    for (const allowList of permissions.allowed_tools_lists) {
      if (!matchesAny(tool.name, allowList)) {
        return false;
      }
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
  identity: ResolvedIdentity,
  config: McpGuardConfig,
): Array<{ uri: string; [key: string]: unknown }> {
  const permissions = resolveEffectivePermissions(serverConfig.policy.permissions, identity, config);

  return resources.filter((resource) => {
    if (matchesAny(resource.uri, permissions.denied_resources)) {
      return false;
    }

    for (const allowList of permissions.allowed_resources_lists) {
      if (!matchesAny(resource.uri, allowList)) {
        return false;
      }
    }

    return true;
  });
}
