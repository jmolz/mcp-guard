import type { McpGuardConfig, PermissionsConfig, RateLimitConfig } from '../config/schema.js';
import type { ResolvedIdentity } from './types.js';

export interface EffectivePermissions {
  /**
   * Multiple allow-lists that must ALL be satisfied (semantic intersection).
   * A tool/resource must match every list to be allowed.
   * Empty array = no allow-list restrictions.
   */
  allowed_tools_lists: string[][];
  denied_tools: string[];
  allowed_resources_lists: string[][];
  denied_resources: string[];
}

export interface EffectiveRateLimit {
  requests_per_minute?: number;
  requests_per_hour?: number;
  tool_limits: Record<string, { requests_per_minute?: number }>;
}

/**
 * Resolve effective permissions by merging server-level policy with role-level restrictions.
 * Floor-based: role permissions can only restrict, never relax the server policy.
 * - allowed_tools: each non-undefined allow-list is accumulated; a tool must match ALL lists
 * - denied_tools: union (role adds more denials)
 */
export function resolveEffectivePermissions(
  serverPermissions: PermissionsConfig,
  identity: ResolvedIdentity,
  config: McpGuardConfig,
): EffectivePermissions {
  // Accumulate all allow-lists — a tool/resource must match ALL of them
  const allowedToolsLists: string[][] = [];
  const allowedResourcesLists: string[][] = [];

  if (serverPermissions.allowed_tools) {
    allowedToolsLists.push(serverPermissions.allowed_tools);
  }
  if (serverPermissions.allowed_resources) {
    allowedResourcesLists.push(serverPermissions.allowed_resources);
  }

  let deniedTools = [...serverPermissions.denied_tools];
  let deniedResources = [...serverPermissions.denied_resources];

  for (const role of identity.roles) {
    const roleConfig = config.auth.roles[role];
    if (!roleConfig) continue;

    const rolePerms = roleConfig.permissions;

    // Union denied (role adds more denials)
    deniedTools = [...new Set([...deniedTools, ...rolePerms.denied_tools])];
    deniedResources = [...new Set([...deniedResources, ...rolePerms.denied_resources])];

    // Accumulate allow-lists (each must be independently satisfied)
    if (rolePerms.allowed_tools) {
      allowedToolsLists.push(rolePerms.allowed_tools);
    }
    if (rolePerms.allowed_resources) {
      allowedResourcesLists.push(rolePerms.allowed_resources);
    }
  }

  return {
    allowed_tools_lists: allowedToolsLists,
    denied_tools: deniedTools,
    allowed_resources_lists: allowedResourcesLists,
    denied_resources: deniedResources,
  };
}

/**
 * Resolve effective rate limit by merging server-level with role-level.
 * Floor-based: takes the stricter (lower) value, including per-tool limits.
 */
export function resolveEffectiveRateLimit(
  serverRateLimit: RateLimitConfig,
  identity: ResolvedIdentity,
  config: McpGuardConfig,
): EffectiveRateLimit {
  const effective: EffectiveRateLimit = {
    requests_per_minute: serverRateLimit.requests_per_minute,
    requests_per_hour: serverRateLimit.requests_per_hour,
    tool_limits: { ...serverRateLimit.tool_limits },
  };

  for (const role of identity.roles) {
    const roleConfig = config.auth.roles[role];
    if (!roleConfig) continue;

    const roleLimit = roleConfig.rate_limit;

    // Stricter (lower) value wins for top-level limits
    if (roleLimit.requests_per_minute) {
      effective.requests_per_minute = effective.requests_per_minute
        ? Math.min(effective.requests_per_minute, roleLimit.requests_per_minute)
        : roleLimit.requests_per_minute;
    }

    if (roleLimit.requests_per_hour) {
      effective.requests_per_hour = effective.requests_per_hour
        ? Math.min(effective.requests_per_hour, roleLimit.requests_per_hour)
        : roleLimit.requests_per_hour;
    }

    // Merge per-tool limits (stricter wins)
    for (const [toolName, toolLimit] of Object.entries(roleLimit.tool_limits)) {
      const existing = effective.tool_limits[toolName];
      if (!existing) {
        effective.tool_limits[toolName] = { ...toolLimit };
      } else if (toolLimit.requests_per_minute) {
        existing.requests_per_minute = existing.requests_per_minute
          ? Math.min(existing.requests_per_minute, toolLimit.requests_per_minute)
          : toolLimit.requests_per_minute;
      }
    }
  }

  return effective;
}
