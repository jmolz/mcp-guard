import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';
import { resolveEffectivePermissions } from './effective-policy.js';

// Max input length for regex/glob matching to prevent ReDoS
const MAX_MATCH_INPUT_LENGTH = 1024;

// Module-level cache for compiled regex patterns (auto-populates on first use)
const patternCache = new Map<string, RegExp>();

export function createPermissionInterceptor(config: McpGuardConfig): Interceptor {
  // Pre-compile all patterns at creation time into the module cache
  for (const serverConfig of Object.values(config.servers)) {
    const allPatterns = [
      ...serverConfig.policy.permissions.denied_tools,
      ...(serverConfig.policy.permissions.allowed_tools ?? []),
      ...serverConfig.policy.permissions.denied_resources,
      ...(serverConfig.policy.permissions.allowed_resources ?? []),
    ];
    for (const pattern of allPatterns) {
      if (!patternCache.has(pattern)) {
        const compiled = compilePattern(pattern);
        if (compiled) patternCache.set(pattern, compiled);
      }
    }
  }

  return {
    name: 'permissions',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      const serverConfig = config.servers[ctx.server];
      if (!serverConfig) {
        return { action: 'PASS' };
      }

      // Merge server-level + role-level permissions (floor-based)
      const permissions = resolveEffectivePermissions(
        serverConfig.policy.permissions,
        ctx.identity,
        config,
      );

      if (ctx.message.method === 'tools/call') {
        const toolName = ctx.message.params?.['name'] as string | undefined;
        if (!toolName) {
          return { action: 'BLOCK', reason: 'tools/call missing required tool name', code: 'MALFORMED_REQUEST' };
        }

        if (matchesAny(toolName, permissions.denied_tools)) {
          return {
            action: 'BLOCK',
            reason: `Tool '${toolName}' is denied`,
            code: 'PERMISSION_DENIED',
          };
        }

        // Tool must match ALL allow-lists (semantic intersection)
        for (const allowList of permissions.allowed_tools_lists) {
          if (!matchesAny(toolName, allowList)) {
            return {
              action: 'BLOCK',
              reason: `Tool '${toolName}' is not in allowed list`,
              code: 'PERMISSION_DENIED',
            };
          }
        }

        return { action: 'PASS' };
      }

      if (ctx.message.method === 'resources/read') {
        const uri = ctx.message.params?.['uri'] as string | undefined;
        if (!uri) {
          return { action: 'BLOCK', reason: 'resources/read missing required URI', code: 'MALFORMED_REQUEST' };
        }

        if (matchesAny(uri, permissions.denied_resources)) {
          return {
            action: 'BLOCK',
            reason: `Resource '${uri}' is denied`,
            code: 'PERMISSION_DENIED',
          };
        }

        // Resource must match ALL allow-lists (semantic intersection)
        for (const allowList of permissions.allowed_resources_lists) {
          if (!matchesAny(uri, allowList)) {
            return {
              action: 'BLOCK',
              reason: `Resource '${uri}' is not in allowed list`,
              code: 'PERMISSION_DENIED',
            };
          }
        }

        return { action: 'PASS' };
      }

      // Non-tool/resource methods (tools/list, resources/list, prompts/*, etc.) → PASS
      // Capability filtering happens post-pipeline
      return { action: 'PASS' };
    },
  };
}

/**
 * Check if a value matches any pattern in the list.
 * Supports: exact match, glob wildcards (*), regex (prefixed with ^).
 */
export function matchesAny(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesPattern(value, pattern));
}

function matchesPattern(value: string, pattern: string): boolean {
  if (pattern.startsWith('^') || pattern.includes('*')) {
    if (value.length > MAX_MATCH_INPUT_LENGTH) {
      return false;
    }
    // Use cached compiled pattern, or compile on-demand for uncached patterns
    const compiled = patternCache.get(pattern) ?? compileAndCache(pattern);
    return compiled ? compiled.test(value) : false;
  }

  return value === pattern;
}

function compilePattern(pattern: string): RegExp | null {
  try {
    if (pattern.startsWith('^')) {
      return new RegExp(pattern);
    }
    if (pattern.includes('*')) {
      const regexStr = '^' + pattern.replace(/[.+?{}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$';
      return new RegExp(regexStr);
    }
  } catch {
    // Invalid regex — skip
  }
  return null;
}

function compileAndCache(pattern: string): RegExp | null {
  const compiled = compilePattern(pattern);
  if (compiled) patternCache.set(pattern, compiled);
  return compiled;
}
