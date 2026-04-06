import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';

export function createPermissionInterceptor(config: McpGuardConfig): Interceptor {
  return {
    name: 'permissions',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      const serverConfig = config.servers[ctx.server];
      if (!serverConfig) {
        return { action: 'PASS' };
      }

      const permissions = serverConfig.policy.permissions;

      if (ctx.message.method === 'tools/call') {
        const toolName = ctx.message.params?.['name'] as string | undefined;
        if (!toolName) {
          return { action: 'PASS' };
        }

        // Check denied_tools first — deny always wins
        if (matchesAny(toolName, permissions.denied_tools)) {
          return {
            action: 'BLOCK',
            reason: `Tool '${toolName}' is denied`,
            code: 'PERMISSION_DENIED',
          };
        }

        // If allowed_tools is defined, tool must be in the list
        if (permissions.allowed_tools && !matchesAny(toolName, permissions.allowed_tools)) {
          return {
            action: 'BLOCK',
            reason: `Tool '${toolName}' is not in allowed list`,
            code: 'PERMISSION_DENIED',
          };
        }

        return { action: 'PASS' };
      }

      if (ctx.message.method === 'resources/read') {
        const uri = ctx.message.params?.['uri'] as string | undefined;
        if (!uri) {
          return { action: 'PASS' };
        }

        if (matchesAny(uri, permissions.denied_resources)) {
          return {
            action: 'BLOCK',
            reason: `Resource '${uri}' is denied`,
            code: 'PERMISSION_DENIED',
          };
        }

        if (permissions.allowed_resources && !matchesAny(uri, permissions.allowed_resources)) {
          return {
            action: 'BLOCK',
            reason: `Resource '${uri}' is not in allowed list`,
            code: 'PERMISSION_DENIED',
          };
        }

        return { action: 'PASS' };
      }

      // Non-tool/resource methods (tools/list, resources/list, prompts/*, etc.) → PASS
      // Capability filtering happens post-pipeline
      return { action: 'PASS' };
    },
  };
}

// Max input length for regex/glob matching to prevent ReDoS
const MAX_MATCH_INPUT_LENGTH = 1024;

/**
 * Check if a value matches any pattern in the list.
 * Supports: exact match, glob wildcards (*), regex (prefixed with ^).
 */
export function matchesAny(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesPattern(value, pattern));
}

function matchesPattern(value: string, pattern: string): boolean {
  // Regex pattern (starts with ^)
  if (pattern.startsWith('^')) {
    // Cap input length to prevent ReDoS on adversarial tool/resource names
    if (value.length > MAX_MATCH_INPUT_LENGTH) {
      return false;
    }
    try {
      return new RegExp(pattern).test(value);
    } catch {
      return false;
    }
  }

  // Glob pattern (contains *)
  if (pattern.includes('*')) {
    if (value.length > MAX_MATCH_INPUT_LENGTH) {
      return false;
    }
    // Convert glob to regex with non-greedy matching to limit backtracking
    const regexStr = '^' + pattern.replace(/[.+?{}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$';
    try {
      return new RegExp(regexStr).test(value);
    } catch {
      return false;
    }
  }

  // Exact match
  return value === pattern;
}
