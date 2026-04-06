import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';

/**
 * Auth interceptor — validates that the caller has a resolved identity with roles.
 *
 * In OS mode (default): Identity is pre-resolved from peer credentials by the daemon.
 * The interceptor verifies it's present and has roles.
 *
 * In API key mode: Validates the key against config.auth.api_keys.
 * The key is expected in ctx.message.params._api_key (stripped before forwarding).
 *
 * NOTE: In Phase 2, API key roles are validated but not yet mapped to
 * per-role permissions/rate-limits. Full role→policy resolution is Phase 4.
 */
export function createAuthInterceptor(config: McpGuardConfig): Interceptor {
  return {
    name: 'auth',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      if (config.auth.mode === 'os') {
        return validateOsIdentity(ctx);
      }

      return validateApiKey(ctx, config);
    },
  };
}

function validateOsIdentity(ctx: InterceptorContext): InterceptorDecision {
  // Identity must be present (resolved by daemon on connection)
  if (!ctx.identity) {
    return { action: 'BLOCK', reason: 'No identity resolved', code: 'AUTH_MISSING' };
  }

  if (!ctx.identity.username) {
    return { action: 'BLOCK', reason: 'Identity has no username', code: 'AUTH_INVALID' };
  }

  if (!ctx.identity.roles || ctx.identity.roles.length === 0) {
    return { action: 'BLOCK', reason: 'Identity has no roles', code: 'AUTH_NO_ROLES' };
  }

  return { action: 'PASS' };
}

function validateApiKey(
  ctx: InterceptorContext,
  config: McpGuardConfig,
): InterceptorDecision {
  const apiKey = ctx.message.params?.['_api_key'] as string | undefined;

  if (!apiKey) {
    return { action: 'BLOCK', reason: 'API key required but not provided', code: 'AUTH_MISSING' };
  }

  const keyConfig = config.auth.api_keys[apiKey];
  if (!keyConfig) {
    return { action: 'BLOCK', reason: 'Invalid API key', code: 'AUTH_INVALID' };
  }

  // Strip the _api_key from params before forwarding
  const { _api_key: _, ...cleanParams } = ctx.message.params ?? {};

  return {
    action: 'MODIFY',
    params: cleanParams,
  };
}
