import { timingSafeEqual, createHash } from 'node:crypto';
import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';
import { createTokenValidator, type TokenValidator } from '../identity/token-validator.js';
import { resolveOAuthIdentity } from '../identity/roles.js';
import { OAuthError } from '../errors.js';

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
  // Pre-hash configured API keys at creation time for constant-time comparison
  const hashedKeys = new Map<string, { roles: string[] }>();
  for (const [key, keyConfig] of Object.entries(config.auth.api_keys)) {
    const hash = createHash('sha256').update(key).digest('hex');
    hashedKeys.set(hash, keyConfig);
  }

  // Lazy-initialize token validator on first OAuth request (async OIDC discovery)
  let tokenValidator: TokenValidator | undefined;
  let tokenValidatorPromise: Promise<TokenValidator> | undefined;
  if (config.auth.mode === 'oauth' && config.auth.oauth) {
    tokenValidatorPromise = createTokenValidator(config.auth.oauth);
  }

  return {
    name: 'auth',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      if (config.auth.mode === 'os') {
        return validateOsIdentity(ctx);
      }

      if (config.auth.mode === 'oauth') {
        if (!tokenValidatorPromise) {
          return { action: 'BLOCK', reason: 'OAuth configured but token validator not initialized', code: 'OAUTH_INTERNAL' };
        }
        if (!tokenValidator) {
          tokenValidator = await tokenValidatorPromise;
        }
        return validateOAuthToken(ctx, tokenValidator, config);
      }

      return validateApiKey(ctx, hashedKeys);
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
  hashedKeys: Map<string, { roles: string[] }>,
): InterceptorDecision {
  const apiKey = ctx.message.params?.['_api_key'] as string | undefined;

  if (!apiKey) {
    return { action: 'BLOCK', reason: 'API key required but not provided', code: 'AUTH_MISSING' };
  }

  // Constant-time comparison: hash the presented key and compare against all
  // pre-hashed keys using timingSafeEqual to prevent timing oracles
  const presentedHash = createHash('sha256').update(apiKey).digest();
  let matchedRoles: string[] | undefined;
  for (const [storedHash, keyConfig] of hashedKeys) {
    const storedBuf = Buffer.from(storedHash, 'hex');
    if (presentedHash.length === storedBuf.length && timingSafeEqual(presentedHash, storedBuf)) {
      matchedRoles = keyConfig.roles;
      break;
    }
  }

  if (!matchedRoles) {
    return { action: 'BLOCK', reason: 'Invalid API key', code: 'AUTH_INVALID' };
  }

  // Strip the _api_key from params before forwarding
  const { _api_key: _, ...cleanParams } = ctx.message.params ?? {};

  return {
    action: 'MODIFY',
    params: cleanParams,
    metadata: {
      authMode: 'api_key',
      roles: matchedRoles,
    },
  };
}

async function validateOAuthToken(
  ctx: InterceptorContext,
  tokenValidator: TokenValidator,
  config: McpGuardConfig,
): Promise<InterceptorDecision> {
  const bearerToken = ctx.message.params?.['_bearer_token'] as string | undefined;

  if (!bearerToken) {
    return { action: 'BLOCK', reason: 'OAuth token required but not provided', code: 'OAUTH_TOKEN_MISSING' };
  }

  try {
    const result = await tokenValidator.validate(bearerToken);

    // Map claims to roles
    const identity = resolveOAuthIdentity(result.claims as Record<string, unknown>, config);

    if (!identity.roles || identity.roles.length === 0) {
      return { action: 'BLOCK', reason: 'OAuth token has no mapped roles', code: 'OAUTH_NO_ROLES' };
    }

    // Strip _bearer_token from params before forwarding (never send credentials upstream)
    const { _bearer_token: _, ...cleanParams } = ctx.message.params ?? {};

    return {
      action: 'MODIFY',
      params: cleanParams,
      metadata: {
        oauthSubject: result.subject,
        roles: identity.roles,
        authMode: 'oauth',
      },
    };
  } catch (err) {
    // Sanitize error message to prevent token fragments from leaking into audit logs
    const safeReason = err instanceof OAuthError
      ? sanitizeOAuthError(err.message)
      : 'OAuth token validation failed';
    return { action: 'BLOCK', reason: safeReason, code: 'OAUTH_INVALID_TOKEN' };
  }
}

/** Strip potential JWT fragments from error messages before they reach audit logs */
function sanitizeOAuthError(message: string): string {
  // Remove JWT header/payload segments (start with eyJ = base64url of '{"')
  // AND any long base64url sequence that could be a signature segment
  return message
    .replace(/eyJ[A-Za-z0-9_-]{20,}/g, '[redacted]')
    .replace(/[A-Za-z0-9_-]{40,}/g, '[redacted]');
}
