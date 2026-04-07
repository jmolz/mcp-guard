import type { McpGuardConfig } from '../config/schema.js';
import type { RateLimitStore } from '../storage/rate-limit-store.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';
import { resolveEffectiveRateLimit } from './effective-policy.js';

export function createRateLimitInterceptor(
  store: RateLimitStore,
  config: McpGuardConfig,
): Interceptor {
  return {
    name: 'rate-limit',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      const serverConfig = config.servers[ctx.server];
      if (!serverConfig) {
        return { action: 'PASS' };
      }

      // Merge server-level + role-level rate limits (floor-based: stricter wins)
      const rateConfig = resolveEffectiveRateLimit(
        serverConfig.policy.rate_limit,
        ctx.identity,
        config,
      );

      // Check server-level rate limit
      if (rateConfig.requests_per_minute) {
        const key = `server:${ctx.server}:${ctx.identity.username}:rpm`;
        const allowed = store.tryConsume(key, {
          maxTokens: rateConfig.requests_per_minute,
          refillRate: rateConfig.requests_per_minute / 60, // tokens per second
        });

        if (!allowed) {
          return {
            action: 'BLOCK',
            reason: 'Rate limit exceeded (requests per minute)',
            code: 'RATE_LIMITED',
          };
        }
      }

      if (rateConfig.requests_per_hour) {
        const key = `server:${ctx.server}:${ctx.identity.username}:rph`;
        const allowed = store.tryConsume(key, {
          maxTokens: rateConfig.requests_per_hour,
          refillRate: rateConfig.requests_per_hour / 3600, // tokens per second
        });

        if (!allowed) {
          return {
            action: 'BLOCK',
            reason: 'Rate limit exceeded (requests per hour)',
            code: 'RATE_LIMITED',
          };
        }
      }

      // Check per-tool rate limit (only for tools/call)
      if (ctx.message.method === 'tools/call') {
        const toolName = ctx.message.params?.['name'] as string | undefined;
        if (toolName && rateConfig.tool_limits[toolName]) {
          const toolLimit = rateConfig.tool_limits[toolName];
          if (toolLimit.requests_per_minute) {
            const key = `tool:${ctx.server}:${ctx.identity.username}:${toolName}:rpm`;
            const allowed = store.tryConsume(key, {
              maxTokens: toolLimit.requests_per_minute,
              refillRate: toolLimit.requests_per_minute / 60,
            });

            if (!allowed) {
              return {
                action: 'BLOCK',
                reason: `Rate limit exceeded for tool '${toolName}'`,
                code: 'RATE_LIMITED',
              };
            }
          }
        }
      }

      return { action: 'PASS' };
    },
  };
}
