import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';

export function createSamplingGuardInterceptor(config: McpGuardConfig): Interceptor {
  return {
    name: 'sampling-guard',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      // Only gate sampling/createMessage — all other methods pass through
      if (ctx.message.method !== 'sampling/createMessage') {
        return { action: 'PASS' };
      }

      const serverConfig = config.servers[ctx.server];
      if (!serverConfig) {
        // Unknown server → BLOCK (fail-closed)
        return {
          action: 'BLOCK',
          reason: `Sampling is disabled for unknown server "${ctx.server}"`,
          code: 'SAMPLING_DISABLED',
        };
      }

      if (!serverConfig.policy.sampling.enabled) {
        return {
          action: 'BLOCK',
          reason: `Sampling is disabled for server "${ctx.server}"`,
          code: 'SAMPLING_DISABLED',
        };
      }

      return { action: 'PASS' };
    },
  };
}
