import type {
  Interceptor,
  InterceptorContext,
  InterceptorDecision,
  PipelineResult,
} from './types.js';
import type { Logger } from '../logger.js';

export interface PipelineOptions {
  interceptors: Interceptor[];
  timeout: number; // ms, per interceptor
  logger: Logger;
}

export function createPipeline(options: PipelineOptions) {
  const { interceptors, timeout, logger } = options;

  async function execute(ctx: InterceptorContext): Promise<PipelineResult> {
    const decisions: PipelineResult['decisions'] = [];
    let currentParams = ctx.message.params;

    for (const interceptor of interceptors) {
      const start = Date.now();
      let decision: InterceptorDecision;

      const timer = createTimeout(timeout, interceptor.name);
      try {
        decision = await Promise.race([
          interceptor.execute(ctx),
          timer.promise,
        ]);
      } catch (err) {
        timer.clear();
        // Interceptor threw or timed out → BLOCK (fail-closed)
        const durationMs = Date.now() - start;
        const reason = String(err);
        logger.error('Interceptor failed', {
          interceptor: interceptor.name,
          error: reason,
          durationMs,
        });

        const blockDecision: InterceptorDecision = {
          action: 'BLOCK',
          reason: `Interceptor '${interceptor.name}' failed: ${reason}`,
        };

        decisions.push({
          interceptor: interceptor.name,
          decision: blockDecision,
          durationMs,
        });

        return {
          allowed: false,
          decisions,
          finalParams: currentParams,
        };
      }
      timer.clear();

      const durationMs = Date.now() - start;

      // Validate MODIFY decisions — reject mutations to method or other protected fields
      if (decision.action === 'MODIFY') {
        if ('method' in decision.params || 'name' in decision.params || 'uri' in decision.params) {
          logger.error('Interceptor attempted to modify protected fields', {
            interceptor: interceptor.name,
          });

          const blockDecision: InterceptorDecision = {
            action: 'BLOCK',
            reason: `Interceptor '${interceptor.name}' attempted to modify protected fields`,
          };

          decisions.push({
            interceptor: interceptor.name,
            decision: blockDecision,
            durationMs,
          });

          return {
            allowed: false,
            decisions,
            finalParams: currentParams,
          };
        }

        // Apply modified params for next interceptor
        currentParams = { ...currentParams, ...decision.params };
        ctx = { ...ctx, message: { ...ctx.message, params: currentParams } };
      }

      decisions.push({
        interceptor: interceptor.name,
        decision,
        durationMs,
      });

      // Short-circuit on BLOCK
      if (decision.action === 'BLOCK') {
        return {
          allowed: false,
          decisions,
          finalParams: currentParams,
        };
      }
    }

    return {
      allowed: true,
      decisions,
      finalParams: currentParams,
    };
  }

  return { execute };
}

function createTimeout(ms: number, name: string): { promise: Promise<never>; clear: () => void } {
  let timerId: ReturnType<typeof setTimeout>;
  const promise = new Promise<never>((_, reject) => {
    timerId = setTimeout(() => reject(new Error(`Interceptor '${name}' timed out after ${ms}ms`)), ms);
  });
  // Suppress unhandled rejection if the interceptor resolves before the timer
  promise.catch(() => {});
  return {
    promise,
    clear: () => clearTimeout(timerId),
  };
}
