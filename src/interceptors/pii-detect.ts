import type { McpGuardConfig } from '../config/schema.js';
import type { Interceptor, InterceptorContext, InterceptorDecision } from './types.js';
import type { PIIRegistry } from '../pii/registry.js';
import type { PIIAction } from '../pii/types.js';
import { scanAndRedact } from '../pii/redactor.js';

/** Block if serialized content exceeds 1MB — fail-closed, never pass uninspected content */
const MAX_SCAN_BYTES = 1_048_576;

/** Action severity order for picking the strictest */
const ACTION_SEVERITY: Record<PIIAction, number> = {
  warn: 0,
  redact: 1,
  block: 2,
};

export function createPiiInterceptor(
  registry: PIIRegistry,
  config: McpGuardConfig,
): Interceptor {
  // Pre-merge action map: top-level actions + custom_types actions (custom overrides built-in if same key)
  const actionMap: Record<string, { request: PIIAction; response: PIIAction }> = { ...config.pii.actions };
  for (const [typeName, customType] of Object.entries(config.pii.custom_types)) {
    actionMap[typeName] = customType.actions;
  }

  return {
    name: 'pii-detect',

    async execute(ctx: InterceptorContext): Promise<InterceptorDecision> {
      if (!config.pii.enabled) {
        return { action: 'PASS' };
      }

      const params = ctx.message.params;
      if (!params) {
        return { action: 'PASS' };
      }

      // Size guard — block uninspected content (fail-closed)
      const serialized = JSON.stringify(params);
      if (serialized.length > MAX_SCAN_BYTES) {
        return {
          action: 'BLOCK',
          reason: 'Content exceeds 1MB PII scan limit — blocked uninspected',
          code: 'PII_CONTENT_TOO_LARGE',
        };
      }

      const direction = ctx.direction;

      const detectFn = (content: string) => registry.scan(content, { direction, server: ctx.server });

      // Phase 1: Scan without redaction to discover matches (no unnecessary deep clone)
      let scanResult;
      try {
        scanResult = scanAndRedact(params, detectFn, false);
      } catch (err) {
        // Detector errors → BLOCK (fail-closed)
        return {
          action: 'BLOCK',
          reason: `PII detector error: ${String(err)}`,
          code: 'PII_DETECTOR_ERROR',
        };
      }

      if (scanResult.matches.length === 0) {
        return { action: 'PASS' };
      }

      // Resolve the strictest action across all matched PII types
      let strictestAction: PIIAction = 'warn';
      const detections: Array<{ type: string; action: PIIAction }> = [];

      for (const match of scanResult.matches) {
        const typeActions = actionMap[match.type];
        const action: PIIAction = typeActions
          ? typeActions[direction]
          : (direction === 'request' ? 'redact' : 'warn');

        detections.push({ type: match.type, action });

        if (ACTION_SEVERITY[action] > ACTION_SEVERITY[strictestAction]) {
          strictestAction = action;
        }
      }

      // Metadata for audit — NEVER includes original PII values
      const metadata = {
        piiDetections: detections,
      };

      if (strictestAction === 'block') {
        const detectedTypes = [...new Set(detections.map((d) => d.type))].join(', ');
        return {
          action: 'BLOCK',
          reason: `PII detected (${detectedTypes}) — blocked by ${direction} policy`,
          code: 'PII_BLOCKED',
          metadata,
        };
      }

      if (strictestAction === 'redact') {
        // Phase 2: Only compute redacted output when action is redact
        let redactResult;
        try {
          redactResult = scanAndRedact(params, detectFn, true);
        } catch (err) {
          return {
            action: 'BLOCK',
            reason: `PII redaction error: ${String(err)}`,
            code: 'PII_DETECTOR_ERROR',
          };
        }

        // Strip protected fields — pipeline rejects MODIFY containing name/method/uri.
        // This is safe: pipeline merges via { ...currentParams, ...decision.params },
        // so original name/method/uri from currentParams are preserved in the merge.
        const redactedParams = { ...(redactResult.redacted as Record<string, unknown>) };
        delete redactedParams['name'];
        delete redactedParams['method'];
        delete redactedParams['uri'];

        return {
          action: 'MODIFY',
          params: redactedParams,
          metadata,
        };
      }

      // warn — pass through with metadata
      return { action: 'PASS', metadata };
    },
  };
}
