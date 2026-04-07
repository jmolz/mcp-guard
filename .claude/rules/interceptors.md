---
paths:
  - "src/interceptors/**"
  - "src/pii/**"
---

# Interceptor Pipeline Rules

## Pipeline Execution Contract

- Fixed order: Auth → RateLimit → Permissions → SamplingGuard → PII Detect (request pipeline). Response pipeline: PII Detect only (on both result and error payloads)
- Each interceptor implements a single interface returning `PASS`, `MODIFY`, or `BLOCK`
- If an interceptor throws: the pipeline catches it and returns `BLOCK` (fail-closed)
- If an interceptor exceeds its timeout: the pipeline returns `BLOCK` (fail-closed)
- Custom/plugin interceptors run after built-ins on the request path
- Custom interceptors can only modify `params`/`content` — the pipeline runner diffs before/after and rejects mutations to `method`, `toolName`, or `resourceUri`

## Interceptor Interface

```typescript
interface Interceptor {
  name: string;
  execute(ctx: InterceptorContext): Promise<InterceptorDecision>;
}

type InterceptorDecision =
  | { action: 'PASS' }
  | { action: 'MODIFY'; params: Record<string, unknown> }
  | { action: 'BLOCK'; reason: string; code?: string };
```

## Context Object

The `InterceptorContext` carries:
- `message`: The MCP message (request or response)
- `server`: Server name and config
- `identity`: Resolved identity (user, role)
- `direction`: `'request'` or `'response'`
- `metadata`: Timing, bridge ID, upstream status

Interceptors receive the context and must not mutate it directly — return a decision instead.

## Key Patterns

- **Audit tap is NOT an interceptor**: Don't add audit logic to the pipeline. The tap observes from outside. The daemon's message handler is wrapped in try/catch to guarantee audit recording even on unexpected runtime errors.
- **Per-interceptor timeout**: Each interceptor has a configurable timeout (default 10s). The pipeline runner wraps each `execute()` in `Promise.race` with a cancellable timer. Always clear the timer in both success and error paths, and add `.catch(() => {})` to the timeout promise to suppress unhandled rejections.
- **Short-circuit on BLOCK**: Once any interceptor returns BLOCK, remaining interceptors are skipped. The audit tap still records the full decision chain.
- **MODIFY validation**: MODIFY decisions are validated — mutations to the *values* of `method`, `name`, or `uri` fields are rejected (→ BLOCK). The check compares values, not key presence, because auth interceptors legitimately return the full params (minus credentials) which naturally include `name`. This prevents custom interceptors from redirecting tool calls while allowing credential stripping.
- **Identity propagation**: When the auth interceptor returns MODIFY with `metadata.authMode` set ('oauth' or 'api_key'), the pipeline updates `ctx.identity` for downstream interceptors. The `resolvedIdentity` field on `PipelineResult` carries the final identity back to the daemon for audit and response-side context.
- **Malformed requests → BLOCK**: `tools/call` without `name` or `resources/read` without `uri` must be blocked, not passed through. Fail-closed on malformed input.
- **PII interceptor runs bidirectionally**: On requests (pre-upstream) and responses (post-upstream). Different actions can apply per direction.

## Permission Matching

- Patterns support exact match, glob (`*`), and regex (prefix with `^`)
- Pre-compile patterns at interceptor creation time into a module-level cache
- Cap input length to `MAX_MATCH_INPUT_LENGTH` (1024) to prevent ReDoS
- Glob patterns convert `*` to `[^/]*` (not `.*`) to limit backtracking
- Invalid regex patterns silently fail (return no match), they don't throw

## Rate Limiting

- Token bucket algorithm with SQLite persistence
- Clamp available tokens to `Math.min(persisted_max, config_max)` to handle tightened limits
- Denied requests must NOT update `last_refill` — only update the token count. Resetting the refill clock on denial makes the effective rate limit stricter than configured.

## PII Detection

- `PIIDetector` is a pluggable interface — the built-in regex detector is one implementation
- Detectors return `PIIMatch[]` with type, value, confidence, and span internally
- `ScanResult.matches` uses `PIIMatchSafe` (no `value` field) — the value is stripped at the `scanAndRedact` boundary and must never propagate beyond it
- Confidence threshold is configurable (default 0.8)
- The redactor replaces matched spans — the original value is discarded immediately, never stored
- Response scanning runs on BOTH `response.result` and `response.error` payloads
- Content exceeding 1MB → BLOCK (fail-closed, never pass uninspected content)
- Input length capped at `MAX_CONTENT_LENGTH` (64KB) at the registry scan level for all detectors (prevents ReDoS in custom patterns)
- Scan-first-then-redact: scan without redaction to discover matches, determine action, only compute redacted output when action is `redact` (avoids unnecessary deep cloning for block/warn cases)
- Custom PII type `actions` from `custom_types[*].actions` are pre-merged into the action map at interceptor creation time — they are NOT looked up at scan time via a fallback
- `PipelineResult.finalParams` must NEVER be persisted to the audit store — it may contain redacted content that creates data retention concerns

## Effective Policy Resolution

The permissions and rate-limit interceptors use `resolveEffectivePermissions()` and `resolveEffectiveRateLimit()` from `effective-policy.ts` to merge server-level policy with role-level restrictions:

- **Allow-lists use multi-list intersection**: Each allow-list (server + each role) is accumulated separately. A tool must match ALL lists independently. This prevents wildcard patterns in one list from widening access granted by another (e.g., server `['*']` + role `['read_*']` = only `read_*` tools pass).
- **Deny-lists use union**: Server denials and role denials are combined. Any denial from any source blocks.
- **Rate limits take stricter values**: Lower of server and role RPM/RPH wins. Per-tool limits from roles are merged with the same floor semantics.
- **Capability filtering uses the same effective policy**: `filterToolsList` and `filterResourcesList` call `resolveEffectivePermissions` so capabilities advertised to the client are consistent with what the interceptor will allow.
- The `EffectivePermissions` type uses `allowed_tools_lists: string[][]` (not a single `allowed_tools`) to support the multi-list semantics.

## Sampling Guard

- Blocks `sampling/createMessage` unless `serverConfig.policy.sampling.enabled` is explicitly `true`
- Unknown servers → BLOCK (fail-closed)
- Non-sampling methods always pass through
- Runs BEFORE PII detection in the pipeline (Auth → RateLimit → Permissions → SamplingGuard → PII)
