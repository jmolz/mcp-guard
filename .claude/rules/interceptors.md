---
paths:
  - "src/interceptors/**"
  - "src/pii/**"
---

# Interceptor Pipeline Rules

## Pipeline Execution Contract

- Fixed order: Auth → RateLimit → Permissions → PII Detect (request), PII Detect (response)
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
- **MODIFY validation**: MODIFY decisions are validated — mutations to `method`, `name`, or `uri` fields are rejected (→ BLOCK). This prevents custom interceptors from redirecting tool calls.
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
- Detectors return `PIIMatch[]` with type, value, confidence, and span
- Confidence threshold is configurable (default 0.8)
- The redactor replaces matched spans — the original value is discarded immediately, never stored
- Response scanning defaults to buffered mode (accumulate full response before scanning)
