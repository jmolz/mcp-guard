---
paths:
  - "src/config/**"
---

# Configuration System Rules

## Schema-First Design

- Zod schemas in `src/config/schema.ts` are the single source of truth for config shape
- TypeScript config types are always `z.infer<typeof schema>`, never hand-written
- Invalid config = daemon refuses to start. No partial loading, no best-effort parsing.
- `mcp-guard validate` checks config without starting the daemon (uses the same Zod schemas)

## YAML Loading

- Config file: `mcp-guard.yaml` (default) or path from `MCP_GUARD_CONFIG` env var
- Environment variable interpolation: `${VAR_NAME}` syntax, resolved at load time
- Unresolved variables are a validation error (fail-closed), not silently empty

## Extends & Merge

- `extends.url`: HTTPS URL to base config (HTTP allowed only for loopback: 127.0.0.1, localhost, ::1)
- `extends.sha256`: Required SHA-256 hash — loader refuses to use a base config that doesn't match
- Hash mismatch on live fetch is **fatal** — never falls back to cache (prevents serving tampered content)
- Fetch failure (non-hash): use last-known-good cache if available, re-verify cached hash, otherwise refuse to start
- Cache stored alongside hash at `{daemon.home}/extends-cache/{sha256}.yaml` with 0600 permissions
- `reloadConfig()` caches the parsed base config in memory, keyed by sha256 — avoids network re-fetch on every hot reload unless the hash changes

### Floor-Based Merge Semantics

The merger (`src/config/merger.ts`) enforces that personal configs can only restrict, never relax:

| Field | Merge Strategy |
|-------|---------------|
| `servers.*.policy.permissions.allowed_tools` | Intersection (personal ∩ base) |
| `servers.*.policy.permissions.denied_tools` | Union (personal ∪ base) |
| `servers.*.policy.permissions.allowed_resources` | Intersection |
| `servers.*.policy.permissions.denied_resources` | Union |
| `servers.*.policy.rate_limit` | Stricter value (lower of two) |
| `servers.*.policy.sampling.enabled` | AND (both must be true) |
| `servers.*.policy.sampling.audit` | Stricter (`verbose` wins over `basic`) |
| `servers.*.policy.locked` | If base is `true`, entire personal policy for that server is ignored |
| `pii.enabled` | Base wins — personal cannot toggle |
| `pii.confidence_threshold` | Stricter (lower threshold = more sensitive) |
| `pii.actions` | Stricter per direction (warn < redact < block) |
| `pii.custom_types` | Additive — personal can add new types; existing base types get patterns unioned and actions escalated (never weakened) |
| `auth` | Base wins entirely |
| `daemon` | Base wins entirely |
| `interceptors.timeout` | Stricter (lower of two) |

This is enforced structurally by the merge function, not by convention. Personal configs can add new servers not in base — these inherit no base server-level restrictions (global `pii` and `interceptors` config still applies).

## Hot Reload

- Daemon watches config file via `fs.watch()` with 250ms debounce (`CONFIG_RELOAD_DEBOUNCE`)
- Policy changes (permissions, rate limits, PII rules) apply immediately — pipelines are rebuilt atomically
- Identity is resolved per-message (not per-connection) so role changes apply to active sessions
- Server definition changes (command, url, transport, args, env) log a warning — requires daemon restart
- Config re-validated through Zod on every reload — invalid changes are rejected (keep previous config)
- If `fs.watch()` fails at startup (e.g., inotify limit), hot reload is disabled with an error-level log
