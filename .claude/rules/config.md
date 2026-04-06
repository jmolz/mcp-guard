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

- `extends.url`: HTTP(S) URL to base config
- `extends.sha256`: Required hash — loader refuses to use a base config that doesn't match
- Fetch failure: use last-known-good cache if available, otherwise refuse to start
- Cache stored alongside hash at `~/.config/mcp-guard/extends-cache/`

### Floor-Based Merge Semantics

The merger enforces that personal configs can only restrict, never relax:

| Field | Merge Strategy |
|-------|---------------|
| `allowed_tools` | Intersection (personal ∩ base) |
| `denied_tools` | Union (personal ∪ base) |
| `rate_limit` | Stricter value (lower of two) |
| `pii.detectors` | Can add, cannot remove base detectors |
| `locked: true` | Cannot be overridden at all |

This is enforced structurally by the merge function, not by convention.

## Hot Reload

- Daemon watches `mcp-guard.yaml` for changes (fs.watch or chokidar)
- Policy changes (permissions, rate limits, PII rules) apply immediately
- Server definition changes (upstream URLs, transports) trigger graceful restart of affected connections only
- Config re-validated through Zod on every reload — invalid changes are rejected (keep previous config)
