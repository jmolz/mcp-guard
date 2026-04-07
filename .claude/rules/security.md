---
paths:
  - "src/identity/**"
  - "src/interceptors/auth.ts"
  - "src/interceptors/permissions.ts"
  - "src/interceptors/effective-policy.ts"
  - "src/interceptors/sampling-guard.ts"
  - "src/pii/**"
  - "src/audit/**"
  - "src/bridge/index.ts"
---

# Security Rules

MCP-Guard is a security tool. Security mistakes here directly expose users.

## Fail-Closed Principle

Every decision point defaults to BLOCK:
- Interceptor throws → BLOCK
- Interceptor times out → BLOCK
- Auth fails or is ambiguous → BLOCK
- Config is invalid → refuse to start
- `extends` URL unreachable and no cached copy → refuse to start
- Sampling not explicitly enabled → BLOCK and remove from capabilities
- Unknown MCP message type → BLOCK

- Malformed MCP requests (e.g., `tools/call` without `name`, `resources/read` without `uri`) → BLOCK

**Never** add a fallback that silently allows a request through.

## Authentication

### Daemon Key
- Generated on first run: 256-bit random via `crypto.randomBytes(32)`
- Stored at `{daemon.home}/daemon.key` with 0600 permissions (path derived from config, not hardcoded)
- Both `ensureDaemonKey` and `readDaemonKey` check permissions — wrong permissions throw `AuthError`
- Only `ENOENT` is suppressed during key read — other FS errors (EACCES, EIO) are fatal `AuthError`, never silently regenerating the key
- Verified on every bridge connection using `crypto.timingSafeEqual` alongside peer UID match
- If key file permissions are wrong, daemon refuses to start

### API Key Authentication
- API keys must be compared in constant time — pre-hash all configured keys at startup with SHA-256, then compare the hash of the presented key using `crypto.timingSafeEqual`
- Never use plain object property lookup (`config.api_keys[key]`) for key validation — this is a timing oracle
- Strip `_api_key` from params before forwarding to upstream

### Peer Credentials
- Linux: `SO_PEERCRED` via socket option
- macOS: `getpeereid()` + `LOCAL_PEERPID` via koffi FFI
- The connecting process's UID must match the daemon's UID
- This is a defense-in-depth layer on top of daemon.key

### OAuth 2.1 (enterprise mode)
- Token validated via `jose` (JWT) with OIDC discovery for JWKS endpoint
- Audience always validated — defaults to `client_id` when not explicitly configured (prevents cross-API token reuse)
- Claims mapped to roles via `config.auth.oauth.claims_to_roles` — unmapped claims return empty roles (fail-closed, NOT `['default']`)
- Auth interceptor BLOCKS on empty roles with `OAUTH_NO_ROLES` code
- Bearer tokens only injected by bridge when `auth.mode === 'oauth'` — prevents credential leakage in OS/API key modes
- `_bearer_token` stripped from params before upstream forwarding (same pattern as `_api_key`)
- BLOCK reason messages sanitized via `sanitizeOAuthError()` — strips JWT header segments (`eyJ...`) and long base64url sequences before audit storage
- Token store files: 0600 permissions with explicit `chmod` on every write (not just creation)
- Token store directory: 0700 permissions
- Token store path traversal prevented by name sanitization (`/[^a-zA-Z0-9_-]/g → '_'`)
- OAuth tokens are never logged — log `oauthSubject` and `roles` only
- Pipeline propagates OAuth-resolved identity to downstream interceptors via `resolvedIdentity` on `PipelineResult`
- Daemon uses pipeline-resolved identity (not OS identity) for audit recording when available

### API Key Role Propagation
- API key auth interceptor returns matched key's roles in MODIFY `metadata: { authMode: 'api_key', roles }`
- Pipeline propagates API key roles to downstream interceptors (same mechanism as OAuth)
- Rate limits and permissions use the API key's configured roles, not the OS identity

## PII Handling

- **Redacted values are immediately discarded** — they must not exist in any variable, log, or database after redaction
- `ScanResult.matches` returns `PIIMatchSafe` (no `value` field) — the type system structurally prevents PII value propagation beyond the redactor
- Audit log records: PII type, action taken — never the original value. The `metadata` field on `InterceptorDecision` carries `piiDetections: [{type, action}]` only
- `PipelineResult.finalParams` is intentionally NOT persisted to the audit store — it may contain redacted content
- The `Redactor` returns a new string; it must not mutate the input
- PII patterns must not be overly broad — false positives that block legitimate traffic are a usability bug
- Credit card detection must include Luhn validation (regex alone is insufficient)
- Content exceeding 1MB → BLOCK (fail-closed). Never pass uninspected content through
- Response PII scanning covers both `response.result` and `response.error` payloads — error messages can echo PII
- Custom PII type actions are pre-merged into the action map at interceptor creation; they don't fall back to permissive defaults

## Permission Scoping

- `allowed_tools` and `denied_tools` are evaluated at two points: capability filtering (initialize) and request interception (tools/call)
- Both must agree — a tool denied by permissions must also be absent from the capability advertisement
- Wildcard and regex patterns must be anchored (e.g., `^delete_.*$`) to prevent partial matches
- If both allow and deny match the same tool, deny wins

## Secrets and Credentials

- Never log credentials (daemon.key, OAuth tokens, API keys, upstream server credentials)
- Environment variable interpolation (`${VAR}`) in config must not log the resolved value at info level (debug only, and even then redact known secret fields)
- Dashboard auth token: generated once, displayed only via `mcp-guard dashboard-token`, never logged

## Key Derivation

- SQLCipher encryption key derived via `hkdfSync('sha256', daemonKey, 'mcp-guard', 'mcp-guard-db-encryption', 32)`
- Never use the raw daemon.key as a database password — always derive with HKDF for domain separation
- Encryption key validated as hex-only before passing to SQLCipher PRAGMA (prevents SQL injection)
- CLI commands that read the DB (e.g., `mcp-guard logs`) must also derive and pass the key when encryption is enabled

## Config Extends Security

- `extends.url` must be HTTPS (enforced by Zod schema refine); HTTP allowed only for loopback addresses
- SHA-256 hash mismatch on live fetch is immediately fatal — never falls back to cache
- This prevents a MITM from serving tampered content that still falls back to the "good" cached version
- Cache files are re-verified on every read (defense against cache corruption/tampering)

## PII Custom Type Merge Security

- Personal configs cannot weaken base custom PII type definitions
- When both base and personal define the same custom type name: patterns are unioned (base always preserved), actions take the stricter severity per direction
- Personal cannot replace base patterns with a never-matching regex (union preserves all base patterns)
- Base label is preserved (personal cannot rename to obscure the type's purpose)
