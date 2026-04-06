---
paths:
  - "src/identity/**"
  - "src/interceptors/auth.ts"
  - "src/interceptors/permissions.ts"
  - "src/interceptors/sampling-guard.ts"
  - "src/pii/**"
  - "src/audit/**"
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
- Token validated via `jose` (JWT) or `oauth4webapi` (introspection)
- Claims mapped to roles defined in config
- Tokens are never logged in audit (log the resolved identity, not the credential)

## PII Handling

- **Redacted values are immediately discarded** — they must not exist in any variable, log, or database after redaction
- Audit log records: PII type, action taken, span location — never the original value
- The `Redactor` returns a new string; it must not mutate the input
- PII patterns must not be overly broad — false positives that block legitimate traffic are a usability bug
- Credit card detection must include Luhn validation (regex alone is insufficient)

## Permission Scoping

- `allowed_tools` and `denied_tools` are evaluated at two points: capability filtering (initialize) and request interception (tools/call)
- Both must agree — a tool denied by permissions must also be absent from the capability advertisement
- Wildcard and regex patterns must be anchored (e.g., `^delete_.*$`) to prevent partial matches
- If both allow and deny match the same tool, deny wins

## Secrets and Credentials

- Never log credentials (daemon.key, OAuth tokens, API keys, upstream server credentials)
- Environment variable interpolation (`${VAR}`) in config must not log the resolved value at info level (debug only, and even then redact known secret fields)
- Dashboard auth token: generated once, displayed only via `mcp-guard dashboard-token`, never logged
