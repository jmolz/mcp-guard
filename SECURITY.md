# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the latest minor release receives security updates.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities through one of these channels:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/jmolz/mcp-guard/security/advisories/new)
2. **Email**: security@jmolz.dev

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (what an attacker could do)
- Any suggested fixes

### Response Timeline

- **48 hours**: Acknowledgment of your report
- **7 days**: Initial assessment and severity classification
- **30 days**: Fix developed and tested (critical issues faster)
- **Release**: Patch published with credit to reporter (unless anonymity requested)

## Scope

### In Scope

- Authentication bypass (daemon key, OAuth, API key)
- Authorization bypass (permission escalation, policy circumvention)
- PII detection evasion that could leak sensitive data
- Audit log tampering or bypass
- Config merge vulnerabilities (relaxing base policies)
- SQL injection in audit storage
- Socket security (peer credential verification bypass)
- Denial of service against the daemon
- Cryptographic issues (key generation, token validation)

### Out of Scope

- Vulnerabilities in upstream MCP servers (report to those projects)
- Issues requiring physical access to the machine
- Social engineering attacks
- Issues in dependencies (report upstream, but let us know so we can update)

## Security Model

MCP-Guard uses a **terminate, inspect, re-originate** architecture. See the [README](README.md) for details. Key security properties:

- **Fail-closed**: Any error in the interceptor pipeline blocks the request
- **Bridge isolation**: The bridge process contains zero policy logic
- **Floor-based config merge**: Personal configs can only restrict, never relax base policies
- **Structural audit**: The audit tap cannot be bypassed by pipeline errors
- **Parameterized SQL**: All database queries use parameterized statements
