# Blog Post Outline: Introducing MCP-Guard

## 1. Hook
- "MCP servers have no authentication. Here's what we found."
- Framing: AI tools now have filesystem, database, and shell access via MCP — with zero access control

## 2. The Problem
- MCP servers expose powerful tools with no auth, no audit trail, no rate limiting
- Any process on the machine can connect and call any tool
- No way to restrict what an AI agent can do once connected
- No visibility into what happened after the fact

## 3. The Solution: MCP-Guard
- Transparent security proxy — no upstream server modifications needed
- Terminate, inspect, re-originate architecture
- Interceptor pipeline: Auth, Rate Limit, Permissions, Sampling Guard, PII Detect
- Audit every interaction to queryable SQLite

## 4. Architecture Deep-Dive
- Three-process model (daemon, bridge, CLI)
- Why terminate/re-originate instead of byte-level proxy
- Fail-closed design: errors block, not pass
- Bridge isolation: zero policy logic in the thin relay
- Floor-based config merge: personal configs can only restrict
- Diagram: data flow from client to upstream

## 5. Benchmark Methodology
- 8 mock server archetypes covering real-world MCP usage patterns
- 10 attack categories with 4,500+ scenarios generated combinatorially
- Categories: permission bypass, PII evasion, rate limit evasion, resource traversal, etc.
- 10,000+ legitimate requests for false positive measurement
- Performance: latency overhead, concurrency scaling, throughput
- Reference: `benchmarks/results/REPORT.md` for full data

## 6. Results
- Overall detection rate: >95%
- Per-category breakdown (embed security table from report)
- False positive rate: <0.1%
- Honest limitations: what we catch and what we don't
  - Semantic attacks (encoded PII that doesn't match regex patterns)
  - Application-level logic exploits
  - Timing-based side channels

## 7. Performance
- p50 latency overhead: <5ms
- Concurrency scaling chart
- Throughput numbers
- Why the overhead is low: in-process pipeline, no network hop

## 8. Getting Started
- `npm install -g mcp-guard`
- `mcp-guard init` — auto-discovers existing configs
- Update MCP client config — one JSON change per server
- Daemon auto-starts on first connection

## 9. What's Next
- Plugin system for custom interceptors
- ML-based PII detection (beyond regex)
- Real-time dashboard with htmx
- Expanded transport support
- Community-contributed benchmark scenarios

## Notes
- Target audience: developers using MCP tools (Cursor, Claude Desktop, VS Code)
- Tone: technical but accessible, honest about limitations
- Include benchmark charts as inline SVGs
- Link to GitHub repo and npm package
