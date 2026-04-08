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
- Lead with: "We open-sourced our entire benchmark suite — `pnpm benchmark` reproduces everything"
- Explain the deterministic pipeline architecture: regex matching, hash lookups, policy evaluation
- Frame why sub-ms latency + high detection + zero FP is consistent, not suspicious
- Threat-model positioning: MCP-Guard operates at the transport layer; MCPSecBench and MSB (ICLR 2026) test agent-layer resilience — complementary, not competing
- Self-testing transparency: acknowledge testing against own generators, explain mitigations (spot-check tests, audit integrity verification, natural result variation, full open-source reproducibility)
- Coverage gap analysis: map MCPSecBench's 17 attack types to our 10 categories, show gaps honestly
- Reference: `docs/benchmark-methodology.md` for full methodology, `benchmarks/results/REPORT.md` for data

## 6. Results
- Per-category breakdown as centerpiece (embed security table — the 92-100% range with natural variation is the most credible element)
- Overall detection rate: 97% across 7,095 scenarios
- Zero false positives in 10K+ trials (95% CI <0.03%) — explain Rule of Three for zero-event confidence intervals
- Audit integrity: no raw PII in logs (structural guarantee)
- **What We Don't Catch** (prominent, not buried):
  - Regex PII misses semantic encoding (spelling out digits, splitting across fields)
  - No LLM-level prompt injection resistance
  - No network-layer attack coverage (MITM, DNS rebinding)
  - Tested against own suite, not independent corpus (see §5 mitigations)
  - ML-based detection planned but not yet implemented

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
