# Benchmark Methodology

MCP-Guard's benchmark suite is open-source and fully reproducible: `pnpm benchmark` runs the complete suite, `pnpm benchmark:quick` runs a stratified sample in ~30 seconds. Every generator, mock server, and expected decision is readable in `benchmarks/`. Detection rates are deterministic (seeded RNG in generators); latency varies by machine.

## Scope and Threat Model

MCP-Guard is a transport-layer security proxy. Its interceptor pipeline performs deterministic checks on MCP messages: regex pattern matching (PII), hash/set lookups (permissions, denied tools), counter checks (rate limits), and policy evaluation (sampling guard). These are O(1) or O(n) operations where n is the number of patterns (~20), completing in microseconds.

This detection scope explains the benchmark results as a coherent story:

- **Sub-millisecond latency** — the pipeline performs the same class of operations as firewall rule evaluation (~0.1ms), not WAF/IDS analysis (~1-10ms) or ML inference (~5-50ms). The latency *tells you what the tool does*.
- **High detection on in-scope attacks** — the patterns being matched are explicit and well-defined. When MCP-Guard is looking for a denied tool name or a regex-matched SSN, it finds it.
- **Low false positives** — the checks are narrow and deterministic. A string either matches a PII regex or it doesn't. There's no probabilistic classification to produce false hits.

These three results are *consistent with each other*, not "too good to be true." Heavier analysis (semantic PII detection, prompt injection classification) would add latency and false positives — that work belongs at the application or agent layer, not the transport proxy.

### Related Work

[MCPSecBench](https://arxiv.org/abs/2508.13220) (17 attack types across 4 attack surfaces) and [MSB](https://arxiv.org/abs/2510.15994) (12 attack types, 2,000 instances, ICLR 2026) test a complementary but different threat model: whether LLM agents resist malicious MCP server instructions. Those benchmarks measure agent-layer resilience — can the LLM refuse to follow a harmful tool response? MCP-Guard operates at the transport layer *before* the LLM sees the message, like comparing a network firewall to endpoint detection. Different layers, both needed.

## Attack Scenario Generation

10 categories, each producing 450+ scenarios via combinatorial axes:

| Category | Axes | Example |
|----------|------|---------|
| Permission bypass | denied tools × 8 servers × bypass techniques | Call `exec_command` on `shell` server |
| PII evasion | 6 PII types × 8 servers × encoding techniques | Cyrillic-substituted email in tool args |
| PII request leak | 6 PII types × echoing tools × servers | SSN in `read_file` path argument |
| PII response leak | 6 PII types × 8 servers | Trigger `_benchmark_pii` tool |
| Rate limit evasion | burst patterns × servers × tool combinations | 70 requests against 60 RPM limit |
| Resource traversal | path patterns × 8 servers × traversal depths | `../../etc/passwd` in resource URI |
| Auth bypass | credential types × rejection scenarios | Missing daemon key, invalid format |
| Capability probe | disabled capabilities × 8 servers | `sampling/createMessage` on non-sampling server |
| Config override | override attempts × locked fields | Attempt to relax `denied_tools` via personal config |
| Sampling injection | injection payloads × sampling-enabled servers | Malicious `createMessage` with tool instructions |

Total: 4,500+ attack scenarios plus 10,168 legitimate requests across 8 mock server archetypes.

## Self-Testing: Honesty About Our Own Test Suite

**This benchmark tests MCP-Guard against its own scenario generators.** We are aware that this is the most common source of inflated security claims. Rather than downplaying this, we want to explain how we mitigate it and why we believe the results are still informative.

**Mitigations:**

1. **Expected-decision spot-checks.** Every category generator has unit tests (`tests/benchmarks/generators.test.ts`) that verify expected decisions against actual interceptor behavior — not just that scenarios are generated, but that the expected outcomes are correct.

2. **Structural audit verification.** The audit integrity verifier independently confirms that no raw PII appears in audit logs from any code path. This is a structural property check, not a benchmark assertion.

3. **Natural variation in results.** Detection rates range from 92% to 100% across categories because generators include genuinely hard cases: word-boundary evasion with padding, Cyrillic substitution on digit-only values, multi-level path traversal beyond single-glob matching. If we were cherry-picking scenarios, every category would be 100%.

4. **Full open-source reproducibility.** The entire benchmark suite — every generator, every mock server, every expected decision — is readable and runnable. `pnpm benchmark` reproduces everything. We encourage security researchers to audit the generators and contribute adversarial scenarios we haven't thought of.

## Coverage Gap Analysis

Mapping MCPSecBench's attack taxonomy to our 10 categories:

| MCPSecBench Category | MCP-Guard Coverage | Notes |
|---------------------|--------------------|-------|
| Tool poisoning | Partial (permissions) | We block unauthorized tool calls; we don't analyze tool description content |
| Data exfiltration | Covered (PII detect) | Bidirectional regex scanning on request and response content |
| Permission escalation | Covered (permissions) | Denied-tool enforcement + capability filtering |
| Resource access | Covered (permissions) | URI-based allow/deny with glob matching |
| Rate abuse | Covered (rate limit) | Per-server, per-user, per-tool counters |
| Authentication bypass | Covered (auth) | OS credentials, API keys, OAuth JWT validation |
| Prompt injection | Not covered | Requires LLM-layer analysis — outside our threat model |
| Malicious server detection | Not covered | Requires agent-layer trust evaluation |
| MITM / DNS rebinding | Not covered | Network-layer attack — outside transport proxy scope |
| Cross-server data leakage | Partial (audit) | Audit trail enables forensic detection, not real-time prevention |
| Sampling abuse | Covered (sampling guard) | Disabled by default, explicit per-server enablement required |
| Config manipulation | Covered (config) | Floor-based merge prevents policy relaxation |

We explicitly do not claim coverage of network-layer attacks, LLM prompt injection, or malicious server identification. These require complementary defenses at different layers of the stack.

## Legitimate Traffic and False Positive Methodology

10,168 requests across 8 mock server archetypes covering standard MCP operations: `tools/list`, `resources/list`, `resources/read`, `tools/call` with benign parameters, and `initialize` handshakes.

The test set includes 21 **near-PII edge cases** — strings designed to resemble PII patterns but not match: zip codes ("90210"), version numbers ("1.2.3.4"), process IDs, hex hashes, RGB color values, and descriptive text about email formats. These verify that the PII detector's word-boundary and format requirements prevent false triggers on legitimate data.

We acknowledge that production traffic will include patterns not in this set. If you encounter a false positive, please [open an issue](https://github.com/jmolz/mcp-guard/issues).

## Statistical Interpretation

When 0 false positives are observed in n trials, the 95% confidence interval upper bound is computed using the **Rule of Three**: 3/n. For n = 10,168, this gives approximately 0.03%.

This means: we are 95% confident that the true false positive rate is below 0.03%. It does *not* mean the FP rate is literally zero — it means we haven't observed any in this sample size. The Rule of Three is standard in biostatistics for rare-event estimation and is conservative (the exact Clopper-Pearson interval gives a slightly tighter bound).

## Known Limitations

- **Regex PII detection misses semantic encoding** — spelling out digits, splitting values across fields, or using context-dependent formats that don't match fixed patterns.
- **Word-boundary evasion with padding** is a known gap. The benchmark includes this as the `offset-10k` technique and reports detection honestly in the PII evasion category.
- **No ML-based detection yet.** A learned detector could catch patterns that regexes miss, at the cost of latency and false positive rate. This is planned.
- **Tested against our own generated suite, not an independent corpus.** See the self-testing transparency section above for mitigations.
- **Does not address network-layer attacks** (MITM, DNS rebinding) or **malicious server detection** — these require defenses at different layers.

## Cross-Validation

We investigated cross-validating MCP-Guard against GenTelLab's MCP-AttackBench (the largest published MCP security dataset at 70K+ samples). The dataset is incompatible with protocol-layer evaluation:

- **96.77% of samples are jailbreak/prompt injection strings** — flat natural language text designed for agent-layer text classification, not structured JSON-RPC messages.
- **Threat model mismatch** — MCP-AttackBench evaluates whether a model can be tricked into making malicious calls. MCP-Guard evaluates whether a malicious call (regardless of origin) gets blocked at the protocol layer. These are complementary defenses at different layers, not competing approaches to the same problem.
- **No published JSON-RPC samples** — the dataset does not include structured MCP tool_call payloads, permission probes, or PII exfiltration attempts in protocol message format.

MCP-Guard's benchmark suite remains self-generated. We mitigate this with: open-source reproducibility (`pnpm benchmark`), programmatic generation with documented methodology, per-category transparency (showing 92.4%–100% range rather than a single aggregate), and explicit limitations disclosure.

We welcome external benchmark suites targeting protocol-layer MCP security. If one emerges, we will cross-validate and publish results.
