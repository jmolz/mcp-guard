# MCP-Guard Benchmark Report

Generated: 2026-04-07T19:28:54.562Z

## Verdict

| Suite | Result | Details |
|-------|--------|---------|
| Security | ❌ FAIL | 92.5% detection (target >95%) |
| Audit Integrity | ✅ PASS | No raw PII in audit logs |
| False Positives | ✅ PASS | 0.000% FP rate (target <0.1%) |
| Performance | ✅ PASS | p50 0.19ms (target <5ms) |

## Security Detection

![Security Detection Rates](../charts/security-detection.svg)

| Category | Scenarios | Detected | Rate | Status |
|----------|-----------|----------|------|--------|
| rate_limit_evasion | 554 | 511 | 92.2% | ❌ |
| permission_bypass | 50 | 50 | 100.0% | ✅ |
| resource_traversal | 50 | 47 | 94.0% | ❌ |
| pii_request_leak | 50 | 42 | 84.0% | ❌ |
| pii_response_leak | 50 | 50 | 100.0% | ✅ |
| auth_bypass | 50 | 40 | 80.0% | ❌ |
| sampling_injection | 50 | 50 | 100.0% | ✅ |
| config_override | 50 | 50 | 100.0% | ✅ |
| capability_probe | 50 | 48 | 96.0% | ✅ |
| pii_evasion | 50 | 41 | 82.0% | ❌ |
| **OVERALL** | **1004** | **929** | **92.5%** | ❌ |

## False Positives

![False Positive Rate](../charts/false-positive.svg)

- Total requests: 500
- False positives: 0
- FP rate: 0.000%

## Performance

![Latency Distribution](../charts/latency.svg)

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| p50 latency | 0.19 ms | <5 ms | ✅ |
| p95 latency | 0.41 ms | — | ℹ️ |
| p99 latency | 1.22 ms | — | ℹ️ |
| Mean latency | 0.24 ms | — | ℹ️ |
| Throughput | 7042 req/s | — | ℹ️ |

### Concurrency Scaling

![Concurrency Scaling](../charts/concurrency.svg)

| Connections | p50 (ms) | p95 (ms) | p99 (ms) |
|-------------|----------|----------|----------|
| 1 | 0.19 | 0.25 | 0.25 |
| 10 | 1.18 | 3.47 | 3.48 |
