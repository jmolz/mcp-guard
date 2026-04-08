/**
 * Security benchmark runner — orchestrates all security scenarios against a real daemon.
 */

import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Socket } from 'node:net';
import { loadConfig } from '../../src/config/loader.js';
import { startDaemon, type DaemonHandle } from '../../src/daemon/index.js';
import { ensureDaemonKey, readDaemonKey } from '../../src/identity/daemon-key.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { connectSocket, writeFramed, readFramed } from '../../tests/fixtures/framing.js';
import type {
  AuditIntegrityResult,
  BenchmarkScenario,
  BurstGroup,
  GeneratorOptions,
  ScenarioResult,
  SecurityBenchmarkResult,
} from '../types.js';
import { ScenarioGeneratorRegistry } from './generator.js';
import { PII_RESPONSE_DATA } from '../mock-servers/base.js';

// Import all generators
import { PermissionBypassGenerator } from './categories/permission-bypass.js';
import { ResourceTraversalGenerator } from './categories/resource-traversal.js';
import { PiiRequestLeakGenerator } from './categories/pii-request-leak.js';
import { PiiResponseLeakGenerator } from './categories/pii-response-leak.js';
import { RateLimitEvasionGenerator } from './categories/rate-limit-evasion.js';
import { AuthBypassGenerator } from './categories/auth-bypass.js';
import { SamplingInjectionGenerator } from './categories/sampling-injection.js';
import { ConfigOverrideGenerator } from './categories/config-override.js';
import { CapabilityProbeGenerator } from './categories/capability-probe.js';
import { PiiEvasionGenerator } from './categories/pii-evasion.js';

interface McpResponse {
  type: string;
  data?: {
    jsonrpc: string;
    id?: number;
    result?: Record<string, unknown>;
    error?: { code: number; message: string; data?: unknown };
  };
}

function inferDecision(response: McpResponse): 'PASS' | 'BLOCK' | 'MODIFY' {
  if (!response.data) return 'BLOCK';
  if (response.data.error) {
    const msg = response.data.error.message ?? '';
    // Pipeline BLOCK errors use code -32600
    if (response.data.error.code === -32600) return 'BLOCK';
    // PII response block
    if (msg.includes('blocked by PII policy') || msg.includes('Blocked by')) return 'BLOCK';
    // Upstream errors (tool not found, etc.) are not pipeline blocks
    return 'PASS';
  }
  // Check if response was modified (PII redaction leaves [REDACTED] markers)
  const resultStr = JSON.stringify(response.data.result ?? {});
  if (resultStr.includes('[REDACTED')) return 'MODIFY';
  return 'PASS';
}

function inferInterceptor(response: McpResponse): string | undefined {
  if (!response.data?.error) return undefined;
  const msg = response.data.error.message ?? '';
  if (msg.includes('Rate limit')) return 'rate-limit';
  if (msg.includes('denied') || msg.includes('not allowed') || msg.includes('Permission') || msg.includes('Malformed')) return 'permissions';
  if (msg.includes('sampling') || msg.includes('createMessage')) return 'sampling-guard';
  if (msg.includes('PII') || msg.includes('pii')) return 'pii-detect';
  if (msg.includes('Auth') || msg.includes('auth')) return 'auth';
  return undefined;
}

async function runScenario(
  socket: Socket,
  scenario: BenchmarkScenario,
): Promise<ScenarioResult> {
  const start = Date.now();
  writeFramed(socket, { type: 'mcp', server: scenario.server, data: scenario.message });
  const response = (await readFramed(socket, 10000)) as McpResponse;
  const durationMs = Date.now() - start;

  const actualDecision = inferDecision(response);
  const actualInterceptor = inferInterceptor(response);

  const passed = actualDecision === scenario.expectedDecision;

  return {
    scenario,
    actualDecision,
    actualInterceptor,
    durationMs,
    passed,
  };
}

async function authenticateSocket(socketPath: string, keyPath: string): Promise<Socket> {
  const socket = await connectSocket(socketPath);
  const key = await readDaemonKey(keyPath);
  writeFramed(socket, { type: 'auth', key: key.toString('hex') });
  const response = (await readFramed(socket)) as { type: string };
  if (response.type !== 'auth_ok') {
    throw new Error(`Socket auth failed: ${JSON.stringify(response)}`);
  }
  return socket;
}

async function rewriteConfig(configPath: string, tempDir: string): Promise<string> {
  const socketPath = join(tempDir, 'daemon.sock');
  const raw = await readFile(configPath, 'utf-8');
  const rewritten = raw
    .replace(/__SOCKET_PATH__/g, socketPath)
    .replace(/__HOME__/g, tempDir);
  const outPath = join(tempDir, 'config.yaml');
  await writeFile(outPath, rewritten);
  return outPath;
}

export interface SecurityRunResult {
  results: SecurityBenchmarkResult[];
  auditIntegrity: AuditIntegrityResult;
}

export async function runSecurityBenchmark(
  configPath: string,
  options?: GeneratorOptions,
): Promise<SecurityRunResult> {
  const tempDir = await mkdtemp(join(tmpdir(), 'mcp-guard-bench-security-'));
  const socketPath = join(tempDir, 'daemon.sock');
  const keyPath = join(tempDir, 'daemon.key');
  let daemonHandle: DaemonHandle | undefined;

  try {
    // Setup
    await ensureDaemonKey(keyPath);
    const rewrittenConfigPath = await rewriteConfig(configPath, tempDir);
    const config = await loadConfig(rewrittenConfigPath);
    daemonHandle = await startDaemon(config);

    // Wait for upstream servers
    await new Promise((r) => setTimeout(r, 3000));

    const socket = await authenticateSocket(socketPath, keyPath);

    // Register all generators
    const registry = new ScenarioGeneratorRegistry();
    registry.registerScenario(new PermissionBypassGenerator());
    registry.registerScenario(new ResourceTraversalGenerator());
    registry.registerScenario(new PiiRequestLeakGenerator());
    registry.registerScenario(new PiiResponseLeakGenerator());
    registry.registerScenario(new AuthBypassGenerator());
    registry.registerScenario(new SamplingInjectionGenerator());
    registry.registerScenario(new ConfigOverrideGenerator());
    registry.registerScenario(new CapabilityProbeGenerator());
    registry.registerScenario(new PiiEvasionGenerator());
    registry.registerBurstGroup(new RateLimitEvasionGenerator());

    const { scenarios, burstGroups } = registry.generateAll(options);

    // Group scenarios by category
    const byCategory = new Map<string, BenchmarkScenario[]>();
    for (const s of scenarios) {
      const list = byCategory.get(s.category) ?? [];
      list.push(s);
      byCategory.set(s.category, list);
    }

    const results: SecurityBenchmarkResult[] = [];

    // Run rate-limit burst groups FIRST — before other categories consume rate-limit budgets.
    // Rate limits are keyed by (server, username, tool); other categories sending to the
    // same servers would drain counters and contaminate burst group measurements.
    if (burstGroups.length > 0) {
      console.log(`  Running rate_limit_evasion: ${burstGroups.length} burst groups...`);
      const burstResults: ScenarioResult[] = [];

      for (const group of burstGroups) {
        // Each burst group needs its own socket to avoid cross-contamination
        const burstSocket = await authenticateSocket(socketPath, keyPath);

        for (const req of group.requests) {
          const start = Date.now();
          writeFramed(burstSocket, { type: 'mcp', server: group.server, data: req.message });
          const response = (await readFramed(burstSocket, 10000)) as McpResponse;
          const durationMs = Date.now() - start;

          const actualDecision = inferDecision(response);
          const passed = actualDecision === req.expectedDecision;

          burstResults.push({
            scenario: {
              id: `${group.id}-req`,
              category: 'rate_limit_evasion',
              description: group.description,
              server: group.server,
              message: req.message,
              expectedDecision: req.expectedDecision,
              expectedInterceptor: 'rate-limit',
            },
            actualDecision,
            actualInterceptor: actualDecision === 'BLOCK' ? 'rate-limit' : undefined,
            durationMs,
            passed,
          });

          if (req.delayMs) {
            await new Promise((r) => setTimeout(r, req.delayMs));
          }
        }

        burstSocket.destroy();
      }

      const detected = burstResults.filter((r) => r.passed).length;
      results.push({
        category: 'rate_limit_evasion',
        total: burstResults.length,
        detected,
        missed: burstResults.length - detected,
        detectionRate: burstResults.length > 0 ? detected / burstResults.length : 1,
        scenarios: burstResults,
      });
    }

    // Open DB for rate limit resets between categories.
    // Each non-rate-limit category tests a specific interceptor (permissions, PII, etc.).
    // Rate limiting is tested separately via burst groups. To prevent rate limit state
    // from contaminating other categories' measurements, we reset between each category.
    const benchDb = openDatabase({ path: join(tempDir, 'mcp-guard.db') });
    const resetRateLimits = benchDb.prepare('DELETE FROM rate_limits');

    // Run non-rate-limit categories (each starts with fresh rate limit state).
    // Rate limit behavior is tested exclusively by burst groups above. For all other
    // categories, rate limits are noise — reset them periodically so only the targeted
    // interceptor (permissions, PII, auth, etc.) determines the outcome.
    const RATE_LIMIT_RESET_INTERVAL = 50;

    for (const [category, categoryScenarios] of byCategory) {
      // Fresh rate limit state at category start
      resetRateLimits.run();

      console.log(`  Running ${category}: ${categoryScenarios.length} scenarios...`);
      const scenarioResults: ScenarioResult[] = [];

      for (let i = 0; i < categoryScenarios.length; i++) {
        // Reset rate limits periodically so non-rate-limit categories aren't affected
        if (i > 0 && i % RATE_LIMIT_RESET_INTERVAL === 0) {
          resetRateLimits.run();
        }
        const result = await runScenario(socket, categoryScenarios[i]);
        scenarioResults.push(result);
      }

      const detected = scenarioResults.filter((r) => r.passed).length;
      results.push({
        category,
        total: scenarioResults.length,
        detected,
        missed: scenarioResults.length - detected,
        detectionRate: scenarioResults.length > 0 ? detected / scenarioResults.length : 1,
        scenarios: scenarioResults,
      });
    }

    benchDb.close();

    // Audit log integrity check — fail-closed: if we can't verify, it's a FAIL
    let auditIntegrity: AuditIntegrityResult;
    const dbPath = join(tempDir, 'mcp-guard.db');
    try {
      const db = openDatabase({ path: dbPath });
      // Check both response-side PII (from mock servers) and request-side PII values
      const REQUEST_PII_VALUES = [
        'test@example.com', 'user.name+tag@domain.co.uk', 'admin@company.org',
        '+1-555-123-4567', '(555) 987-6543', '555.123.4567',
        '123-45-6789', '234-56-7890', '345-67-8901',
        '4111111111111111', '5500000000000004', '4242424242424242',
        'AKIAIOSFODNN7EXAMPLE', 'AKIAI44QH8DHBEXAMPLE',
        'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
      ];
      const allPiiValues = [...new Set([...Object.values(PII_RESPONSE_DATA), ...REQUEST_PII_VALUES])];
      // Search ALL text columns that could contain PII
      // Escape SQL LIKE metacharacters (% and _) to prevent false matches
      const searchStmt = db.prepare(
        `SELECT COUNT(*) as cnt FROM audit_logs WHERE params_summary LIKE ? ESCAPE '\\' OR block_reason LIKE ? ESCAPE '\\' OR interceptor_decisions LIKE ? ESCAPE '\\'`,
      );
      let piiFound = 0;
      for (const val of allPiiValues) {
        const escaped = val.replace(/%/g, '\\%').replace(/_/g, '\\_');
        const pattern = `%${escaped}%`;
        const rows = searchStmt.get(pattern, pattern, pattern) as { cnt: number } | undefined;
        if (rows && rows.cnt > 0) {
          console.log(`  WARNING: Raw PII value found in audit log: ${val.slice(0, 10)}...`);
          piiFound += rows.cnt;
        }
      }
      db.close();
      auditIntegrity = { passed: piiFound === 0, rawPiiFound: piiFound };
      if (piiFound === 0) {
        console.log('  Audit log integrity: PASS (no raw PII found)');
      } else {
        console.log(`  Audit log integrity: FAIL (${piiFound} raw PII values found)`);
      }
    } catch (err) {
      // Fail-closed: if we can't verify, treat as failure
      const message = err instanceof Error ? err.message : String(err);
      console.log(`  Audit log integrity: FAIL (could not verify: ${message})`);
      auditIntegrity = { passed: false, rawPiiFound: -1, error: message };
    }

    socket.destroy();
    return { results, auditIntegrity };
  } finally {
    if (daemonHandle) {
      await daemonHandle.shutdown();
    }
    await rm(tempDir, { recursive: true, force: true });
  }
}

// Direct execution
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*[\\/]/, ''))) {
  const quick = process.argv.includes('--quick');
  runSecurityBenchmark('benchmarks/configs/security-benchmark.yaml', { quick })
    .then((results) => {
      console.log(JSON.stringify(results, null, 2));
    })
    .catch((err) => {
      console.error('Security benchmark failed:', err);
      process.exit(1);
    });
}
