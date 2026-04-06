import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { McpGuardConfig } from '../config/schema.js';
import { ensureDaemonKey } from '../identity/daemon-key.js';
import { openDatabase } from '../storage/sqlite.js';
import { runMigrations } from '../storage/migrations.js';
import { createSocketServer } from './socket-server.js';
import { createServerManager } from './server-manager.js';
import { createProxyServer } from '../proxy/mcp-server.js';
import { registerShutdownHandlers } from './shutdown.js';
import { createLogger } from '../logger.js';
import { createPipeline } from '../interceptors/pipeline.js';
import { createAuthInterceptor } from '../interceptors/auth.js';
import { createRateLimitInterceptor } from '../interceptors/rate-limit.js';
import { createPermissionInterceptor } from '../interceptors/permissions.js';
import { createSamplingGuardInterceptor } from '../interceptors/sampling-guard.js';
import { createPiiInterceptor } from '../interceptors/pii-detect.js';
import { createPIIRegistry } from '../pii/registry.js';
import { createRateLimitStore } from '../storage/rate-limit-store.js';
import { createAuditStore } from '../audit/store.js';
import { createAuditTap } from '../audit/tap.js';
import { resolveIdentity } from '../identity/roles.js';
import { filterToolsList, filterResourcesList, filterCapabilities } from '../proxy/capability-filter.js';
import type { InterceptorContext } from '../interceptors/types.js';

export interface DaemonHandle {
  shutdown(): Promise<void>;
}

export async function startDaemon(config: McpGuardConfig): Promise<DaemonHandle> {
  const logger = createLogger({
    component: 'daemon',
  });

  const home = config.daemon.home;

  // Derive all state paths from config.daemon.home
  const keyPath = join(home, 'daemon.key');
  const pidFile = join(home, 'daemon.pid');
  const dbPath = join(home, 'mcp-guard.db');

  // 1. Ensure home directory
  await mkdir(home, { recursive: true, mode: 0o700 });
  logger.info('Home directory ready', { path: home });

  // 2. Ensure daemon key
  const daemonKey = await ensureDaemonKey(keyPath);
  logger.info('Daemon key ready');

  // 3. Write PID file
  await writeFile(pidFile, String(process.pid), { mode: 0o600 });
  logger.info('PID file written', { pid: process.pid, path: pidFile });

  // 4. Open database and run migrations
  const db = openDatabase({ path: dbPath });
  runMigrations(db);
  logger.info('Database ready', { path: dbPath });

  // 5. Create server manager and connect to upstream servers
  const serverManager = createServerManager(config, logger);
  await serverManager.startAll();

  // 6. Create proxy server
  const upstreamClients = new Map<string, import('../proxy/mcp-client.js').UpstreamClient>();
  for (const name of Object.keys(config.servers)) {
    const client = serverManager.getClient(name);
    if (client) {
      upstreamClients.set(name, client);
    }
  }
  const proxyServer = createProxyServer(upstreamClients, logger);

  // 7. Create interceptor pipeline
  const rateLimitStore = createRateLimitStore(db);
  const auditStore = createAuditStore(db);
  const auditTap = createAuditTap(auditStore, logger, config);

  const piiRegistry = createPIIRegistry(config.pii);

  const pipeline = createPipeline({
    interceptors: [
      createAuthInterceptor(config),
      createRateLimitInterceptor(rateLimitStore, config),
      createPermissionInterceptor(config),
      createSamplingGuardInterceptor(config),
      createPiiInterceptor(piiRegistry, config),
    ],
    timeout: config.interceptors.timeout * 1000,
    logger,
  });

  const responsePipeline = createPipeline({
    interceptors: [
      createPiiInterceptor(piiRegistry, config),
    ],
    timeout: config.interceptors.timeout * 1000,
    logger,
  });

  logger.info('Interceptor pipeline ready', {
    interceptors: ['auth', 'rate-limit', 'permissions', 'sampling-guard', 'pii-detect'],
    timeout: config.interceptors.timeout,
  });

  // 8. Create socket server
  const socketServer = createSocketServer({
    socketPath: config.daemon.socket_path,
    daemonKey,
    logger,
    onConnection: (conn) => {
      const identity = resolveIdentity(conn.uid, conn.pid, config);

      conn.onMessage(async (msg) => {
        if (msg.type === 'mcp') {
          const method = msg.data.method ?? 'unknown';
          const startTime = Date.now();

          // Wrap entire handler in try/catch to ensure audit tap fires
          // even on unexpected runtime errors (structural audit guarantee)
          try {
            const ctx: InterceptorContext = {
              message: { method, params: msg.data.params },
              server: msg.server,
              identity,
              direction: 'request',
              metadata: { bridgeId: conn.id, timestamp: Date.now() },
            };

            // Run pipeline
            const pipelineResult = await pipeline.execute(ctx);
            const latencyMs = Date.now() - startTime;

            // Audit tap records everything (including blocks)
            auditTap.record({
              bridgeId: conn.id,
              server: msg.server,
              method,
              direction: 'request',
              identity,
              toolOrResource: extractToolOrResource(msg.data),
              pipelineResult,
              latencyMs,
            });

            if (!pipelineResult.allowed) {
              const blockReason = pipelineResult.decisions.find(
                (d) => d.decision.action === 'BLOCK',
              );
              conn.send({
                type: 'mcp',
                data: {
                  jsonrpc: '2.0',
                  id: msg.data.id,
                  error: {
                    code: -32600,
                    message: blockReason?.decision.action === 'BLOCK'
                      ? blockReason.decision.reason
                      : 'Blocked by security policy',
                  },
                },
              });
              return;
            }

            // Forward to upstream (with potentially modified params)
            const upstreamMsg = pipelineResult.finalParams
              ? { ...msg.data, params: pipelineResult.finalParams }
              : msg.data;
            const response = await proxyServer.handleMessage(upstreamMsg, msg.server);

            // Run response-direction PII scanning on result AND error payloads
            // No outer pii.enabled guard — interceptor checks internally, audit tap must always fire
            const responseContent = response.result ?? response.error;
            if (responseContent) {
              const responseCtx: InterceptorContext = {
                message: { method, params: responseContent as Record<string, unknown> },
                server: msg.server,
                identity,
                direction: 'response',
                metadata: { bridgeId: conn.id, timestamp: Date.now() },
              };

              const responseResult = await responsePipeline.execute(responseCtx);

              auditTap.record({
                bridgeId: conn.id,
                server: msg.server,
                method,
                direction: 'response',
                identity,
                toolOrResource: extractToolOrResource(msg.data),
                pipelineResult: responseResult,
                latencyMs: Date.now() - startTime,
              });

              if (!responseResult.allowed) {
                conn.send({
                  type: 'mcp',
                  data: {
                    jsonrpc: '2.0',
                    id: msg.data.id,
                    error: { code: -32600, message: 'Response blocked by PII policy' },
                  },
                });
                return;
              }

              if (responseResult.finalParams) {
                if (response.result) {
                  response.result = responseResult.finalParams;
                } else if (response.error) {
                  // Apply redacted fields back to the typed error structure
                  const redacted = responseResult.finalParams;
                  if (typeof redacted['message'] === 'string') {
                    response.error.message = redacted['message'];
                  }
                  if ('data' in redacted) {
                    response.error.data = redacted['data'];
                  }
                }
              }
            }

            // Filter sampling capability from initialize response
            if (msg.data.method === 'initialize' && response.result) {
              const result = response.result as { capabilities?: Record<string, unknown> };
              const serverConfig = config.servers[msg.server];
              if (result.capabilities && serverConfig) {
                result.capabilities = filterCapabilities(result.capabilities, serverConfig);
              }
            }

            // Apply capability filtering to list responses
            if (msg.data.method === 'tools/list' && response.result) {
              const result = response.result as { tools?: Array<{ name: string }> };
              const serverConfig = config.servers[msg.server];
              if (result.tools && serverConfig) {
                result.tools = filterToolsList(result.tools, serverConfig, identity, config);
              }
            }

            if (msg.data.method === 'resources/list' && response.result) {
              const result = response.result as { resources?: Array<{ uri: string }> };
              const serverConfig = config.servers[msg.server];
              if (result.resources && serverConfig) {
                result.resources = filterResourcesList(result.resources, serverConfig, identity, config);
              }
            }

            conn.send({ type: 'mcp', data: response });
          } catch (err) {
            const latencyMs = Date.now() - startTime;
            logger.error('Message handler failed', { error: String(err), method });

            // Audit tap MUST fire even on unexpected errors
            auditTap.record({
              bridgeId: conn.id,
              server: msg.server,
              method,
              direction: 'request',
              identity,
              toolOrResource: extractToolOrResource(msg.data),
              pipelineResult: {
                allowed: false,
                decisions: [{
                  interceptor: 'internal',
                  decision: { action: 'BLOCK', reason: `Internal error: ${String(err)}` },
                  durationMs: latencyMs,
                }],
              },
              latencyMs,
            });

            conn.send({
              type: 'mcp',
              data: {
                jsonrpc: '2.0',
                id: msg.data.id,
                error: { code: -32603, message: 'Internal error' },
              },
            });
          }
        }
      });
    },
  });

  await socketServer.listen();

  // 9. Register shutdown handlers (single unified shutdown path)
  const shutdownHandle = registerShutdownHandlers({
    socketServer,
    serverManager,
    db,
    pidFile,
    timeout: config.daemon.shutdown_timeout * 1000,
    logger,
  });

  logger.info('Daemon started', {
    socket: config.daemon.socket_path,
    servers: Object.keys(config.servers),
    pid: process.pid,
  });

  return {
    shutdown() {
      return shutdownHandle.shutdown();
    },
  };
}

function extractToolOrResource(data: { method?: string; params?: Record<string, unknown> }): string | undefined {
  if (data.method === 'tools/call') {
    return data.params?.['name'] as string | undefined;
  }
  if (data.method === 'resources/read') {
    return data.params?.['uri'] as string | undefined;
  }
  return undefined;
}
