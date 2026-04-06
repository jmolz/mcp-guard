import { mkdir, writeFile } from 'node:fs/promises';
import type { McpGuardConfig } from '../config/schema.js';
import { ensureDaemonKey } from '../identity/daemon-key.js';
import { openDatabase } from '../storage/sqlite.js';
import { runMigrations } from '../storage/migrations.js';
import { createSocketServer } from './socket-server.js';
import { createServerManager } from './server-manager.js';
import { createProxyServer } from '../proxy/mcp-server.js';
import { registerShutdownHandlers } from './shutdown.js';
import { createLogger } from '../logger.js';
import { DEFAULT_PID_FILE, DEFAULT_DB_PATH } from '../constants.js';

export interface DaemonHandle {
  shutdown(): Promise<void>;
}

export async function startDaemon(config: McpGuardConfig): Promise<DaemonHandle> {
  const logger = createLogger({
    component: 'daemon',
  });

  const home = config.daemon.home;

  // 1. Ensure home directory
  await mkdir(home, { recursive: true, mode: 0o700 });
  logger.info('Home directory ready', { path: home });

  // 2. Ensure daemon key
  const daemonKey = await ensureDaemonKey();
  logger.info('Daemon key ready');

  // 3. Write PID file
  const pidFile = DEFAULT_PID_FILE;
  await writeFile(pidFile, String(process.pid), { mode: 0o600 });
  logger.info('PID file written', { pid: process.pid, path: pidFile });

  // 4. Open database and run migrations
  const db = openDatabase({ path: DEFAULT_DB_PATH });
  runMigrations(db);
  logger.info('Database ready', { path: DEFAULT_DB_PATH });

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

  // 7. Create socket server
  const socketServer = createSocketServer({
    socketPath: config.daemon.socket_path,
    daemonKey,
    logger,
    onConnection: (conn) => {
      conn.onMessage(async (msg) => {
        if (msg.type === 'mcp') {
          const response = await proxyServer.handleMessage(msg.data, msg.server);
          conn.send({ type: 'mcp', data: response });
        }
      });
    },
  });

  await socketServer.listen();

  // 8. Register shutdown handlers
  registerShutdownHandlers({
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
    async shutdown() {
      await socketServer.close();
      await serverManager.stopAll();
      try {
        db.pragma('wal_checkpoint(TRUNCATE)');
        db.close();
      } catch {
        // Best effort
      }
    },
  };
}
