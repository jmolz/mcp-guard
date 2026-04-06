import type { SocketServer } from './socket-server.js';
import type { ServerManager } from './server-manager.js';
import type Database from 'better-sqlite3-multiple-ciphers';
import { unlink } from 'node:fs/promises';
import { checkpointWal } from '../storage/sqlite.js';
import type { Logger } from '../logger.js';

export interface ShutdownContext {
  socketServer: SocketServer;
  serverManager: ServerManager;
  db: Database.Database;
  pidFile: string;
  timeout: number;
  logger: Logger;
}

export function registerShutdownHandlers(context: ShutdownContext): void {
  let shuttingDown = false;

  async function shutdown(signal: string) {
    if (shuttingDown) return;
    shuttingDown = true;

    const { socketServer, serverManager, db, pidFile, timeout, logger } = context;
    logger.info('Shutdown initiated', { signal });

    const timer = setTimeout(() => {
      logger.warn('Shutdown timeout — forcing exit');
      process.exit(1);
    }, timeout);

    try {
      // 1. Stop accepting new connections + notify bridges
      await socketServer.close();
      logger.info('Socket server closed');

      // 2. Disconnect upstream servers
      await serverManager.stopAll();
      logger.info('Upstream servers disconnected');

      // 3. Checkpoint and close database
      checkpointWal(db);
      db.close();
      logger.info('Database closed');

      // 4. Remove PID file
      try {
        await unlink(pidFile);
      } catch {
        // Already removed
      }

      logger.info('Shutdown complete');
      clearTimeout(timer);
      process.exit(0);
    } catch (err) {
      logger.error('Shutdown error', { error: String(err) });
      clearTimeout(timer);
      process.exit(1);
    }
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
