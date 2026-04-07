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
  onBeforeShutdown?: () => Promise<void>;
}

export interface ShutdownHandle {
  /** Trigger graceful shutdown. Idempotent — safe to call multiple times. */
  shutdown(signal?: string): Promise<void>;
}

export function registerShutdownHandlers(context: ShutdownContext): ShutdownHandle {
  let shutdownPromise: Promise<void> | undefined;

  async function shutdown(signal: string) {
    const { socketServer, serverManager, db, pidFile, logger, onBeforeShutdown } = context;
    logger.info('Shutdown initiated', { signal });

    try {
      // 0. Run pre-shutdown hooks (config watcher, dashboard server)
      // Failures must not abort the rest of shutdown (DB checkpoint, PID cleanup)
      if (onBeforeShutdown) {
        try {
          await onBeforeShutdown();
        } catch (err) {
          logger.warn('Pre-shutdown hook failed', { error: String(err) });
        }
      }

      // 1. Stop accepting new connections + notify bridges
      await socketServer.close();
      logger.info('Socket server closed');

      // 2. Disconnect upstream servers
      await serverManager.stopAll();
      logger.info('Upstream servers disconnected');

      // 3. Checkpoint and close database
      try {
        checkpointWal(db);
        db.close();
        logger.info('Database closed');
      } catch {
        // DB may already be closed — not an error
      }

      // 4. Remove PID file
      try {
        await unlink(pidFile);
      } catch {
        // Already removed
      }

      logger.info('Shutdown complete');
    } catch (err) {
      logger.error('Shutdown error', { error: String(err) });
      throw err;
    }
  }

  function triggerShutdown(signal: string): Promise<void> {
    if (!shutdownPromise) {
      shutdownPromise = shutdown(signal);
    }
    return shutdownPromise;
  }

  // Signal handlers add process.exit after shutdown completes
  function signalHandler(signal: string) {
    const timer = setTimeout(() => {
      context.logger.warn('Shutdown timeout exceeded — forcing exit', { signal });
      process.exit(1);
    }, context.timeout);

    triggerShutdown(signal)
      .then(() => {
        clearTimeout(timer);
        process.exit(0);
      })
      .catch(() => {
        clearTimeout(timer);
        process.exit(1);
      });
  }

  process.once('SIGTERM', () => signalHandler('SIGTERM'));
  process.once('SIGINT', () => signalHandler('SIGINT'));

  return {
    shutdown(signal?: string) {
      return triggerShutdown(signal ?? 'programmatic');
    },
  };
}
