import type { McpGuardConfig } from '../config/schema.js';
import { createUpstreamClient, type UpstreamClient } from '../proxy/mcp-client.js';
import type { Logger } from '../logger.js';

export interface ServerManager {
  startAll(): Promise<void>;
  stopAll(): Promise<void>;
  getClient(serverName: string): UpstreamClient | undefined;
  getStatus(): Map<string, string>;
}

export function createServerManager(config: McpGuardConfig, logger: Logger): ServerManager {
  const clients = new Map<string, UpstreamClient>();

  return {
    async startAll() {
      const entries = Object.entries(config.servers);
      logger.info('Starting upstream servers', { count: entries.length });

      const results = await Promise.allSettled(
        entries.map(async ([name, serverConfig]) => {
          const client = await createUpstreamClient(name, serverConfig, logger);
          clients.set(name, client);
          await client.connect();
        }),
      );

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.status === 'rejected') {
          logger.error('Failed to start server', {
            server: entries[i][0],
            error: String(result.reason),
          });
        }
      }
    },

    async stopAll() {
      logger.info('Stopping all upstream servers', { count: clients.size });
      const promises = Array.from(clients.values()).map((c) => c.disconnect());
      await Promise.allSettled(promises);
      clients.clear();
    },

    getClient(serverName: string) {
      return clients.get(serverName);
    },

    getStatus() {
      const status = new Map<string, string>();
      for (const [name, client] of clients) {
        status.set(name, client.status);
      }
      return status;
    },
  };
}
