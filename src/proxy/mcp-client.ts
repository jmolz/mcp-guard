import { Client } from '@modelcontextprotocol/sdk/client';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { ServerConfig } from '../config/schema.js';
import type { Logger } from '../logger.js';

export interface UpstreamClient {
  name: string;
  client: Client;
  status: 'connecting' | 'connected' | 'disconnected' | 'error';
  connect(): Promise<void>;
  disconnect(): Promise<void>;
}

export async function createUpstreamClient(
  name: string,
  config: ServerConfig,
  logger: Logger,
): Promise<UpstreamClient> {
  let status: UpstreamClient['status'] = 'disconnected';

  if (config.transport === 'sse') {
    throw new Error(`SSE transport not yet supported (deferred to Phase 4) — server: ${name}`);
  }

  const command = config.command;
  if (!command) {
    throw new Error(`Server '${name}' has transport 'stdio' but no command specified`);
  }

  const client = new Client({
    name: `mcp-guard-upstream-${name}`,
    version: '0.1.0',
  });

  const upstream: UpstreamClient = {
    name,
    client,
    get status() {
      return status;
    },

    async connect() {
      status = 'connecting';
      logger.info('Connecting to upstream server', { server: name, command: config.command });

      try {
        const transport = new StdioClientTransport({
          command,
          args: config.args,
          env: { ...process.env, ...config.env } as Record<string, string>,
        });

        transport.onclose = () => {
          status = 'disconnected';
          logger.info('Upstream server disconnected', { server: name });
        };

        transport.onerror = (err) => {
          status = 'error';
          logger.error('Upstream server error', { server: name, error: String(err) });
        };

        await client.connect(transport);
        status = 'connected';
        logger.info('Connected to upstream server', { server: name });
      } catch (err) {
        status = 'error';
        logger.error('Failed to connect to upstream server', {
          server: name,
          error: String(err),
        });
        throw err;
      }
    },

    async disconnect() {
      try {
        await client.close();
      } catch {
        // Best effort
      }
      status = 'disconnected';
      logger.info('Disconnected from upstream server', { server: name });
    },
  };

  return upstream;
}
