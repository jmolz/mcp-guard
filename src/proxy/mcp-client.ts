import { Client } from '@modelcontextprotocol/sdk/client';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { ServerConfig } from '../config/schema.js';
import type { Logger } from '../logger.js';

export interface UpstreamClientOptions {
  authToken?: string;
}

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
  options?: UpstreamClientOptions,
): Promise<UpstreamClient> {
  let status: UpstreamClient['status'] = 'disconnected';

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

      try {
        let transport;

        if (config.transport === 'sse' || config.transport === 'streamable-http') {
          if (!config.url) {
            throw new Error(`Server '${name}' has transport '${config.transport}' but no url specified`);
          }

          const url = new URL(config.url);
          const headers: Record<string, string> = {};
          if (options?.authToken) {
            headers['Authorization'] = `Bearer ${options.authToken}`;
          }

          logger.info('Connecting to upstream server', { server: name, transport: config.transport, url: config.url });

          if (config.transport === 'sse') {
            transport = new SSEClientTransport(url, {
              requestInit: { headers },
            });
          } else {
            transport = new StreamableHTTPClientTransport(url, {
              requestInit: { headers },
            });
          }

          transport.onclose = () => {
            status = 'disconnected';
            logger.info('Upstream server disconnected', { server: name });
          };

          transport.onerror = (err: Error) => {
            status = 'error';
            logger.error('Upstream server error', { server: name, error: String(err) });
          };
        } else {
          // stdio transport
          const command = config.command;
          if (!command) {
            throw new Error(`Server '${name}' has transport 'stdio' but no command specified`);
          }

          logger.info('Connecting to upstream server', { server: name, command });

          transport = new StdioClientTransport({
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
        }

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
