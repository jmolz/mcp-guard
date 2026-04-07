import { createServer, type Server } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Logger } from '../logger.js';
import type { HealthContext } from './health.js';
import { buildHealthResponse } from './health.js';
import { DashboardError } from '../errors.js';

export interface DashboardServer {
  listen(): Promise<void>;
  close(): Promise<void>;
  getAuthToken(): string;
  getPort(): number;
}

export interface DashboardServerOptions {
  port: number;
  healthContext: HealthContext;
  authToken?: string;
  logger: Logger;
  home?: string;
}

export function createDashboardServer(options: DashboardServerOptions): DashboardServer {
  const { port, healthContext, logger } = options;
  const authToken = options.authToken ?? randomBytes(32).toString('hex');
  const authTokenBuffer = Buffer.from(authToken, 'utf-8');

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);

    if (url.pathname === '/healthz' && req.method === 'GET') {
      const health = buildHealthResponse(healthContext);
      const statusCode = health.status === 'unhealthy' ? 503 : 200;
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(health));
      return;
    }

    if (url.pathname === '/api/status' && req.method === 'GET') {
      if (!verifyBearerToken(req.headers.authorization, authTokenBuffer)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      const health = buildHealthResponse(healthContext);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(health));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  return {
    async listen() {
      await new Promise<void>((resolve, reject) => {
        server.on('error', (err) => {
          reject(new DashboardError(`Dashboard server failed to start: ${err.message}`));
        });
        server.listen(port, '127.0.0.1', () => {
          logger.info('Dashboard server started', { port });
          resolve();
        });
      });

      // Persist token and actual port for CLI access
      if (options.home) {
        const actualPort = String(server.address() && typeof server.address() === 'object'
          ? (server.address() as { port: number }).port
          : port);
        const tokenPath = join(options.home, 'dashboard.token');
        const portPath = join(options.home, 'dashboard.port');
        await writeFile(tokenPath, authToken, { mode: 0o600 });
        await writeFile(portPath, actualPort, { mode: 0o600 });
      }
    },

    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err) {
            reject(new DashboardError(`Dashboard server close failed: ${err.message}`));
          } else {
            logger.info('Dashboard server closed');
            resolve();
          }
        });
      });
    },

    getAuthToken() {
      return authToken;
    },

    getPort() {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        return addr.port;
      }
      return port;
    },
  };
}

function verifyBearerToken(
  authHeader: string | undefined,
  expectedTokenBuffer: Buffer,
): boolean {
  if (!authHeader?.startsWith('Bearer ')) {
    return false;
  }

  const provided = Buffer.from(authHeader.slice(7), 'utf-8');
  if (provided.length !== expectedTokenBuffer.length) {
    return false;
  }

  return timingSafeEqual(provided, expectedTokenBuffer);
}
