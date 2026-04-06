import { createServer, type Server, type Socket } from 'node:net';
import { randomUUID } from 'node:crypto';
import { unlinkSync } from 'node:fs';
import { chmodSync } from 'node:fs';
import { verifyDaemonKey } from '../identity/daemon-key.js';
import { getPeerCredentials, verifyPeerIsCurrentUser } from '../identity/os-identity.js';
import type { BridgeMessage, DaemonMessage } from '../bridge/types.js';
import type { Logger } from '../logger.js';
import { AUTH_TIMEOUT, MAX_MESSAGE_SIZE } from '../constants.js';

export interface SocketServerOptions {
  socketPath: string;
  daemonKey: Buffer;
  onConnection: (conn: AuthenticatedConnection) => void;
  logger: Logger;
}

export interface AuthenticatedConnection {
  id: string;
  uid: number;
  pid?: number;
  send(message: DaemonMessage): void;
  onMessage(handler: (message: BridgeMessage) => void): void;
  close(): void;
}

export interface SocketServer {
  listen(): Promise<void>;
  close(): Promise<void>;
  getConnections(): AuthenticatedConnection[];
}

function writeFramed(socket: Socket, data: DaemonMessage): void {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

function createFrameParser(onMessage: (data: unknown) => void): (chunk: Buffer) => void {
  let buffer = Buffer.alloc(0);

  return (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 4) {
      const length = buffer.readUInt32BE(0);

      if (length > MAX_MESSAGE_SIZE) {
        buffer = Buffer.alloc(0);
        return;
      }

      if (buffer.length < 4 + length) {
        break; // Wait for more data
      }

      const json = buffer.subarray(4, 4 + length).toString('utf-8');
      buffer = buffer.subarray(4 + length);

      try {
        onMessage(JSON.parse(json));
      } catch {
        // Invalid JSON — skip frame
      }
    }
  };
}

export function createSocketServer(options: SocketServerOptions): SocketServer {
  const { socketPath, daemonKey, onConnection, logger } = options;
  const connections = new Map<string, AuthenticatedConnection>();
  let server: Server;

  function handleSocket(socket: Socket) {
    let authenticated = false;
    let connId: string | undefined;
    const messageHandlers: ((message: BridgeMessage) => void)[] = [];

    // Auth timeout — close if not authenticated within AUTH_TIMEOUT
    const authTimer = setTimeout(() => {
      if (!authenticated) {
        logger.warn('Connection auth timeout — closing');
        socket.destroy();
      }
    }, AUTH_TIMEOUT);

    const parser = createFrameParser((data) => {
      const msg = data as BridgeMessage;

      if (!authenticated) {
        if (msg.type !== 'auth') {
          socket.destroy();
          return;
        }

        // Verify daemon key
        const presented = Buffer.from(msg.key, 'hex');
        if (!verifyDaemonKey(presented, daemonKey)) {
          writeFramed(socket, { type: 'auth_fail', reason: 'Invalid daemon key' });
          socket.destroy();
          return;
        }

        // Verify peer credentials
        try {
          // SAFETY: socket._handle.fd is the internal file descriptor used by koffi
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const fd = (socket as any)._handle?.fd;
          if (fd !== undefined) {
            const creds = getPeerCredentials(fd);
            if (!verifyPeerIsCurrentUser(creds)) {
              writeFramed(socket, { type: 'auth_fail', reason: 'UID mismatch' });
              socket.destroy();
              return;
            }

            connId = randomUUID();
            authenticated = true;
            clearTimeout(authTimer);

            const conn: AuthenticatedConnection = {
              id: connId,
              uid: creds.uid,
              pid: creds.pid,
              send: (message) => {
                if (!socket.destroyed) writeFramed(socket, message);
              },
              onMessage: (handler) => messageHandlers.push(handler),
              close: () => socket.destroy(),
            };

            connections.set(connId, conn);
            writeFramed(socket, { type: 'auth_ok' });
            logger.info('Bridge authenticated', { bridge: connId, uid: creds.uid, pid: creds.pid });
            onConnection(conn);
          } else {
            writeFramed(socket, { type: 'auth_fail', reason: 'Cannot verify peer credentials' });
            socket.destroy();
          }
        } catch (err) {
          logger.error('Peer credential check failed', { error: String(err) });
          writeFramed(socket, { type: 'auth_fail', reason: 'Credential check failed' });
          socket.destroy();
        }
        return;
      }

      // Authenticated — forward to handlers
      for (const handler of messageHandlers) {
        handler(msg);
      }
    });

    socket.on('data', parser);

    socket.on('close', () => {
      clearTimeout(authTimer);
      if (connId) {
        connections.delete(connId);
        logger.info('Bridge disconnected', { bridge: connId });
      }
    });

    socket.on('error', (err) => {
      logger.error('Socket error', { bridge: connId, error: String(err) });
    });
  }

  return {
    async listen() {
      // Remove stale socket file
      try {
        unlinkSync(socketPath);
      } catch {
        // Doesn't exist — fine
      }

      server = createServer(handleSocket);

      return new Promise<void>((resolve, reject) => {
        server.on('error', reject);
        server.listen(socketPath, () => {
          chmodSync(socketPath, 0o600);
          logger.info('Socket server listening', { path: socketPath });
          resolve();
        });
      });
    },

    async close() {
      for (const conn of connections.values()) {
        conn.send({ type: 'shutdown', reason: 'daemon stopping' });
        conn.close();
      }
      connections.clear();

      return new Promise<void>((resolve) => {
        if (!server) {
          resolve();
          return;
        }
        server.close(() => {
          try {
            unlinkSync(socketPath);
          } catch {
            // Already removed
          }
          resolve();
        });
      });
    },

    getConnections() {
      return Array.from(connections.values());
    },
  };
}
