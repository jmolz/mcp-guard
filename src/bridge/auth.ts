import type { Socket } from 'node:net';
import { readDaemonKey } from '../identity/daemon-key.js';
import { AuthError } from '../errors.js';
import { AUTH_TIMEOUT } from '../constants.js';

function writeFramed(socket: Socket, data: unknown): void {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

function readFramed(socket: Socket, timeout: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new AuthError('Auth response timeout'));
    }, timeout);

    function onData(chunk: Buffer) {
      buffer = Buffer.concat([buffer, chunk]);

      if (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + length) {
          cleanup();
          const json = buffer.subarray(4, 4 + length).toString('utf-8');
          try {
            resolve(JSON.parse(json));
          } catch {
            reject(new AuthError('Invalid auth response'));
          }
        }
      }
    }

    function onError(err: Error) {
      cleanup();
      reject(new AuthError(`Socket error during auth: ${err.message}`));
    }

    function cleanup() {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
    }

    socket.on('data', onData);
    socket.on('error', onError);
  });
}

export async function authenticateToDaemon(
  socket: Socket,
  keyPath?: string,
): Promise<void> {
  const key = await readDaemonKey(keyPath);
  writeFramed(socket, { type: 'auth', key: key.toString('hex') });

  const response = (await readFramed(socket, AUTH_TIMEOUT)) as { type: string; reason?: string };

  if (response.type !== 'auth_ok') {
    const reason = response.reason ?? 'Unknown auth failure';
    throw new AuthError(`Daemon auth failed: ${reason}`);
  }
}
