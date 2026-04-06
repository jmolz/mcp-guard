import { connect, type Socket } from 'node:net';

export function writeFramed(socket: Socket, data: unknown): void {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

export function readFramed(socket: Socket, timeout = 5000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Read timeout'));
    }, timeout);

    function onData(chunk: Buffer) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + length) {
          cleanup();
          const json = buffer.subarray(4, 4 + length).toString('utf-8');
          resolve(JSON.parse(json));
        }
      }
    }

    function onError(err: Error) {
      cleanup();
      reject(err);
    }

    function onClose() {
      cleanup();
      reject(new Error('Socket closed'));
    }

    function cleanup() {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    }

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

export function connectSocket(path: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    socket.on('connect', () => resolve(socket));
    socket.on('error', reject);
  });
}
