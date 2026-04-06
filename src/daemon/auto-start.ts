import { connect } from 'node:net';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { DEFAULT_SOCKET_PATH } from '../constants.js';
import { BridgeError } from '../errors.js';

export async function isDaemonRunning(socketPath?: string): Promise<boolean> {
  const path = socketPath ?? DEFAULT_SOCKET_PATH;

  return new Promise((resolve) => {
    const socket = connect(path);
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 1000);

    socket.on('connect', () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve(true);
    });

    socket.on('error', () => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

export async function autoStartDaemon(configPath?: string): Promise<void> {
  // Fork the CLI process with 'start' command in background mode
  const thisFile = fileURLToPath(import.meta.url);
  const cliPath = join(dirname(thisFile), '..', 'cli.js');

  const args = ['start', '--daemon'];
  if (configPath) {
    args.push('--config', configPath);
  }

  const child = fork(cliPath, args, {
    detached: true,
    stdio: 'ignore',
  });
  child.unref();

  // Wait for socket to become available
  const maxWait = 3000;
  const interval = 100;
  let waited = 0;

  while (waited < maxWait) {
    await new Promise((r) => setTimeout(r, interval));
    waited += interval;

    if (await isDaemonRunning()) {
      return;
    }
  }

  throw new BridgeError('Daemon failed to start within timeout');
}
