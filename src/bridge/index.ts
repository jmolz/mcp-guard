import { connect } from 'node:net';
import { authenticateToDaemon } from './auth.js';
import { isDaemonRunning, autoStartDaemon } from '../daemon/auto-start.js';
import { DEFAULT_SOCKET_PATH, DEFAULT_DAEMON_KEY_PATH, DEFAULT_HOME, MAX_MESSAGE_SIZE } from '../constants.js';
import { BridgeError } from '../errors.js';
import { createTokenStore } from '../identity/token-store.js';

export interface BridgeOptions {
  socketPath?: string;
  keyPath?: string;
  home?: string;
}

export async function startBridge(
  serverName: string,
  configPath?: string,
  options?: BridgeOptions,
): Promise<void> {
  const socketPath = options?.socketPath ?? DEFAULT_SOCKET_PATH;
  const keyPath = options?.keyPath ?? DEFAULT_DAEMON_KEY_PATH;
  const home = options?.home ?? DEFAULT_HOME;

  // 0. Load stored OAuth token only when config uses OAuth mode
  // Never inject tokens in non-OAuth modes to prevent credential leakage to upstream servers
  let bearerToken: string | undefined;
  try {
    const { loadConfig } = await import('../config/loader.js');
    const bridgeConfig = await loadConfig(configPath);
    if (bridgeConfig.auth.mode === 'oauth') {
      const tokenStore = createTokenStore(home);
      const stored = await tokenStore.load(serverName) ?? await tokenStore.load('default');
      if (stored) {
        const now = Math.floor(Date.now() / 1000);
        if (stored.expires_at > now) {
          bearerToken = stored.access_token;
        } else {
          process.stderr.write('OAuth token expired — run `mcp-guard auth login` to refresh\n');
        }
      }
    }
  } catch {
    // Config or token read failed — proceed without (daemon will BLOCK if oauth mode)
  }

  // 1. Ensure daemon is running
  if (!(await isDaemonRunning(socketPath))) {
    await autoStartDaemon(configPath, socketPath);
  }

  // 2. Connect to daemon
  const socket = connect(socketPath);

  await new Promise<void>((resolve, reject) => {
    socket.on('connect', resolve);
    socket.on('error', (err) => reject(new BridgeError(`Cannot connect to daemon: ${err.message}`)));
  });

  // 3. Authenticate
  await authenticateToDaemon(socket, keyPath);

  // 4. Pipe stdin → daemon
  let stdinBuffer = Buffer.alloc(0);
  process.stdin.on('data', (chunk: Buffer) => {
    stdinBuffer = Buffer.concat([stdinBuffer, chunk]);

    // Try to parse complete JSON-RPC messages (newline-delimited from MCP clients)
    while (true) {
      const newline = stdinBuffer.indexOf(0x0a); // \n
      if (newline === -1) break;

      const line = stdinBuffer.subarray(0, newline).toString('utf-8').trim();
      stdinBuffer = stdinBuffer.subarray(newline + 1);

      if (line.length === 0) continue;

      try {
        const data = JSON.parse(line);
        // Inject bearer token into MCP message params if available
        if (bearerToken && data.params) {
          data.params = { ...data.params, _bearer_token: bearerToken };
        } else if (bearerToken && !data.params) {
          data.params = { _bearer_token: bearerToken };
        }
        // Send as framed bridge message
        const msg = JSON.stringify({ type: 'mcp', server: serverName, data });
        const payload = Buffer.from(msg, 'utf-8');
        const header = Buffer.alloc(4);
        header.writeUInt32BE(payload.length, 0);
        socket.write(Buffer.concat([header, payload]));
      } catch {
        // Not valid JSON — skip
      }
    }
  });

  // 5. Pipe daemon → stdout
  let socketBuffer = Buffer.alloc(0);
  socket.on('data', (chunk: Buffer) => {
    socketBuffer = Buffer.concat([socketBuffer, chunk]);

    while (socketBuffer.length >= 4) {
      const length = socketBuffer.readUInt32BE(0);
      if (length > MAX_MESSAGE_SIZE) {
        socketBuffer = Buffer.alloc(0);
        return;
      }
      if (socketBuffer.length < 4 + length) break;

      const json = socketBuffer.subarray(4, 4 + length).toString('utf-8');
      socketBuffer = socketBuffer.subarray(4 + length);

      try {
        const msg = JSON.parse(json) as { type: string; data?: unknown; reason?: string };

        if (msg.type === 'mcp' && msg.data) {
          process.stdout.write(JSON.stringify(msg.data) + '\n');
        } else if (msg.type === 'shutdown') {
          process.exit(1);
        } else if (msg.type === 'error') {
          process.stderr.write(`Daemon error: ${JSON.stringify(msg)}\n`);
        }
      } catch {
        // Invalid JSON — skip
      }
    }
  });

  // 6. Handle stream close
  process.stdin.on('end', () => {
    socket.destroy();
    process.exit(0);
  });

  socket.on('close', () => {
    process.exit(1);
  });

  socket.on('error', (err) => {
    process.stderr.write(`Bridge socket error: ${err.message}\n`);
    process.exit(1);
  });
}
