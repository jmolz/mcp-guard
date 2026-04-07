import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_HOME = join(homedir(), '.config', 'mcp-guard');
export const DEFAULT_SOCKET_PATH = join(DEFAULT_HOME, 'daemon.sock');
export const DEFAULT_PID_FILE = join(DEFAULT_HOME, 'daemon.pid');
export const DEFAULT_DAEMON_KEY_PATH = join(DEFAULT_HOME, 'daemon.key');
export const DEFAULT_DB_PATH = join(DEFAULT_HOME, 'mcp-guard.db');
export const DEFAULT_CONFIG_PATH = 'mcp-guard.yaml';
export const DEFAULT_DASHBOARD_PORT = 9777;
export const DEFAULT_SHUTDOWN_TIMEOUT = 30_000;
export const DAEMON_KEY_BYTES = 32;
export const AUTH_TIMEOUT = 5_000;
export const MAX_MESSAGE_SIZE = 4 * 1024 * 1024; // 4MB
export const DEFAULT_EXTENDS_CACHE_DIR = 'extends-cache';
export const EXTENDS_FETCH_TIMEOUT = 10_000; // 10s
export const CONFIG_RELOAD_DEBOUNCE = 250; // 250ms

// OAuth
export const OAUTH_TOKEN_DIR = 'oauth-tokens';
export const OAUTH_TOKEN_FILE_MODE = 0o600;
export const OAUTH_CALLBACK_PORT = 8399;
export const OAUTH_CALLBACK_TIMEOUT = 120_000; // 2 min for user to complete browser auth
