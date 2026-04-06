export interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

// Bridge → Daemon
export type BridgeMessage =
  | { type: 'auth'; key: string }
  | { type: 'mcp'; server: string; data: JsonRpcMessage };

// Daemon → Bridge
export type DaemonMessage =
  | { type: 'auth_ok' }
  | { type: 'auth_fail'; reason: string }
  | { type: 'mcp'; data: JsonRpcMessage }
  | { type: 'shutdown'; reason: string }
  | { type: 'error'; message: string };
