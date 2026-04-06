import { z } from 'zod';
import {
  DEFAULT_SOCKET_PATH,
  DEFAULT_HOME,
  DEFAULT_DASHBOARD_PORT,
} from '../constants.js';

export const serverSchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).default([]),
  env: z.record(z.string()).default({}),
  url: z.string().url().optional(),
  transport: z.enum(['stdio', 'sse']).default('stdio'),
});

export const daemonSchema = z.object({
  socket_path: z.string().default(DEFAULT_SOCKET_PATH),
  home: z.string().default(DEFAULT_HOME),
  shutdown_timeout: z.number().min(1).default(30),
  log_level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  dashboard_port: z.number().min(1).max(65535).default(DEFAULT_DASHBOARD_PORT),
});

export const configSchema = z.object({
  servers: z.record(z.string(), serverSchema),
  daemon: daemonSchema.default({}),
});

export type McpGuardConfig = z.infer<typeof configSchema>;
export type ServerConfig = z.infer<typeof serverSchema>;
export type DaemonConfig = z.infer<typeof daemonSchema>;
