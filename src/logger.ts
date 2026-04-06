type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  component: string;
  server?: string;
  bridge?: string;
  [key: string]: unknown;
}

export interface Logger {
  debug(message: string, extra?: Record<string, unknown>): void;
  info(message: string, extra?: Record<string, unknown>): void;
  warn(message: string, extra?: Record<string, unknown>): void;
  error(message: string, extra?: Record<string, unknown>): void;
}

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function getLogLevel(): LogLevel {
  const env = process.env['MCP_GUARD_LOG_LEVEL']?.toLowerCase();
  if (env && env in LEVEL_ORDER) {
    return env as LogLevel;
  }
  return 'info';
}

export function createLogger(defaultContext: LogContext): Logger {
  const minLevel = getLogLevel();

  function log(level: LogLevel, message: string, extra?: Record<string, unknown>) {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[minLevel]) {
      return;
    }

    const entry = {
      level,
      timestamp: new Date().toISOString(),
      ...defaultContext,
      message,
      ...extra,
    };

    // Write to stderr — stdout is reserved for MCP protocol in bridge
    process.stderr.write(JSON.stringify(entry) + '\n');
  }

  return {
    debug: (message, extra) => log('debug', message, extra),
    info: (message, extra) => log('info', message, extra),
    warn: (message, extra) => log('warn', message, extra),
    error: (message, extra) => log('error', message, extra),
  };
}
