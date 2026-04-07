import { Command } from 'commander';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { loadConfig } from './config/loader.js';
import { startDaemon } from './daemon/index.js';
import { startBridge } from './bridge/index.js';
import { isDaemonRunning } from './daemon/auto-start.js';
import { openDatabase, deriveDbEncryptionKey } from './storage/sqlite.js';
import { queryAuditLogs, formatAuditRow } from './audit/query.js';
import { readDaemonKey } from './identity/daemon-key.js';
import type { HealthResponse } from './dashboard/health.js';
import { executeOAuthFlow } from './identity/oauth-flow.js';
import { createTokenStore } from './identity/token-store.js';

const program = new Command()
  .name('mcp-guard')
  .description('Security proxy for MCP servers')
  .version('0.1.0');

program
  .command('start')
  .description('Start the MCP-Guard daemon')
  .option('-c, --config <path>', 'Path to config file')
  .option('-d, --daemon', 'Run in background (detached)')
  .action(async (opts: { config?: string; daemon?: boolean }) => {
    if (opts.daemon) {
      // Fork and detach
      const { fork } = await import('node:child_process');
      const child = fork(process.argv[1], ['start', '--config', opts.config ?? 'mcp-guard.yaml'], {
        detached: true,
        stdio: 'ignore',
      });
      child.unref();
      console.log(`Daemon started (PID: ${child.pid})`);
      process.exit(0);
    }

    try {
      const config = await loadConfig(opts.config);
      await startDaemon(config, opts.config);
    } catch (err) {
      console.error(`Failed to start daemon: ${err}`);
      process.exit(1);
    }
  });

program
  .command('stop')
  .description('Stop the running daemon')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    try {
      const config = await loadConfig(opts.config);
      const pidFile = join(config.daemon.home, 'daemon.pid');
      const pidStr = await readFile(pidFile, 'utf-8');
      const pid = parseInt(pidStr.trim(), 10);

      process.kill(pid, 'SIGTERM');
      console.log(`Sent SIGTERM to daemon (PID: ${pid})`);

      // Wait for exit
      const maxWait = 10_000;
      const interval = 200;
      let waited = 0;

      while (waited < maxWait) {
        await new Promise((r) => setTimeout(r, interval));
        waited += interval;
        try {
          process.kill(pid, 0); // Check if still alive
        } catch {
          console.log('Daemon stopped');
          return;
        }
      }

      // Force kill
      console.log('Daemon did not stop in time — sending SIGKILL');
      process.kill(pid, 'SIGKILL');

      try {
        await unlink(pidFile);
      } catch {
        // Already cleaned up
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        console.log('Daemon is not running (no PID file)');
      } else if (code === 'ESRCH') {
        console.log('Daemon process not found — cleaning up stale PID file');
      } else {
        console.error(`Failed to stop daemon: ${err}`);
        process.exit(1);
      }
    }
  });

program
  .command('connect')
  .description('Start a bridge to proxy an MCP server through the daemon')
  .requiredOption('-s, --server <name>', 'Server name from config')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { server: string; config?: string }) => {
    try {
      const config = await loadConfig(opts.config);
      await startBridge(opts.server, opts.config, {
        socketPath: config.daemon.socket_path,
        keyPath: join(config.daemon.home, 'daemon.key'),
        home: config.daemon.home,
      });
    } catch (err) {
      console.error(`Bridge failed: ${err}`);
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show daemon status')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    const config = await loadConfig(opts.config);
    const running = await isDaemonRunning(config.daemon.socket_path);
    if (running) {
      try {
        const pidFile = join(config.daemon.home, 'daemon.pid');
        const pidStr = await readFile(pidFile, 'utf-8');
        console.log(`Daemon is running (PID: ${pidStr.trim()})`);
      } catch {
        console.log('Daemon is running');
      }
    } else {
      console.log('Daemon is not running');
    }
  });

program
  .command('health')
  .description('Check daemon health (exit 0 if healthy, 1 if not)')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    const config = await loadConfig(opts.config);
    try {
      // Read actual bound port from file (supports port 0 / OS-assigned)
      const portPath = join(config.daemon.home, 'dashboard.port');
      let dashboardPort = config.daemon.dashboard_port;
      try {
        const portStr = await readFile(portPath, 'utf-8');
        dashboardPort = parseInt(portStr.trim(), 10);
      } catch {
        // Port file not found — use config value
      }
      const res = await fetch(`http://127.0.0.1:${dashboardPort}/healthz`);
      const health = await res.json() as HealthResponse;
      console.log(JSON.stringify(health, null, 2));
      process.exit(health.status === 'healthy' ? 0 : 1);
    } catch {
      // Fall back to socket check
      const running = await isDaemonRunning(config.daemon.socket_path);
      if (running) {
        console.log('Daemon is running (health endpoint unavailable)');
        process.exit(0);
      }
      console.log('Daemon is not running');
      process.exit(1);
    }
  });

program
  .command('dashboard-token')
  .description('Display the dashboard auth token')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    const config = await loadConfig(opts.config);
    const tokenPath = join(config.daemon.home, 'dashboard.token');
    try {
      const token = await readFile(tokenPath, 'utf-8');
      console.log(token.trim());
    } catch {
      console.log('No dashboard token found — start the daemon first');
      process.exit(1);
    }
  });

program
  .command('validate')
  .description('Validate config file')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    try {
      await loadConfig(opts.config);
      console.log('Config is valid');
    } catch (err) {
      console.error(`Config validation failed: ${err}`);
      process.exit(1);
    }
  });

program
  .command('logs')
  .description('Query audit logs')
  .option('-c, --config <path>', 'Path to config file')
  .option('-s, --server <name>', 'Filter by server name')
  .option('--last <duration>', 'Time range (e.g., 1h, 24h, 7d)')
  .option('-u, --user <name>', 'Filter by username')
  .option('-m, --method <method>', 'Filter by MCP method')
  .option('-t, --type <type>', 'Filter by type (allow/block)')
  .option('-l, --limit <count>', 'Maximum results', '100')
  .action(
    async (opts: {
      config?: string;
      server?: string;
      last?: string;
      user?: string;
      method?: string;
      type?: string;
      limit: string;
    }) => {
      let db: ReturnType<typeof openDatabase> | undefined;
      try {
        const config = await loadConfig(opts.config);
        const dbPath = join(config.daemon.home, 'mcp-guard.db');
        const dbOptions: { path: string; encryptionKey?: string } = { path: dbPath };
        if (config.daemon.encryption.enabled) {
          const keyPath = join(config.daemon.home, 'daemon.key');
          try {
            const daemonKey = await readDaemonKey(keyPath);
            dbOptions.encryptionKey = deriveDbEncryptionKey(daemonKey);
          } catch {
            console.error('Cannot read daemon key for encrypted database — is the daemon running?');
            process.exit(1);
          }
        }
        db = openDatabase(dbOptions);

        const parsedLimit = parseInt(opts.limit, 10);
        const limit = Number.isNaN(parsedLimit) || parsedLimit < 1 ? 100 : Math.min(parsedLimit, 10000);

        const rows = queryAuditLogs(db, {
          server: opts.server,
          last: opts.last,
          user: opts.user,
          method: opts.method,
          type: opts.type as 'allow' | 'block' | undefined,
          limit,
        });

        if (rows.length === 0) {
          console.log('No audit log entries found');
        } else {
          for (const row of rows) {
            console.log(formatAuditRow(row));
          }
          console.log(`\n${rows.length} entries`);
        }
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'SQLITE_CANTOPEN' || code === 'ENOENT') {
          console.log('No audit database found — is the daemon running?');
        } else {
          console.error(`Failed to query logs: ${err}`);
          process.exit(1);
        }
      } finally {
        db?.close();
      }
    },
  );

const authCmd = program
  .command('auth')
  .description('Manage OAuth authentication');

authCmd
  .command('login')
  .description('Authenticate with the configured OAuth provider')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    try {
      const config = await loadConfig(opts.config);
      if (config.auth.mode !== 'oauth' || !config.auth.oauth) {
        console.error('OAuth is not configured (auth.mode must be "oauth")');
        process.exit(1);
      }
      const result = await executeOAuthFlow({
        issuer: config.auth.oauth.issuer,
        clientId: config.auth.oauth.client_id,
        clientSecret: config.auth.oauth.client_secret,
        scopes: config.auth.oauth.scopes,
      });
      const store = createTokenStore(config.daemon.home);
      await store.save('default', {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        id_token: result.id_token,
        expires_at: result.expires_at,
        scope: result.scope,
      });
      console.log('Authentication successful — token stored');
    } catch (err) {
      console.error(`Authentication failed: ${err}`);
      process.exit(1);
    }
  });

authCmd
  .command('status')
  .description('Show current OAuth token status')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    try {
      const config = await loadConfig(opts.config);
      const store = createTokenStore(config.daemon.home);
      const token = await store.load('default');
      if (!token) {
        console.log('Not authenticated — run `mcp-guard auth login`');
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const expired = token.expires_at < now;
      const remaining = token.expires_at - now;
      console.log(`Status: ${expired ? 'EXPIRED' : 'Valid'}`);
      if (!expired) {
        console.log(`Expires in: ${Math.floor(remaining / 60)} minutes`);
      }
      console.log(`Scope: ${token.scope}`);
      // Decode JWT payload to show subject (without verifying — just for display)
      try {
        const parts = token.access_token.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          console.log(`Subject: ${payload.sub ?? 'unknown'}`);
        }
      } catch {
        // Opaque token — no subject to display
      }
    } catch (err) {
      console.error(`Failed to check status: ${err}`);
      process.exit(1);
    }
  });

authCmd
  .command('logout')
  .description('Remove stored OAuth tokens')
  .option('-c, --config <path>', 'Path to config file')
  .action(async (opts: { config?: string }) => {
    try {
      const config = await loadConfig(opts.config);
      const store = createTokenStore(config.daemon.home);
      await store.remove('default');
      console.log('Logged out — tokens removed');
    } catch (err) {
      console.error(`Failed to logout: ${err}`);
      process.exit(1);
    }
  });

program.parse();
