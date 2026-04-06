import { Command } from 'commander';
import { readFile, unlink } from 'node:fs/promises';
import { loadConfig } from './config/loader.js';
import { startDaemon } from './daemon/index.js';
import { startBridge } from './bridge/index.js';
import { isDaemonRunning } from './daemon/auto-start.js';
import { DEFAULT_PID_FILE } from './constants.js';

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
      await startDaemon(config);
    } catch (err) {
      console.error(`Failed to start daemon: ${err}`);
      process.exit(1);
    }
  });

program
  .command('stop')
  .description('Stop the running daemon')
  .action(async () => {
    try {
      const pidStr = await readFile(DEFAULT_PID_FILE, 'utf-8');
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
        await unlink(DEFAULT_PID_FILE);
      } catch {
        // Already cleaned up
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        console.log('Daemon is not running (no PID file)');
      } else if (code === 'ESRCH') {
        console.log('Daemon process not found — cleaning up PID file');
        try {
          await unlink(DEFAULT_PID_FILE);
        } catch {
          // Already cleaned up
        }
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
      await startBridge(opts.server, opts.config);
    } catch (err) {
      console.error(`Bridge failed: ${err}`);
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show daemon status')
  .action(async () => {
    const running = await isDaemonRunning();
    if (running) {
      try {
        const pidStr = await readFile(DEFAULT_PID_FILE, 'utf-8');
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
  .action(async () => {
    const running = await isDaemonRunning();
    process.exit(running ? 0 : 1);
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

program.parse();
