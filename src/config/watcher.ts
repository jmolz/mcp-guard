import { watch, type FSWatcher } from 'node:fs';
import type { Logger } from '../logger.js';
import type { McpGuardConfig } from './schema.js';
import { reloadConfig } from './loader.js';
import { CONFIG_RELOAD_DEBOUNCE } from '../constants.js';

export interface ConfigWatcher {
  stop(): void;
}

export function createConfigWatcher(
  configPath: string,
  onChange: (newConfig: McpGuardConfig, oldConfig: McpGuardConfig) => void,
  logger: Logger,
  currentConfig: McpGuardConfig,
): ConfigWatcher {
  let oldConfig = currentConfig;
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  let watcher: FSWatcher;

  try {
    watcher = watch(configPath, { persistent: false }, (_eventType) => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }

      debounceTimer = setTimeout(async () => {
        try {
          const newConfig = await reloadConfig(configPath);
          const previousConfig = oldConfig;
          oldConfig = newConfig;
          onChange(newConfig, previousConfig);
          logger.info('Config reloaded successfully');
        } catch (err) {
          logger.warn('Config reload failed — keeping previous config', {
            error: String(err),
          });
        }
      }, CONFIG_RELOAD_DEBOUNCE);
    });
  } catch (err) {
    logger.error('Failed to watch config file — hot reload disabled', { error: String(err), path: configPath });
    return { stop() {} };
  }

  return {
    stop() {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      watcher.close();
    },
  };
}
