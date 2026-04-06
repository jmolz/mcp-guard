import { readFile } from 'node:fs/promises';
import yaml from 'js-yaml';
import { configSchema, type McpGuardConfig } from './schema.js';
import { ConfigError } from '../errors.js';

function interpolateEnvVars(content: string): string {
  return content.replace(/\$\{([^}]+)\}/g, (_match, varName: string) => {
    const value = process.env[varName];
    if (value === undefined) {
      throw new ConfigError(`Unresolved environment variable: \${${varName}}`);
    }
    return value;
  });
}

export async function loadConfig(configPath?: string): Promise<McpGuardConfig> {
  const path = configPath ?? process.env['MCP_GUARD_CONFIG'] ?? 'mcp-guard.yaml';

  let content: string;
  try {
    content = await readFile(path, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new ConfigError(`Config file not found: ${path}`);
    }
    throw new ConfigError(`Failed to read config file: ${path} — ${String(err)}`);
  }

  const interpolated = interpolateEnvVars(content);
  const raw = yaml.load(interpolated);

  const result = configSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new ConfigError(`Invalid config:\n${issues}`);
  }

  return Object.freeze(result.data) as McpGuardConfig;
}
