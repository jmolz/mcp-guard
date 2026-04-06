export class McpGuardError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class ConfigError extends McpGuardError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
  }
}

export class AuthError extends McpGuardError {
  constructor(message: string) {
    super(message, 'AUTH_ERROR');
  }
}

export class PipelineError extends McpGuardError {
  constructor(message: string) {
    super(message, 'PIPELINE_ERROR');
  }
}

export class StorageError extends McpGuardError {
  constructor(message: string) {
    super(message, 'STORAGE_ERROR');
  }
}

export class BridgeError extends McpGuardError {
  constructor(message: string) {
    super(message, 'BRIDGE_ERROR');
  }
}
