export type InterceptorDecision =
  | { action: 'PASS'; metadata?: Record<string, unknown> }
  | { action: 'MODIFY'; params: Record<string, unknown>; metadata?: Record<string, unknown> }
  | { action: 'BLOCK'; reason: string; code?: string; metadata?: Record<string, unknown> };

export interface InterceptorContext {
  /** The MCP JSON-RPC message */
  message: {
    method: string;
    params?: Record<string, unknown>;
  };
  /** Server name from config */
  server: string;
  /** Resolved identity of the caller */
  identity: ResolvedIdentity;
  /** Request or response direction */
  direction: 'request' | 'response';
  /** Metadata about the connection */
  metadata: {
    bridgeId: string;
    timestamp: number;
  };
}

export interface ResolvedIdentity {
  uid: number;
  pid?: number;
  username: string;
  roles: string[];
  /** How this identity was established */
  authMode?: 'os' | 'api_key' | 'oauth';
  /** OAuth 'sub' claim, if authenticated via OAuth */
  oauthSubject?: string;
}

export interface Interceptor {
  name: string;
  execute(ctx: InterceptorContext): Promise<InterceptorDecision>;
}

export interface PipelineResult {
  allowed: boolean;
  decisions: Array<{
    interceptor: string;
    decision: InterceptorDecision;
    durationMs: number;
  }>;
  finalParams?: Record<string, unknown>;
  /** Identity as resolved by the pipeline (may differ from initial if auth overrode it) */
  resolvedIdentity?: ResolvedIdentity;
}
