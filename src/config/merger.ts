import type { McpGuardConfig, PolicyConfig, PIIConfig } from './schema.js';

const PII_ACTION_SEVERITY: Record<string, number> = {
  warn: 0,
  redact: 1,
  block: 2,
};

/**
 * Merge personal config onto base config with floor semantics.
 * Personal config can only restrict, never relax base policies.
 */
export function mergeConfigs(
  base: McpGuardConfig,
  personal: McpGuardConfig,
): McpGuardConfig {
  return {
    // extends is consumed during loading — not carried forward
    servers: mergeServers(base, personal),
    // Base wins for daemon, auth — personal cannot change these
    daemon: base.daemon,
    auth: base.auth,
    // Stricter interceptor timeout
    interceptors: {
      timeout: Math.min(base.interceptors.timeout, personal.interceptors.timeout),
      timeout_action: base.interceptors.timeout_action,
    },
    pii: mergePii(base.pii, personal.pii),
    audit: base.audit,
  };
}

function mergeServers(
  base: McpGuardConfig,
  personal: McpGuardConfig,
): McpGuardConfig['servers'] {
  const merged: McpGuardConfig['servers'] = {};

  // Start with all base servers
  for (const [name, baseServer] of Object.entries(base.servers)) {
    const personalServer = personal.servers[name];
    if (!personalServer) {
      // No personal override — use base as-is
      merged[name] = baseServer;
      continue;
    }

    // If base policy is locked, personal overrides are ignored entirely
    if (baseServer.policy.locked) {
      merged[name] = baseServer;
      continue;
    }

    // Merge server config — personal can tighten but not relax
    merged[name] = {
      // Server connection config from base (personal cannot change transport/command)
      command: baseServer.command,
      args: baseServer.args,
      env: baseServer.env,
      url: baseServer.url,
      transport: baseServer.transport,
      upstream_auth_token: baseServer.upstream_auth_token,
      policy: mergePolicy(baseServer.policy, personalServer.policy),
    };
  }

  // Personal can add new servers (not in base)
  for (const [name, personalServer] of Object.entries(personal.servers)) {
    if (!(name in base.servers)) {
      merged[name] = personalServer;
    }
  }

  return merged;
}

function mergePolicy(base: PolicyConfig, personal: PolicyConfig): PolicyConfig {
  return {
    permissions: {
      // Intersection — only tools in BOTH lists survive
      allowed_tools: intersectLists(
        base.permissions.allowed_tools,
        personal.permissions.allowed_tools,
      ),
      // Union — all denials from both apply
      denied_tools: unionLists(base.permissions.denied_tools, personal.permissions.denied_tools),
      // Same for resources
      allowed_resources: intersectLists(
        base.permissions.allowed_resources,
        personal.permissions.allowed_resources,
      ),
      denied_resources: unionLists(base.permissions.denied_resources, personal.permissions.denied_resources),
    },
    rate_limit: {
      // Stricter (lower) value wins
      requests_per_minute: minOptional(
        base.rate_limit.requests_per_minute,
        personal.rate_limit.requests_per_minute,
      ),
      requests_per_hour: minOptional(
        base.rate_limit.requests_per_hour,
        personal.rate_limit.requests_per_hour,
      ),
      tool_limits: mergeToolLimits(base.rate_limit.tool_limits, personal.rate_limit.tool_limits),
    },
    sampling: {
      // AND — both must enable for sampling to work
      enabled: base.sampling.enabled && personal.sampling.enabled,
      max_tokens: minOptional(base.sampling.max_tokens, personal.sampling.max_tokens),
      rate_limit: minOptional(base.sampling.rate_limit, personal.sampling.rate_limit),
      // Stricter audit level wins (verbose > basic)
      audit: base.sampling.audit === 'verbose' || personal.sampling.audit === 'verbose'
        ? 'verbose' : 'basic',
    },
    locked: base.locked,
  };
}

function mergePii(base: PIIConfig, personal: PIIConfig): PIIConfig {
  return {
    // Base wins — personal cannot toggle PII scanning on or off
    enabled: base.enabled,
    // Lower threshold = more sensitive = stricter. Personal cannot raise it.
    confidence_threshold: Math.min(base.confidence_threshold, personal.confidence_threshold),
    // PII actions: personal can escalate (warn→block), cannot relax (block→warn)
    actions: mergePiiActions(base.actions, personal.actions),
    // Custom types: additive — personal can add, cannot remove base types
    custom_types: mergePiiCustomTypes(base.custom_types, personal.custom_types),
  };
}

function mergePiiActions(
  base: PIIConfig['actions'],
  personal: PIIConfig['actions'],
): PIIConfig['actions'] {
  const merged = { ...base };

  for (const [type, personalAction] of Object.entries(personal)) {
    const baseAction = base[type];
    if (!baseAction) {
      // Personal adds a new PII type action — allowed
      merged[type] = personalAction;
      continue;
    }

    // For each direction, take the stricter (higher severity) action
    merged[type] = {
      request: stricterAction(baseAction.request, personalAction.request),
      response: stricterAction(baseAction.response, personalAction.response),
    };
  }

  return merged;
}

function mergePiiCustomTypes(
  base: PIIConfig['custom_types'],
  personal: PIIConfig['custom_types'],
): PIIConfig['custom_types'] {
  const merged = { ...base };

  for (const [name, personalType] of Object.entries(personal)) {
    const baseType = base[name];
    if (!baseType) {
      // Personal adds a new type — allowed
      merged[name] = personalType;
      continue;
    }

    // Base type exists — personal can union patterns and escalate actions, not weaken
    merged[name] = {
      label: baseType.label,
      // Union patterns: all base patterns preserved, personal can add more
      patterns: [
        ...baseType.patterns,
        ...personalType.patterns.filter(
          (pp) => !baseType.patterns.some((bp) => bp.regex === pp.regex),
        ),
      ],
      // Actions: take the stricter of base vs personal per direction
      actions: {
        request: stricterAction(baseType.actions.request, personalType.actions.request),
        response: stricterAction(baseType.actions.response, personalType.actions.response),
      },
    };
  }

  return merged;
}

function stricterAction(
  base: 'block' | 'redact' | 'warn',
  personal: 'block' | 'redact' | 'warn',
): 'block' | 'redact' | 'warn' {
  const baseSeverity = PII_ACTION_SEVERITY[base] ?? 0;
  const personalSeverity = PII_ACTION_SEVERITY[personal] ?? 0;
  return personalSeverity >= baseSeverity ? personal : base;
}

function intersectLists(
  base: string[] | undefined,
  personal: string[] | undefined,
): string[] | undefined {
  // If base is undefined (no restriction), personal can set restrictions
  if (base === undefined) return personal;
  // If personal is undefined (no restriction), base restrictions apply
  if (personal === undefined) return base;
  // Both defined: intersection — only items in both survive
  const baseSet = new Set(base);
  return personal.filter((item) => baseSet.has(item));
}

function unionLists(base: string[], personal: string[]): string[] {
  return [...new Set([...base, ...personal])];
}

function minOptional(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.min(a, b);
}

function mergeToolLimits(
  base: Record<string, { requests_per_minute?: number }>,
  personal: Record<string, { requests_per_minute?: number }>,
): Record<string, { requests_per_minute?: number }> {
  const merged = { ...base };
  for (const [tool, personalLimit] of Object.entries(personal)) {
    const baseLimit = base[tool];
    if (!baseLimit) {
      merged[tool] = personalLimit;
      continue;
    }
    merged[tool] = {
      requests_per_minute: minOptional(
        baseLimit.requests_per_minute,
        personalLimit.requests_per_minute,
      ),
    };
  }
  return merged;
}
