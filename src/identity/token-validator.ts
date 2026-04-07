import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { OAuthConfig } from '../config/schema.js';
import { OAuthError } from '../errors.js';

export interface TokenValidationResult {
  valid: true;
  claims: JWTPayload;
  subject: string;
}

export interface TokenValidator {
  validate(token: string): Promise<TokenValidationResult>;
}

/**
 * Discover the JWKS URI from the issuer's OIDC discovery endpoint.
 * Falls back to the standard /.well-known/jwks.json path if discovery fails.
 */
async function discoverJwksUri(issuer: string): Promise<string> {
  const discoveryUrl = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  try {
    const response = await fetch(discoveryUrl);
    if (response.ok) {
      const metadata = await response.json() as { jwks_uri?: string };
      if (metadata.jwks_uri && typeof metadata.jwks_uri === 'string') {
        return metadata.jwks_uri;
      }
    }
  } catch {
    // Discovery failed — fall back to standard path
  }
  return `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`;
}

export async function createTokenValidator(config: OAuthConfig): Promise<TokenValidator> {
  // Resolve JWKS endpoint: explicit jwks_uri, or OIDC discovery, or standard fallback
  const jwksUri = config.jwks_uri ?? await discoverJwksUri(config.issuer);
  const jwks = createRemoteJWKSet(new URL(jwksUri));

  return {
    async validate(token: string): Promise<TokenValidationResult> {
      try {
        // Default audience to client_id — always validate who the token was issued for
        const audience = config.audience ?? config.client_id;
        const { payload } = await jwtVerify(token, jwks, {
          issuer: config.issuer,
          audience,
          clockTolerance: config.clock_tolerance_seconds,
        });

        if (!payload.sub) {
          throw new OAuthError('JWT missing required "sub" claim');
        }

        return {
          valid: true,
          claims: payload,
          subject: payload.sub,
        };
      } catch (err) {
        if (err instanceof OAuthError) {
          throw err;
        }
        throw new OAuthError(`JWT validation failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  };
}
