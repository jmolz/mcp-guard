import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { createTokenValidator } from '../../src/identity/token-validator.js';
import { OAuthError } from '../../src/errors.js';
import type { OAuthConfig } from '../../src/config/schema.js';

describe('Token Validator', () => {
  let server: Server;
  let port: number;
  let privateKey: CryptoKey;
  let jwksJson: object;

  const issuer = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    // Generate RSA key pair for signing test JWTs
    const keyPair = await generateKeyPair('RS256');
    privateKey = keyPair.privateKey as CryptoKey;
    const publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = 'test-key-1';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';
    jwksJson = { keys: [publicJwk] };

    // Start mock JWKS server
    server = createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(jwksJson));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterAll(() => {
    server.close();
  });

  function makeConfig(overrides?: Partial<OAuthConfig>): OAuthConfig {
    return {
      issuer: issuer(),
      client_id: 'test-client',
      scopes: ['openid', 'profile'],
      claims_to_roles: { claim_name: 'roles', mapping: {} },
      clock_tolerance_seconds: 30,
      ...overrides,
    };
  }

  async function signJwt(claims: Record<string, unknown>, opts?: { expiresIn?: string; audience?: string }): Promise<string> {
    let builder = new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setIssuer(issuer())
      .setAudience(opts?.audience ?? 'test-client')
      .setSubject(claims['sub'] as string ?? 'test-user');

    if (opts?.expiresIn) {
      builder = builder.setExpirationTime(opts.expiresIn);
    } else {
      builder = builder.setExpirationTime('1h');
    }

    return builder.sign(privateKey);
  }

  it('validates a correct JWT and returns claims + subject', async () => {
    const config = makeConfig();
    const validator = await createTokenValidator(config);
    const token = await signJwt({ sub: 'user-123', roles: ['admin'] });

    const result = await validator.validate(token);
    expect(result.valid).toBe(true);
    expect(result.subject).toBe('user-123');
    expect(result.claims.sub).toBe('user-123');
  });

  it('rejects expired JWT', async () => {
    const config = makeConfig({ clock_tolerance_seconds: 0 });
    const validator = await createTokenValidator(config);

    // Create a token that expired 2 minutes ago
    const token = await new SignJWT({ sub: 'user-expired' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 120)
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject('user-expired')
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow(OAuthError);
  });

  it('rejects JWT with wrong issuer', async () => {
    const config = makeConfig();
    const validator = await createTokenValidator(config);

    const token = await new SignJWT({ sub: 'user-wrong-iss' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer('https://wrong-issuer.example.com')
      .setSubject('user-wrong-iss')
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow(OAuthError);
  });

  it('rejects JWT with wrong audience when audience is configured', async () => {
    const config = makeConfig({ audience: 'expected-audience' });
    const validator = await createTokenValidator(config);

    const token = await new SignJWT({ sub: 'user-wrong-aud' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer(issuer())
      .setAudience('wrong-audience')
      .setSubject('user-wrong-aud')
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow(OAuthError);
  });

  it('rejects JWT with invalid signature (tampered payload)', async () => {
    const config = makeConfig();
    const validator = await createTokenValidator(config);

    const token = await signJwt({ sub: 'user-tampered' });
    // Tamper with the payload
    const parts = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'attacker', iss: issuer() })).toString('base64url');
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    await expect(validator.validate(tampered)).rejects.toThrow(OAuthError);
  });

  it('rejects malformed token (not a JWT)', async () => {
    const config = makeConfig();
    const validator = await createTokenValidator(config);

    await expect(validator.validate('not-a-jwt')).rejects.toThrow(OAuthError);
    await expect(validator.validate('')).rejects.toThrow(OAuthError);
  });

  it('rejects JWT missing sub claim', async () => {
    const config = makeConfig();
    const validator = await createTokenValidator(config);

    // Sign a token without a sub claim
    const token = await new SignJWT({ roles: ['admin'] })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer(issuer())
      .setAudience('test-client')
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow('JWT missing required "sub" claim');
  });

  it('allows slightly expired tokens within clock tolerance window', async () => {
    const config = makeConfig({ clock_tolerance_seconds: 60 });
    const validator = await createTokenValidator(config);

    // Token expired 30 seconds ago (within 60s tolerance)
    const token = await new SignJWT({ sub: 'user-clock-skew' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 30)
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject('user-clock-skew')
      .sign(privateKey);

    const result = await validator.validate(token);
    expect(result.valid).toBe(true);
    expect(result.subject).toBe('user-clock-skew');
  });

  it('blocks tokens expired beyond clock tolerance', async () => {
    const config = makeConfig({ clock_tolerance_seconds: 10 });
    const validator = await createTokenValidator(config);

    // Token expired 60 seconds ago (beyond 10s tolerance)
    const token = await new SignJWT({ sub: 'user-too-expired' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .setIssuer(issuer())
      .setAudience('test-client')
      .setSubject('user-too-expired')
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow(OAuthError);
  });
});
