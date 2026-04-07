import * as oauth from 'oauth4webapi';
import { createServer, type Server } from 'node:http';
import { OAUTH_CALLBACK_PORT, OAUTH_CALLBACK_TIMEOUT } from '../constants.js';
import { OAuthError } from '../errors.js';

export interface OAuthFlowOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  callbackPort?: number;
}

export interface OAuthFlowResult {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_at: number;
  scope: string;
}

export async function executeOAuthFlow(options: OAuthFlowOptions): Promise<OAuthFlowResult> {
  const callbackPort = options.callbackPort ?? OAUTH_CALLBACK_PORT;
  const redirectUri = `http://127.0.0.1:${callbackPort}/callback`;

  // 1. Discover OpenID configuration
  const issuerUrl = new URL(options.issuer);
  const discoveryResponse = await oauth.discoveryRequest(issuerUrl);
  const authServer = await oauth.processDiscoveryResponse(issuerUrl, discoveryResponse);

  if (!authServer.authorization_endpoint) {
    throw new OAuthError('OAuth provider missing authorization_endpoint');
  }
  if (!authServer.token_endpoint) {
    throw new OAuthError('OAuth provider missing token_endpoint');
  }

  // 2. Generate PKCE verifier
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

  // 3. Build authorization URL
  const authUrl = new URL(authServer.authorization_endpoint);
  authUrl.searchParams.set('client_id', options.clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', options.scopes.join(' '));
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  const state = oauth.generateRandomState();
  authUrl.searchParams.set('state', state);

  // 4. Start callback server and wait for authorization code URL params
  const callbackParams = await waitForCallback(callbackPort, authUrl.toString());

  // 5. Validate callback params and extract authorization code
  const client: oauth.Client = { client_id: options.clientId };
  const validatedParams = oauth.validateAuthResponse(authServer, client, callbackParams, state);

  // 6. Exchange code for tokens
  const clientAuth = options.clientSecret
    ? oauth.ClientSecretPost(options.clientSecret)
    : oauth.None();

  const tokenResponse = await oauth.authorizationCodeGrantRequest(
    authServer,
    client,
    clientAuth,
    validatedParams,
    redirectUri,
    codeVerifier,
  );

  const result = await oauth.processAuthorizationCodeResponse(authServer, client, tokenResponse);

  const expiresIn = result.expires_in ?? 3600;
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

  return {
    access_token: result.access_token,
    refresh_token: result.refresh_token,
    id_token: result.id_token,
    expires_at: expiresAt,
    scope: result.scope ?? options.scopes.join(' '),
  };
}

export async function refreshOAuthToken(
  issuer: string,
  clientId: string,
  refreshToken: string,
  clientSecret?: string,
): Promise<OAuthFlowResult> {
  const issuerUrl = new URL(issuer);
  const discoveryResponse = await oauth.discoveryRequest(issuerUrl);
  const authServer = await oauth.processDiscoveryResponse(issuerUrl, discoveryResponse);

  const client: oauth.Client = { client_id: clientId };
  const clientAuth = clientSecret
    ? oauth.ClientSecretPost(clientSecret)
    : oauth.None();

  const tokenResponse = await oauth.refreshTokenGrantRequest(
    authServer,
    client,
    clientAuth,
    refreshToken,
  );

  const result = await oauth.processRefreshTokenResponse(authServer, client, tokenResponse);

  const expiresIn = result.expires_in ?? 3600;
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

  return {
    access_token: result.access_token,
    refresh_token: result.refresh_token ?? refreshToken,
    id_token: result.id_token,
    expires_at: expiresAt,
    scope: result.scope ?? '',
  };
}

async function waitForCallback(
  port: number,
  authUrl: string,
): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    const server: Server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);

      if (url.pathname !== '/callback') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const error = url.searchParams.get('error');
      if (error) {
        const desc = url.searchParams.get('error_description') ?? error;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><h1>Authentication Failed</h1><p>You can close this window.</p></body></html>');
        clearTimeout(timeout);
        server.close();
        reject(new OAuthError(`OAuth authorization failed: ${desc}`));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Authentication Successful</h1><p>You can close this window.</p></body></html>');
      clearTimeout(timeout);
      server.close();
      resolve(url.searchParams);
    });

    server.listen(port, '127.0.0.1', () => {
      openBrowser(authUrl).catch(() => {
        console.log(`\nOpen this URL in your browser to authenticate:\n\n  ${authUrl}\n`);
      });
    });

    const timeout = setTimeout(() => {
      server.close();
      reject(new OAuthError('OAuth flow timed out — no authorization callback received'));
    }, OAUTH_CALLBACK_TIMEOUT);
  });
}

async function openBrowser(url: string): Promise<void> {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execFileAsync = promisify(execFile);

  const platform = process.platform;
  if (platform === 'darwin') {
    await execFileAsync('open', [url]);
  } else if (platform === 'linux') {
    await execFileAsync('xdg-open', [url]);
  } else if (platform === 'win32') {
    await execFileAsync('cmd', ['/c', 'start', '', url]);
  } else {
    throw new Error(`Unsupported platform: ${platform}`);
  }
}
