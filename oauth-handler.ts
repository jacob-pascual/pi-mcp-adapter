// oauth-handler.ts - OAuth token management for MCP servers
// Supports full browser-based OAuth 2.0 authorization code flow with PKCE
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthTokens,
  OAuthClientMetadata,
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
} from "@modelcontextprotocol/sdk/shared/auth.js";

// ── Storage paths ────────────────────────────────────────────────

function getOAuthDir(serverName: string): string {
  return join(homedir(), ".pi", "agent", "mcp-oauth", serverName);
}

function getTokensPath(serverName: string): string {
  return join(getOAuthDir(serverName), "tokens.json");
}

function getClientInfoPath(serverName: string): string {
  return join(getOAuthDir(serverName), "client-info.json");
}

function getCodeVerifierPath(serverName: string): string {
  return join(getOAuthDir(serverName), "code-verifier.txt");
}

function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true });
}

// ── Token file I/O ──────────────────────────────────────────────

interface StoredTokens extends OAuthTokens {
  expiresAt?: number; // absolute timestamp ms
}

function saveTokensToFile(serverName: string, tokens: OAuthTokens): void {
  const dir = getOAuthDir(serverName);
  ensureDir(dir);
  const stored: StoredTokens = { ...tokens };
  if (tokens.expires_in && typeof tokens.expires_in === "number") {
    stored.expiresAt = Date.now() + tokens.expires_in * 1000;
  }
  writeFileSync(getTokensPath(serverName), JSON.stringify(stored, null, 2));
}

function loadTokensFromFile(serverName: string): OAuthTokens | undefined {
  const tokensPath = getTokensPath(serverName);
  if (!existsSync(tokensPath)) return undefined;

  try {
    const stored: StoredTokens = JSON.parse(readFileSync(tokensPath, "utf-8"));
    if (!stored.access_token || typeof stored.access_token !== "string") {
      return undefined;
    }
    // Check expiration if expiresAt is set
    if (stored.expiresAt && typeof stored.expiresAt === "number") {
      if (Date.now() > stored.expiresAt) {
        return undefined; // expired
      }
    }
    return {
      access_token: stored.access_token,
      token_type: stored.token_type ?? "bearer",
      refresh_token: stored.refresh_token,
      expires_in: stored.expires_in,
    };
  } catch {
    return undefined;
  }
}

// ── Client info persistence ─────────────────────────────────────

function saveClientInfo(serverName: string, info: OAuthClientInformationMixed): void {
  const dir = getOAuthDir(serverName);
  ensureDir(dir);
  writeFileSync(getClientInfoPath(serverName), JSON.stringify(info, null, 2));
}

function loadClientInfo(serverName: string): OAuthClientInformationMixed | undefined {
  const path = getClientInfoPath(serverName);
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return undefined;
  }
}

// ── Code verifier persistence ───────────────────────────────────

function saveCodeVerifierToFile(serverName: string, verifier: string): void {
  const dir = getOAuthDir(serverName);
  ensureDir(dir);
  writeFileSync(getCodeVerifierPath(serverName), verifier);
}

function loadCodeVerifierFromFile(serverName: string): string {
  const path = getCodeVerifierPath(serverName);
  if (!existsSync(path)) return "";
  return readFileSync(path, "utf-8").trim();
}

// ── Backward-compat export (used by server-manager for simple token check) ──

/**
 * Get stored OAuth tokens for a server (if any).
 * Returns undefined if no tokens or tokens are expired.
 */
export function getStoredTokens(serverName: string): OAuthTokens | undefined {
  return loadTokensFromFile(serverName);
}

// ── Localhost callback server ───────────────────────────────────

interface CallbackResult {
  code: string;
  state?: string;
}

/**
 * Start a temporary HTTP server on a random port to receive the OAuth callback.
 * Waits for the server to be listening before returning the assigned port.
 * Returns the port, a promise that resolves with the authorization code, and a cleanup function.
 */
async function startCallbackServer(): Promise<{
  port: number;
  codePromise: Promise<CallbackResult>;
  server: Server;
  close: () => void;
}> {
  let resolveCode: (result: CallbackResult) => void;
  let rejectCode: (err: Error) => void;
  const codePromise = new Promise<CallbackResult>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost`);
    const code = url.searchParams.get("code");
    const error = url.searchParams.get("error");
    const errorDescription = url.searchParams.get("error_description");
    const state = url.searchParams.get("state") ?? undefined;

    if (error) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><h2>Authorization failed</h2><p>${errorDescription ?? error}</p><p>You can close this tab.</p></body></html>`);
      rejectCode(new Error(`OAuth error: ${error} - ${errorDescription ?? ""}`));
      return;
    }

    if (code) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><h2>Authorization successful!</h2><p>You can close this tab and return to your terminal.</p></body></html>`);
      resolveCode({ code, state });
      return;
    }

    res.writeHead(400, { "Content-Type": "text/plain" });
    res.end("Missing authorization code");
  });

  // Listen on a random available port and wait for it to be ready
  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  if (port === 0) {
    server.close();
    throw new Error("Failed to bind callback server to a port");
  }

  // Timeout after 5 minutes
  const timeout = setTimeout(() => {
    rejectCode(new Error("OAuth callback timed out after 5 minutes"));
    server.close();
  }, 5 * 60 * 1000);

  const close = () => {
    clearTimeout(timeout);
    server.close();
  };

  return { port, codePromise, server, close };
}

// ── OAuth config ────────────────────────────────────────────────

export interface OAuthServerConfig {
  clientId: string;
  clientSecret?: string;
  scope?: string;
}

// ── PiOAuthClientProvider ───────────────────────────────────────

/**
 * Full OAuthClientProvider implementation for pi-mcp-adapter.
 *
 * Supports the browser-based authorization code flow with PKCE:
 * 1. Opens browser to authorization endpoint
 * 2. Listens on localhost for the callback with the auth code
 * 3. Exchanges the code for tokens (via the SDK's auth machinery)
 * 4. Persists tokens to disk for reuse across sessions
 * 5. Supports token refresh via refresh_token
 */
export class PiOAuthClientProvider implements OAuthClientProvider {
  private serverName: string;
  private config: OAuthServerConfig;
  private callbackPort: number = 0;
  private callbackClose: (() => void) | null = null;
  private _codePromise: Promise<CallbackResult> | null = null;
  private _redirectUrl: URL | undefined;
  private _state: string;
  private onStatusChange?: (status: string) => void;

  constructor(
    serverName: string,
    config: OAuthServerConfig,
    opts?: { onStatusChange?: (status: string) => void }
  ) {
    this.serverName = serverName;
    this.config = config;
    this._state = randomBytes(16).toString("hex");
    this.onStatusChange = opts?.onStatusChange;
  }

  get redirectUrl(): URL | undefined {
    return this._redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    const redirectUri = this._redirectUrl?.toString() ?? "http://127.0.0.1:0/callback";
    return {
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: this.config.clientSecret ? "client_secret_post" : "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: `pi-mcp-${this.serverName}`,
      scope: this.config.scope,
    };
  }

  async state(): Promise<string> {
    return this._state;
  }

  clientInformation(): OAuthClientInformationMixed | undefined {
    // First check persisted dynamic registration info
    const saved = loadClientInfo(this.serverName);
    if (saved) return saved;

    // Use static client_id from config
    if (this.config.clientId) {
      const info: OAuthClientInformationMixed = {
        client_id: this.config.clientId,
      };
      if (this.config.clientSecret) {
        (info as any).client_secret = this.config.clientSecret;
      }
      return info;
    }
    return undefined;
  }

  saveClientInformation(info: OAuthClientInformationMixed): void {
    saveClientInfo(this.serverName, info);
  }

  tokens(): OAuthTokens | undefined {
    return loadTokensFromFile(this.serverName);
  }

  saveTokens(tokens: OAuthTokens): void {
    saveTokensToFile(this.serverName, tokens);
    this.onStatusChange?.("authenticated");
  }

  /**
   * Start the localhost callback server and open the browser to the authorization URL.
   * Called by the MCP SDK's auth machinery when it needs user authorization.
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Start the callback server if not already running
    if (!this.callbackClose) {
      const cb = await startCallbackServer();
      this.callbackPort = cb.port;
      this.callbackClose = cb.close;
      this._codePromise = cb.codePromise;
      this._redirectUrl = new URL(`http://127.0.0.1:${cb.port}/callback`);
    }

    // Add our redirect_uri to the authorization URL if not already present
    if (!authorizationUrl.searchParams.has("redirect_uri")) {
      authorizationUrl.searchParams.set("redirect_uri", this._redirectUrl!.toString());
    }

    this.onStatusChange?.("waiting-for-browser");

    // Open browser
    const urlStr = authorizationUrl.toString();
    console.log(`MCP OAuth: Opening browser for ${this.serverName}...`);
    console.log(`MCP OAuth: If browser doesn't open, visit: ${urlStr}`);

    try {
      const { exec } = await import("node:child_process");
      const platform = process.platform;
      if (platform === "darwin") {
        exec(`open "${urlStr}"`);
      } else if (platform === "linux") {
        exec(`xdg-open "${urlStr}"`);
      } else if (platform === "win32") {
        exec(`start "" "${urlStr}"`);
      }
    } catch {
      console.log(`MCP OAuth: Could not open browser automatically.`);
    }
  }

  saveCodeVerifier(codeVerifier: string): void {
    saveCodeVerifierToFile(this.serverName, codeVerifier);
  }

  codeVerifier(): string {
    return loadCodeVerifierFromFile(this.serverName);
  }

  invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier"): void {
    const dir = getOAuthDir(this.serverName);
    try {
      if (scope === "all" || scope === "tokens") {
        const p = getTokensPath(this.serverName);
        if (existsSync(p)) {
          const { unlinkSync } = require("node:fs");
          unlinkSync(p);
        }
      }
      if (scope === "all" || scope === "client") {
        const p = getClientInfoPath(this.serverName);
        if (existsSync(p)) {
          const { unlinkSync } = require("node:fs");
          unlinkSync(p);
        }
      }
      if (scope === "all" || scope === "verifier") {
        const p = getCodeVerifierPath(this.serverName);
        if (existsSync(p)) {
          const { unlinkSync } = require("node:fs");
          unlinkSync(p);
        }
      }
    } catch {
      // ignore cleanup errors
    }
  }

  /**
   * Wait for the authorization callback and return the code.
   * This is used externally to drive the finishAuth() flow.
   */
  async waitForAuthorizationCode(): Promise<string> {
    if (!this._codePromise) {
      throw new Error("No callback server running. Call redirectToAuthorization first.");
    }
    try {
      const result = await this._codePromise;
      return result.code;
    } finally {
      this.cleanup();
    }
  }

  /**
   * Prepare the callback server before connecting.
   * Must be called before the transport connect() so that
   * redirectUrl is available when the SDK builds the auth request.
   */
  async prepareCallbackServer(): Promise<void> {
    if (this.callbackClose) return; // already running
    const cb = await startCallbackServer();
    this.callbackPort = cb.port;
    this.callbackClose = cb.close;
    this._codePromise = cb.codePromise;
    this._redirectUrl = new URL(`http://127.0.0.1:${cb.port}/callback`);
  }

  cleanup(): void {
    if (this.callbackClose) {
      this.callbackClose();
      this.callbackClose = null;
    }
    this._codePromise = null;
  }
}

// ── Standalone browser auth flow ────────────────────────────────

/**
 * Run a complete browser-based OAuth authorization code flow with PKCE.
 *
 * This is used by the /mcp-auth command and by server-manager when
 * connecting to an OAuth server that has no valid tokens.
 *
 * Steps:
 * 1. Discover OAuth/OIDC metadata from the server
 * 2. Start localhost callback server
 * 3. Build authorization URL with PKCE challenge
 * 4. Open browser
 * 5. Wait for callback with auth code
 * 6. Exchange code for tokens
 * 7. Save tokens to disk
 *
 * Returns the tokens on success, or throws on failure.
 */
export async function runBrowserAuthFlow(
  serverName: string,
  serverUrl: string,
  config: OAuthServerConfig,
  onStatus?: (message: string) => void,
): Promise<OAuthTokens> {
  const {
    discoverOAuthProtectedResourceMetadata,
    discoverAuthorizationServerMetadata,
    startAuthorization,
    exchangeAuthorization,
    registerClient,
  } = await import("@modelcontextprotocol/sdk/client/auth.js");

  onStatus?.("Discovering OAuth metadata...");

  // 1. Discover protected resource metadata (RFC 9728)
  let resourceMetadata;
  try {
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(serverUrl);
  } catch {
    // Server may not support resource metadata, continue without it
  }

  // 2. Determine authorization server URL
  const authServerUrl =
    resourceMetadata?.authorization_servers?.[0]?.toString() ?? serverUrl;

  // 3. Discover authorization server metadata
  const metadata = await discoverAuthorizationServerMetadata(authServerUrl);
  if (!metadata) {
    throw new Error(
      `Could not discover OAuth metadata for ${serverUrl}. ` +
      `Tried .well-known/oauth-authorization-server and .well-known/openid-configuration at ${authServerUrl}`
    );
  }

  onStatus?.(`Found authorization server: ${metadata.issuer}`);

  // 4. Start callback server
  const cb = await startCallbackServer();
  const redirectUrl = new URL(`http://127.0.0.1:${cb.port}/callback`);

  try {
    // 5. Build client information
    let clientInfo: OAuthClientInformationMixed;
    const savedClientInfo = loadClientInfo(serverName);

    if (savedClientInfo) {
      clientInfo = savedClientInfo;
    } else if (config.clientId) {
      clientInfo = {
        client_id: config.clientId,
        ...(config.clientSecret ? { client_secret: config.clientSecret } : {}),
      } as OAuthClientInformationMixed;
    } else if (metadata.registration_endpoint) {
      // Dynamic client registration
      onStatus?.("Registering client dynamically...");
      const clientMetadata: OAuthClientMetadata = {
        redirect_uris: [redirectUrl.toString()],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: `pi-mcp-${serverName}`,
        scope: config.scope,
      };
      const registered = await registerClient(authServerUrl, {
        metadata,
        clientMetadata,
      });
      saveClientInfo(serverName, registered);
      clientInfo = registered;
    } else {
      throw new Error(
        `No client_id configured for "${serverName}" and server does not support dynamic client registration. ` +
        `Add "clientId" to the server config in mcp.json.`
      );
    }

    // 6. Determine resource URL for RFC 8707 (needed in both authz and token requests)
    let resource: URL | undefined;
    if (resourceMetadata?.resource) {
      resource = new URL(resourceMetadata.resource);
    }

    // 7. Start authorization with PKCE
    onStatus?.("Starting authorization flow...");
    const { authorizationUrl, codeVerifier } = await startAuthorization(
      authServerUrl,
      {
        metadata,
        clientInformation: clientInfo,
        redirectUrl,
        scope: config.scope,
        resource,
      }
    );

    // 8. Open browser
    onStatus?.("Opening browser for authorization...");
    const urlStr = authorizationUrl.toString();
    console.log(`MCP OAuth: Visit: ${urlStr}`);

    try {
      const { exec } = await import("node:child_process");
      const platform = process.platform;
      if (platform === "darwin") {
        exec(`open "${urlStr}"`);
      } else if (platform === "linux") {
        exec(`xdg-open "${urlStr}"`);
      } else if (platform === "win32") {
        exec(`start "" "${urlStr}"`);
      }
    } catch {
      console.log("MCP OAuth: Could not open browser automatically.");
    }

    // 9. Wait for callback
    onStatus?.("Waiting for authorization callback...");
    const result = await cb.codePromise;

    // 10. Exchange code for tokens
    onStatus?.("Exchanging authorization code for tokens...");
    const tokens = await exchangeAuthorization(authServerUrl, {
      metadata,
      clientInformation: clientInfo,
      authorizationCode: result.code,
      codeVerifier,
      redirectUri: redirectUrl,
      resource,
    });

    // 11. Save tokens
    saveTokensToFile(serverName, tokens);
    onStatus?.("Authentication successful! Tokens saved.");

    return tokens;
  } finally {
    cb.close();
  }
}
