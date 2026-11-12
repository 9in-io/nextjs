import { NineError, WebAppAuth, verifyIdToken, type IdTokenClaims, type LoginTransaction, type WebLoginOptions, type WebTokenSet } from "@9in-io/sdk/server";
import { chunk, chunkNames, parseCookies, serializeCookie, unchunk, type CookieOptions } from "./cookies.js";
import { seal, unseal } from "./seal.js";
import type { Session, User } from "./types.js";

export { NineError } from "@9in-io/sdk/server";
export type { Session, User } from "./types.js";

/**
 * 9in sign-in for Next.js (App Router). Create it once, in `auth.ts`:
 *
 *   import { createNine } from "@9in-io/nextjs";
 *   export const nine = createNine(); // reads NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_SECRET, NINE_BASE_URL
 *
 * then mount the routes in `app/auth/[...nine]/route.ts` (`export const { GET, POST } = nine.handlers;`),
 * add `middleware.ts` (`export default nine.middleware({ protect: ["/dashboard"] });`) and call
 * `await nine.auth()` wherever you need the user.
 */

export interface NineConfig {
  /** Your tenant's issuer URL, e.g. https://acme.9in.io. Default: NINE_ISSUER. */
  issuer?: string;
  /** Default: NINE_CLIENT_ID. */
  clientId?: string;
  /** Default: NINE_CLIENT_SECRET. Leave out for a public application (PKCE only). */
  clientSecret?: string;
  /**
   * Encrypts the session and sign-in cookies: at least 32 characters (`openssl rand -base64 32`).
   * Default: NINE_SECRET. Pass several to rotate: the first encrypts, all of them decrypt.
   */
  secret?: string | string[];
  /**
   * Your app's URL, e.g. https://app.example.com (include Next's `basePath` if you use one).
   * Default: NINE_BASE_URL, else the URL of each request.
   */
  baseUrl?: string;
  /** Where the routes are mounted. Default "/auth": /auth/login, /auth/signup, /auth/callback, /auth/logout, /auth/session. */
  basePath?: string;
  /** Default "openid profile email offline_access" (offline_access gives a refresh token). */
  scope?: string;
  /** An API identifier, to get access tokens for that API. Default: NINE_AUDIENCE. */
  audience?: string;
  /** Default "nine_session". */
  cookieName?: string;
  /** Seconds a session lasts without being used. Default 30 days; each token refresh starts it again. */
  sessionMaxAge?: number;
  /** Seconds before expiry when the access token is refreshed. Default 60. */
  refreshLeeway?: number;
  /** Where users land after sign-in when no `returnTo` was given. Default "/". */
  afterSignInPath?: string;
  /** Where users land after sign-out (must be an allowed logout URL of the application). Default "/". */
  afterSignOutPath?: string;
  /** Your response for a failed sign-in (`access_denied` when the user cancels, say). Default: a plain-text 400 page. */
  onError?: (error: NineError, request: Request) => Response | Promise<Response>;
  /** Only for tenants that sign with a shared (HMAC) key. */
  idTokenSecret?: string;
  fetch?: typeof fetch;
  /** Allows http:// issuers other than localhost (never in production). */
  allowInsecureIssuer?: boolean;
}

export interface MiddlewareOptions {
  /**
   * Paths that need a signed-in user. "/dashboard" covers /dashboard and everything under it;
   * "/" covers every page. Also takes RegExps, or a function of the request. Signed-out
   * visitors are sent to the sign-in page (API requests get a 401 instead).
   */
  protect?: (string | RegExp)[] | ((request: Request) => boolean);
}

export interface AccessTokenOptions {
  /** Refresh even when the current token is still valid. */
  forceRefresh?: boolean;
}

export type RouteHandler = (request: Request) => Promise<Response>;

export interface Nine {
  /** `export const { GET, POST } = nine.handlers;` in `app/auth/[...nine]/route.ts`. */
  handlers: { GET: RouteHandler; POST: RouteHandler };
  /**
   * The signed-in user, or null. Works in Server Components, Route Handlers, Server Actions
   * (it reads the cookies with `next/headers`) and anywhere you have the request.
   */
  auth(request?: Request): Promise<Session | null>;
  /**
   * A valid access token for your API. In Route Handlers and Server Actions it is refreshed
   * when needed. Server Components can't save cookies, so there it is never refreshed: the
   * middleware keeps it fresh before the page renders.
   */
  getAccessToken(options?: AccessTokenOptions): Promise<string>;
  /** `export default nine.middleware({ protect: [...] })` in `middleware.ts`: refreshes tokens and protects paths. */
  middleware(options?: MiddlewareOptions): RouteHandler;
}

/** What the session cookie holds (encrypted). */
interface StoredSession {
  v: 1;
  user: User;
  accessToken: string;
  refreshToken: string | null;
  /** Access token expiry, ms. */
  expiresAt: number;
  scope: string;
  /** Session expiry, ms (also the cookie's Max-Age). */
  exp: number;
}

interface Resolved {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  secrets: string[];
  baseUrl?: string;
  basePath: string;
  cookieName: string;
  maxAge: number;
  leeway: number;
  afterSignInPath: string;
  afterSignOutPath: string;
}

const DEFAULT_SCOPE = "openid profile email offline_access";
/** Claims about the token rather than the user. */
const TOKEN_CLAIMS = new Set(["iss", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash", "azp", "jti", "sid"]);
const TRANSACTION_MAX_AGE = 15 * 60;
const MAX_TRANSACTIONS = 5;
/** How long a refresh result is reused for requests that still carry the old refresh token. */
const REFRESH_REUSE_MS = 30_000;
const ACTIONS = new Set(["login", "signup", "callback", "logout", "session"]);
const PROMPTS = new Set(["login", "consent", "none", "select_account", "create"]);

function env(name: string): string | undefined {
  try {
    // Read through globalThis so the package needs no Node.js types (it also runs on the Edge runtime).
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    return proc?.env?.[name] || undefined;
  } catch {
    return undefined;
  }
}

const noStore = () => new Headers({ "Cache-Control": "no-store" });

function redirect(location: string, headers: Headers, status = 302): Response {
  headers.set("Location", location);
  return new Response(null, { status, headers });
}

/** A path on our origin, or undefined (no open redirects). */
function safePath(value: string | null | undefined, origin: string): string | undefined {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return undefined;
  try {
    const url = new URL(value, origin);
    return url.origin === origin ? url.pathname + url.search + url.hash : undefined;
  } catch {
    return undefined;
  }
}

/** Link prefetches must not sign anyone in or out. */
function isPrefetch(request: Request): boolean {
  const h = request.headers;
  return h.get("next-router-prefetch") === "1" || /prefetch/i.test(h.get("purpose") ?? "") || /prefetch/i.test(h.get("sec-purpose") ?? "");
}

/** A page navigation (redirect to sign-in) rather than an API call (401). */
function wantsPage(request: Request): boolean {
  const h = request.headers;
  return h.get("rsc") === "1" || h.get("sec-fetch-mode") === "navigate" || (h.get("accept") ?? "").includes("text/html");
}

function pickUser(claims: IdTokenClaims | Record<string, unknown>): User {
  const user: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(claims)) if (!TOKEN_CLAIMS.has(key)) user[key] = value;
  return user as User;
}

function isDeadSession(error: unknown): boolean {
  return error instanceof NineError && error.code === "invalid_grant";
}

export function createNine(config: NineConfig = {}): Nine {
  let resolved: Resolved | null = null;
  const clients = new Map<string, WebAppAuth>();
  const refreshes = new Map<string, { promise: Promise<WebTokenSet>; until: number }>();

  /** Read on first use, so a missing variable fails at request time, not at build time. */
  function settings(): Resolved {
    if (resolved) return resolved;
    const issuer = config.issuer ?? env("NINE_ISSUER");
    const clientId = config.clientId ?? env("NINE_CLIENT_ID");
    const secret = config.secret ?? env("NINE_SECRET");
    const secrets = (Array.isArray(secret) ? secret : secret ? [secret] : []).filter(Boolean);
    if (!issuer) throw new NineError("invalid_options", "issuer is missing: set NINE_ISSUER or pass `issuer` to createNine()");
    if (!clientId) throw new NineError("invalid_options", "clientId is missing: set NINE_CLIENT_ID or pass `clientId` to createNine()");
    if (!secrets.length) throw new NineError("invalid_options", "secret is missing: set NINE_SECRET (32+ characters, e.g. `openssl rand -base64 32`)");
    if (secrets.some((s) => s.length < 32)) throw new NineError("invalid_options", "secret must be at least 32 characters (e.g. `openssl rand -base64 32`)");
    const basePath = `/${(config.basePath ?? "/auth").replace(/^\/+|\/+$/g, "")}`;
    const baseUrl = (config.baseUrl ?? env("NINE_BASE_URL"))?.replace(/\/+$/, "");
    if (baseUrl && !/^https?:\/\//.test(baseUrl)) throw new NineError("invalid_options", "baseUrl must be an absolute URL, e.g. https://app.example.com");
    const clientSecret = config.clientSecret ?? env("NINE_CLIENT_SECRET");
    resolved = {
      issuer,
      clientId,
      ...(clientSecret ? { clientSecret } : {}),
      secrets,
      ...(baseUrl ? { baseUrl } : {}),
      basePath: basePath === "/" ? "/auth" : basePath,
      cookieName: config.cookieName ?? "nine_session",
      maxAge: config.sessionMaxAge ?? 30 * 24 * 3600,
      leeway: (config.refreshLeeway ?? 60) * 1000,
      afterSignInPath: config.afterSignInPath ?? "/",
      afterSignOutPath: config.afterSignOutPath ?? "/",
    };
    return resolved;
  }

  /** Our app's URL: the configured one, or the request's origin. */
  function appBase(request?: Request): string {
    const s = settings();
    if (s.baseUrl) return s.baseUrl;
    if (request) return new URL(request.url).origin;
    throw new NineError("invalid_options", "baseUrl is missing: set NINE_BASE_URL");
  }

  function client(redirectUri: string): WebAppAuth {
    let c = clients.get(redirectUri);
    if (!c) {
      const s = settings();
      const audience = config.audience ?? env("NINE_AUDIENCE");
      c = new WebAppAuth({
        issuer: s.issuer,
        clientId: s.clientId,
        redirectUri,
        scope: config.scope ?? DEFAULT_SCOPE,
        ...(s.clientSecret ? { clientSecret: s.clientSecret } : {}),
        ...(audience ? { audience } : {}),
        ...(config.idTokenSecret ? { idTokenSecret: config.idTokenSecret } : {}),
        ...(config.fetch ? { fetch: config.fetch } : {}),
        ...(config.allowInsecureIssuer ? { allowInsecureIssuer: true } : {}),
      });
      clients.set(redirectUri, c);
    }
    return c;
  }

  /** For refresh, revoke and logout, which don't use the redirect URI. */
  const anyClient = () => clients.values().next().value ?? client(`${settings().baseUrl ?? "http://localhost"}${settings().basePath}/callback`);

  const secure = (base: string) => base.startsWith("https:");
  const txCookie = (state: string) => `${settings().cookieName}_tx_${state}`;

  /** Which of our routes a path is: "/auth/login" (or "/prefix/auth/login") → { action, path: "/auth" }. */
  function route(pathname: string): { action: string; path: string } | null {
    const { basePath } = settings();
    const clean = pathname.replace(/\/+$/, "");
    const index = clean.lastIndexOf(`${basePath}/`);
    if (index < 0) return null;
    const action = clean.slice(index + basePath.length + 1);
    return ACTIONS.has(action) ? { action, path: clean.slice(0, index) + basePath } : null;
  }

  // ---------------------------------------------------------------------------
  // Session cookie

  async function readSession(cookies: Map<string, string>): Promise<StoredSession | null> {
    const s = settings();
    const raw = unchunk(s.cookieName, cookies);
    if (!raw) return null;
    const session = await unseal<StoredSession>(raw, s.secrets, "session");
    if (!session || session.v !== 1 || typeof session.exp !== "number" || session.exp <= Date.now() || !session.user?.sub) return null;
    return session;
  }

  /** Seals the session; returns the cookies to set and which existing ones to delete. */
  async function sessionCookies(session: StoredSession | null, existing: Iterable<string>): Promise<{ set: [string, string][]; remove: string[] }> {
    const s = settings();
    const set = session ? chunk(s.cookieName, await seal({ ...session, exp: Date.now() + s.maxAge * 1000 }, s.secrets, "session")) : [];
    const keep = new Set(set.map(([name]) => name));
    return { set, remove: chunkNames(s.cookieName, existing).filter((name) => !keep.has(name)) };
  }

  function setCookieHeaders(cookies: { set: [string, string][]; remove: string[] }, base: string): string[] {
    const options: CookieOptions = { path: "/", secure: secure(base), maxAge: settings().maxAge };
    return [
      ...cookies.set.map(([name, value]) => serializeCookie(name, value, options)),
      ...cookies.remove.map((name) => serializeCookie(name, "", { ...options, maxAge: 0 })),
    ];
  }

  function appendSessionCookies(headers: Headers, cookies: { set: [string, string][]; remove: string[] }, base: string) {
    for (const header of setCookieHeaders(cookies, base)) headers.append("Set-Cookie", header);
  }

  function newSession(tokens: WebTokenSet, claims: IdTokenClaims): StoredSession {
    return { v: 1, user: pickUser(claims), accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, expiresAt: tokens.expiresAt, scope: tokens.scope, exp: 0 };
  }

  /**
   * Refreshes once per refresh token: concurrent requests share one call, and requests that
   * still carry the old refresh token shortly afterwards get the same result, because 9in
   * rotates refresh tokens and treats a second use as theft.
   */
  function refreshOnce(refreshToken: string): Promise<WebTokenSet> {
    const now = Date.now();
    for (const [token, entry] of refreshes) if (entry.until && entry.until < now) refreshes.delete(token);
    const hit = refreshes.get(refreshToken);
    if (hit) return hit.promise;
    const entry = { promise: anyClient().refresh(refreshToken), until: 0 };
    refreshes.set(refreshToken, entry);
    entry.promise.then(
      () => (entry.until = Date.now() + REFRESH_REUSE_MS),
      () => refreshes.delete(refreshToken),
    );
    return entry.promise;
  }

  async function refreshed(session: StoredSession): Promise<StoredSession> {
    const tokens = await refreshOnce(session.refreshToken!);
    let user = session.user;
    if (tokens.idToken) {
      // Keep the profile current when 9in sends a new ID token (same user only).
      try {
        const s = settings();
        const claims = await verifyIdToken(tokens.idToken, {
          issuer: s.issuer,
          clientId: s.clientId,
          ...(config.idTokenSecret ? { secret: config.idTokenSecret } : {}),
          ...(config.fetch ? { fetch: config.fetch } : {}),
          ...(config.allowInsecureIssuer ? { allowInsecureIssuer: true } : {}),
        });
        if (claims.sub === session.user.sub) user = pickUser(claims);
      } catch {
        // keep the profile we have
      }
    }
    return { ...session, user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken ?? session.refreshToken, expiresAt: tokens.expiresAt, scope: tokens.scope || session.scope };
  }

  const needsRefresh = (session: StoredSession) => session.expiresAt - settings().leeway <= Date.now();

  // ---------------------------------------------------------------------------
  // Routes

  async function login(request: Request, url: URL, path: string, screen?: "signup"): Promise<Response> {
    const headers = noStore();
    if (isPrefetch(request)) return new Response(null, { status: 204, headers });
    const s = settings();
    const base = appBase(request);
    const origin = new URL(base).origin;
    const q = url.searchParams;
    const prompt = q.get("prompt");
    const options: WebLoginOptions = {
      returnTo: safePath(q.get("returnTo"), origin) ?? s.afterSignInPath,
      ...(screen || q.get("screen") === "signup" ? { screen: "signup" as const } : {}),
      ...(prompt && PROMPTS.has(prompt) ? { prompt: prompt as WebLoginOptions["prompt"] } : {}),
      ...(q.get("login_hint") ? { loginHint: q.get("login_hint")! } : {}),
      ...(q.get("locale") || q.get("ui_locales") ? { locale: (q.get("locale") ?? q.get("ui_locales"))! } : {}),
    };
    const { url: authorize, transaction } = await client(`${base}${s.basePath}/callback`).createLogin(options);
    const cookieOptions: CookieOptions = { path, secure: secure(base), maxAge: TRANSACTION_MAX_AGE };
    // Abandoned sign-ins leave cookies behind until they expire; don't let them pile up.
    const pending = [...parseCookies(request.headers.get("cookie")).keys()].filter((name) => name.startsWith(txCookie("")));
    if (pending.length >= MAX_TRANSACTIONS) for (const name of pending) headers.append("Set-Cookie", serializeCookie(name, "", { ...cookieOptions, maxAge: 0 }));
    headers.append("Set-Cookie", serializeCookie(txCookie(transaction.state), await seal(transaction, s.secrets, "transaction"), cookieOptions));
    return redirect(authorize, headers);
  }

  async function callback(request: Request, url: URL, path: string): Promise<Response> {
    const s = settings();
    const base = appBase(request);
    const headers = noStore();
    const cookies = parseCookies(request.headers.get("cookie"));
    const state = url.searchParams.get("state");
    const name = state && /^[A-Za-z0-9_-]{1,128}$/.test(state) ? txCookie(state) : null;
    const raw = name ? cookies.get(name) : undefined;
    const clearTx = name && raw ? serializeCookie(name, "", { path, secure: secure(base), maxAge: 0 }) : null;
    if (clearTx) headers.append("Set-Cookie", clearTx);
    try {
      const transaction = raw ? await unseal<LoginTransaction>(raw, s.secrets, "transaction") : null;
      const { tokens, claims, returnTo } = await client(`${base}${s.basePath}/callback`).handleCallback(request.url, transaction);
      appendSessionCookies(headers, await sessionCookies(newSession(tokens, claims), cookies.keys()), base);
      return redirect(new URL(returnTo ?? s.afterSignInPath, base).toString(), headers);
    } catch (e) {
      const error = e instanceof NineError ? e : new NineError("callback_failed", e instanceof Error ? e.message : String(e));
      if (config.onError) {
        const res = await config.onError(error, request);
        const merged = new Headers(res.headers);
        if (clearTx) merged.append("Set-Cookie", clearTx);
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers: merged });
      }
      headers.set("Content-Type", "text/plain; charset=utf-8");
      headers.set("X-Content-Type-Options", "nosniff");
      return new Response(`Sign-in failed: ${error.message}\n\nStart again: ${base}${s.basePath}/login\n`, { status: 400, headers });
    }
  }

  async function logout(request: Request, url: URL): Promise<Response> {
    const headers = noStore();
    if (request.method === "GET" && isPrefetch(request)) return new Response(null, { status: 204, headers });
    const s = settings();
    const base = appBase(request);
    const params = new URLSearchParams(url.search);
    if (request.method === "POST" && (request.headers.get("content-type") ?? "").includes("application/x-www-form-urlencoded")) {
      for (const [key, value] of new URLSearchParams(await request.text())) params.set(key, value);
    }
    const cookies = parseCookies(request.headers.get("cookie"));
    const session = await readSession(cookies);
    appendSessionCookies(headers, await sessionCookies(null, cookies.keys()), base);
    if (session?.refreshToken) await anyClient().revoke(session.refreshToken).catch(() => undefined);
    const target = new URL(safePath(params.get("returnTo"), new URL(base).origin) ?? s.afterSignOutPath, base).toString();
    const status = request.method === "POST" ? 303 : 302;
    if (params.get("local") === "1" || params.get("local") === "true") return redirect(target, headers, status);
    return redirect(await anyClient().logoutUrl({ postLogoutRedirectUri: target }), headers, status);
  }

  async function sessionRoute(request: Request): Promise<Response> {
    const session = await readSession(parseCookies(request.headers.get("cookie")));
    const headers = noStore();
    headers.set("Content-Type", "application/json");
    return new Response(JSON.stringify({ user: session?.user ?? null }), { headers });
  }

  const notFound = () => new Response("Not found", { status: 404, headers: noStore() });

  const handlers = {
    async GET(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const r = route(url.pathname);
      switch (r?.action) {
        case "login":
          return login(request, url, r.path);
        case "signup":
          return login(request, url, r.path, "signup");
        case "callback":
          return callback(request, url, r.path);
        case "logout":
          return logout(request, url);
        case "session":
          return sessionRoute(request);
        default:
          return notFound();
      }
    },
    async POST(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const r = route(url.pathname);
      if (r?.action === "logout") return logout(request, url);
      return r ? new Response("Method not allowed", { status: 405, headers: { Allow: "GET", "Cache-Control": "no-store" } }) : notFound();
    },
  };

  // ---------------------------------------------------------------------------
  // Server Components, Route Handlers, Server Actions

  async function cookieStore() {
    const { cookies } = await import("next/headers.js");
    return await cookies();
  }

  async function auth(request?: Request): Promise<Session | null> {
    const cookies = request ? parseCookies(request.headers.get("cookie")) : new Map((await cookieStore()).getAll().map((c) => [c.name, c.value] as const));
    const session = await readSession(cookies);
    return session ? { user: session.user } : null;
  }

  async function getAccessToken(options: AccessTokenOptions = {}): Promise<string> {
    const s = settings();
    const store = await cookieStore();
    const cookies = new Map(store.getAll().map((c) => [c.name, c.value] as const));
    const session = await readSession(cookies);
    if (!session) throw new NineError("login_required", "not signed in", 401);
    if (!options.forceRefresh && !needsRefresh(session)) return session.accessToken;
    const expired = session.expiresAt <= Date.now();
    if (!session.refreshToken) {
      if (!expired && !options.forceRefresh) return session.accessToken;
      throw new NineError("login_required", "the access token expired and the session has no refresh token (request the offline_access scope)", 401);
    }
    // 9in rotates the refresh token, so refresh only where the new one can be saved: Server
    // Components can't set cookies (setting one throws there).
    const cookieOptions = { httpOnly: true, sameSite: "lax", path: "/", secure: s.baseUrl ? secure(s.baseUrl) : env("NODE_ENV") === "production", maxAge: s.maxAge };
    try {
      for (const name of chunkNames(s.cookieName, cookies.keys())) store.set(name, cookies.get(name)!, cookieOptions);
    } catch {
      if (!expired && !options.forceRefresh) return session.accessToken;
      throw new NineError(
        "token_expired",
        "the access token expired and can't be refreshed in a Server Component (it can't save cookies): add nine.middleware(), which refreshes it before the page renders, or call getAccessToken() in a Route Handler or Server Action",
        401,
      );
    }
    let next: StoredSession | null;
    try {
      next = await refreshed(session);
    } catch (error) {
      if (!isDeadSession(error)) throw error;
      next = null;
    }
    const written = await sessionCookies(next, cookies.keys());
    for (const [name, value] of written.set) store.set(name, value, cookieOptions);
    for (const name of written.remove) store.set(name, "", { ...cookieOptions, maxAge: 0 });
    if (!next) throw new NineError("login_required", "the session ended; sign in again", 401);
    return next.accessToken;
  }

  // ---------------------------------------------------------------------------
  // Middleware

  function isProtected(request: Request, pathname: string, protect: MiddlewareOptions["protect"]): boolean {
    if (!protect) return false;
    if (typeof protect === "function") return protect(request);
    return protect.some((rule) => {
      if (rule instanceof RegExp) return rule.test(pathname);
      const prefix = rule.endsWith("/") ? rule : `${rule}/`;
      return pathname === rule || pathname.startsWith(prefix);
    });
  }

  function middleware(options: MiddlewareOptions = {}): RouteHandler {
    return async (request: Request): Promise<Response> => {
      const { NextResponse } = await import("next/server.js");
      const url = new URL(request.url);
      if (route(url.pathname)) return NextResponse.next();
      const s = settings();
      const base = appBase(request);
      const cookies = parseCookies(request.headers.get("cookie"));
      const names = chunkNames(s.cookieName, cookies.keys());
      let session = await readSession(cookies);
      let written: { set: [string, string][]; remove: string[] } | null = null;

      if (session?.refreshToken && needsRefresh(session)) {
        try {
          session = await refreshed(session);
          written = await sessionCookies(session, names);
        } catch (error) {
          // 9in unreachable: keep the session (the token may still work); a revoked one ends it.
          if (isDeadSession(error)) session = null;
        }
      }
      // An unreadable, expired or revoked session cookie is removed.
      if (!session && names.length) written = { set: [], remove: names };

      const setCookies = written ? setCookieHeaders(written, base) : [];
      const finish = (res: Response) => {
        for (const header of setCookies) res.headers.append("Set-Cookie", header);
        return res;
      };

      if (!session && isProtected(request, url.pathname, options.protect)) {
        if (!wantsPage(request)) {
          return finish(new Response(JSON.stringify({ error: "unauthorized", error_description: "sign in first" }), { status: 401, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }));
        }
        const login = new URL(`${base}${s.basePath}/login`);
        login.searchParams.set("returnTo", url.pathname + url.search);
        return finish(NextResponse.redirect(login));
      }

      if (!written) return NextResponse.next();
      // Pages rendered for this request read the new cookies, not the ones the browser sent.
      const forward = new Map(cookies);
      for (const name of names) forward.delete(name);
      for (const [name, value] of written.set) forward.set(name, value);
      const headers = new Headers(request.headers);
      if (forward.size) headers.set("cookie", [...forward].map(([name, value]) => `${name}=${value}`).join("; "));
      else headers.delete("cookie");
      return finish(NextResponse.next({ request: { headers } }));
    };
  }

  return { handlers, auth, getAccessToken, middleware };
}
