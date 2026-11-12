import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createNine, NineError } from "../src/index";
import { CHUNK_SIZE } from "../src/cookies";
import { jar, mode, writes } from "./stubs/next-headers";

const SECRET = "a-test-secret-that-is-long-enough-0123456789";
const APP = "https://app.acme.test";

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64json = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
const sha256 = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));

/** A mock 9in tenant: discovery, JWKS, token endpoint with rotating refresh tokens, revocation. */
async function tenant(options: { profile?: Record<string, unknown> } = {}) {
  const issuer = `https://acme.9in.test/w${Math.random().toString(36).slice(2)}`;
  const pair = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const now = () => Math.floor(Date.now() / 1000);
  const idToken = async (claims: Record<string, unknown>) => {
    const input = `${b64json({ alg: "RS256", typ: "JWT", kid: "k1" })}.${b64json({ iss: issuer, aud: "app_1", sub: "usr_1", iat: now(), exp: now() + 300, ...claims })}`;
    return `${input}.${b64url(new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input))))}`;
  };
  const state = { nonce: "", challenge: "", refreshCalls: 0, rotation: 1, revoked: [] as string[], used: new Set<string>(), dead: false };
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    const url = new URL(req.url);
    const at = `${req.method} ${url.pathname.replace(new URL(issuer).pathname, "")}`;
    if (at === "GET /.well-known/openid-configuration") {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/oauth/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${issuer}/oauth/logout`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
      });
    }
    if (at === "GET /.well-known/jwks.json") return Response.json({ keys: [jwk] });
    if (at === "POST /oauth/revoke") {
      state.revoked.push(new URLSearchParams(await req.text()).get("token")!);
      return new Response(null, { status: 200 });
    }
    if (at === "POST /oauth/token") {
      const form = new URLSearchParams(await req.text());
      if (req.headers.get("authorization") !== `Basic ${btoa("app_1:s3cret")}`) return Response.json({ error: "invalid_client" }, { status: 401 });
      if (form.get("grant_type") === "authorization_code") {
        if (form.get("code") !== "code-1" || b64url(await sha256(form.get("code_verifier")!)) !== state.challenge) return Response.json({ error: "invalid_grant" }, { status: 400 });
        return Response.json({ access_token: "at-1", refresh_token: "rt-1", expires_in: 300, scope: "openid email offline_access", token_type: "Bearer", id_token: await idToken({ nonce: state.nonce, email: "jane@acme.test", name: "Jane", amr: ["pwd"], ...options.profile }) });
      }
      if (form.get("grant_type") === "refresh_token") {
        state.refreshCalls++;
        const token = form.get("refresh_token")!;
        // Like 9in: a refresh token works once; a second use is reuse (and kills the family).
        if (state.dead || state.used.has(token) || token !== `rt-${state.rotation}`) {
          state.dead = true;
          return Response.json({ error: "invalid_grant", error_description: "refresh token reuse" }, { status: 400 });
        }
        state.used.add(token);
        state.rotation++;
        return Response.json({ access_token: `at-${state.rotation}`, refresh_token: `rt-${state.rotation}`, expires_in: 300, token_type: "Bearer", id_token: await idToken({ email: "jane@acme.test", name: "Jane Doe" }) });
      }
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
  const authorize = (location: string) => {
    const params = new URL(location).searchParams;
    state.nonce = params.get("nonce")!;
    state.challenge = params.get("code_challenge")!;
    return params;
  };
  return { issuer, fetcher, state, authorize };
}

const setCookies = (res: Response) => res.headers.getSetCookie();
/** Applies a response's Set-Cookie headers to a cookie map, like a browser. */
function store(cookies: Map<string, string>, res: Response) {
  for (const line of setCookies(res)) {
    const [pair] = line.split(";");
    const index = pair!.indexOf("=");
    const name = pair!.slice(0, index);
    const value = pair!.slice(index + 1);
    if (/Max-Age=0/.test(line)) cookies.delete(name);
    else cookies.set(name, value);
  }
  return cookies;
}
const header = (cookies: Map<string, string>) => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
const get = (path: string, cookies = new Map<string, string>(), headers: Record<string, string> = {}) => new Request(`${APP}${path}`, { headers: { cookie: header(cookies), ...headers } });

async function signIn(t: Awaited<ReturnType<typeof tenant>>, nine: ReturnType<typeof createNine>, returnTo = "/dashboard") {
  const cookies = new Map<string, string>();
  const login = await nine.handlers.GET(get(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`));
  store(cookies, login);
  const params = t.authorize(login.headers.get("location")!);
  const callback = await nine.handlers.GET(get(`/auth/callback?code=code-1&state=${params.get("state")}&iss=${encodeURIComponent(t.issuer)}`, cookies));
  store(cookies, callback);
  return { cookies, login, callback, params };
}

function setup(t: Awaited<ReturnType<typeof tenant>>, extra: Parameters<typeof createNine>[0] = {}) {
  return createNine({ issuer: t.issuer, clientId: "app_1", clientSecret: "s3cret", secret: SECRET, baseUrl: APP, fetch: t.fetcher, ...extra });
}

beforeEach(() => {
  jar.clear();
  writes.length = 0;
  mode.writable = true;
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("routes", () => {
  it("signs in: login redirect, encrypted transaction cookie, callback, session cookie", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies, login, callback, params } = await signIn(t, nine);

    expect(login.status).toBe(302);
    expect(params.get("client_id")).toBe("app_1");
    expect(params.get("redirect_uri")).toBe(`${APP}/auth/callback`);
    expect(params.get("code_challenge_method")).toBe("S256");
    const tx = setCookies(login).find((c) => c.startsWith("nine_session_tx_"))!;
    expect(tx).toMatch(/Path=\/auth; HttpOnly; SameSite=Lax; Max-Age=900; Secure/);
    expect(decodeURIComponent(tx)).not.toMatch(/verifier|nonce|dashboard/); // encrypted

    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe(`${APP}/dashboard`);
    expect(setCookies(callback).some((c) => c.startsWith("nine_session_tx_") && c.includes("Max-Age=0"))).toBe(true);
    expect(setCookies(callback).find((c) => c.startsWith("nine_session="))).toMatch(/Path=\/; HttpOnly; SameSite=Lax; Max-Age=2592000; Secure/);
    expect([...cookies.keys()]).toEqual(["nine_session"]);

    const session = await nine.handlers.GET(get("/auth/session", cookies));
    expect(session.headers.get("cache-control")).toBe("no-store");
    const body = (await session.json()) as { user: Record<string, unknown> };
    expect(body.user).toMatchObject({ sub: "usr_1", email: "jane@acme.test", name: "Jane", amr: ["pwd"] });
    for (const claim of ["iss", "aud", "exp", "iat", "nonce"]) expect(body.user).not.toHaveProperty(claim);
    expect(JSON.stringify(body)).not.toContain("at-1");
  });

  it("opens the registration page and passes sign-in options", async () => {
    const t = await tenant();
    const nine = setup(t);
    const res = await nine.handlers.GET(get("/auth/signup?locale=de&login_hint=jane%40acme.test&prompt=bogus"));
    const params = new URL(res.headers.get("location")!).searchParams;
    expect(params.get("prompt")).toBe("create");
    expect(params.get("ui_locales")).toBe("de");
    expect(params.get("login_hint")).toBe("jane@acme.test");
  });

  it("refuses open redirects and unknown routes", async () => {
    const t = await tenant();
    const nine = setup(t);
    for (const returnTo of ["//evil.test/x", "https://evil.test/", "/\\evil.test", "javascript:alert(1)"]) {
      const { callback } = await signIn(t, nine, returnTo);
      expect(callback.headers.get("location")).toBe(`${APP}/`);
    }
    expect((await nine.handlers.GET(get("/auth/nope"))).status).toBe(404);
    expect((await nine.handlers.POST(new Request(`${APP}/auth/login`, { method: "POST" }))).status).toBe(405);
  });

  it("fails the callback without the transaction, with a wrong state, or when the user cancels", async () => {
    const t = await tenant();
    const nine = setup(t);
    const login = await nine.handlers.GET(get("/auth/login"));
    const state = t.authorize(login.headers.get("location")!).get("state")!;
    const noCookie = await nine.handlers.GET(get(`/auth/callback?code=code-1&state=${state}`));
    expect(noCookie.status).toBe(400);
    expect(await noCookie.text()).toContain("invalid_state");
    const cookies = store(new Map(), login);
    const cancelled = await nine.handlers.GET(get(`/auth/callback?error=access_denied&state=${state}`, cookies));
    expect(cancelled.status).toBe(400);
    expect(cancelled.headers.get("content-type")).toContain("text/plain");
    expect(setCookies(cancelled).some((c) => c.includes("Max-Age=0"))).toBe(true);

    const custom = setup(t, { onError: (error) => Response.redirect(`${APP}/sign-in-failed?error=${error.code}`, 302) });
    const res = await custom.handlers.GET(get(`/auth/callback?error=access_denied&state=${state}`, cookies));
    expect(res.headers.get("location")).toBe(`${APP}/sign-in-failed?error=access_denied`);
    expect(setCookies(res).some((c) => c.startsWith("nine_session_tx_"))).toBe(true);
  });

  it("ignores tampered cookies and cookies sealed with another secret", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    const value = cookies.get("nine_session")!;
    const tampered = new Map([["nine_session", value.slice(0, -2) + (value.endsWith("A") ? "BB" : "AA")]]);
    expect(await nine.auth(get("/", tampered))).toBeNull();
    const other = setup(t, { secret: "another-secret-that-is-long-enough-987654321" });
    expect(await other.auth(get("/", cookies))).toBeNull();
    // Rotation: the new secret first, the old one still opens existing sessions.
    const rotated = setup(t, { secret: ["another-secret-that-is-long-enough-987654321", SECRET] });
    expect((await rotated.auth(get("/", cookies)))?.user.sub).toBe("usr_1");
  });

  it("splits a large session over several cookies", async () => {
    const t = await tenant({ profile: { bio: "x".repeat(CHUNK_SIZE * 1.5) } });
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    const names = [...cookies.keys()];
    expect(names.length).toBeGreaterThan(1);
    expect(names).toEqual(names.map((_, i) => `nine_session.${i}`));
    for (const value of cookies.values()) expect(value.length).toBeLessThanOrEqual(CHUNK_SIZE);
    expect((await nine.auth(get("/", cookies)))?.user.bio).toHaveLength(CHUNK_SIZE * 1.5);
    // Signing out removes every chunk.
    expect(store(cookies, await nine.handlers.GET(get("/auth/logout?local=1", cookies))).size).toBe(0);
  });

  it("signs out: clears the cookie, revokes the refresh token, ends the 9in session", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    const prefetch = await nine.handlers.GET(get("/auth/logout", cookies, { "next-router-prefetch": "1" }));
    expect(prefetch.status).toBe(204);
    expect(setCookies(prefetch)).toEqual([]);

    const res = await nine.handlers.GET(get("/auth/logout?returnTo=/bye", cookies));
    const location = new URL(res.headers.get("location")!);
    expect(location.pathname.endsWith("/oauth/logout")).toBe(true);
    expect(location.searchParams.get("client_id")).toBe("app_1");
    expect(location.searchParams.get("post_logout_redirect_uri")).toBe(`${APP}/bye`);
    expect(t.state.revoked).toEqual(["rt-1"]);
    expect(store(cookies, res).size).toBe(0);

    const { cookies: again } = await signIn(t, nine);
    const local = await nine.handlers.POST(new Request(`${APP}/auth/logout`, { method: "POST", headers: { cookie: header(again), "content-type": "application/x-www-form-urlencoded" }, body: "local=1" }));
    expect(local.status).toBe(303);
    expect(local.headers.get("location")).toBe(`${APP}/`);
  });

  it("needs a strong secret", async () => {
    const t = await tenant();
    const nine = setup(t, { secret: "short" });
    await expect(nine.handlers.GET(get("/auth/login"))).rejects.toThrow(/at least 32 characters/);
  });
});

describe("auth() and getAccessToken()", () => {
  it("reads the session from next/headers and returns the access token", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    for (const [k, v] of cookies) jar.set(k, v);
    expect((await nine.auth())?.user).toMatchObject({ sub: "usr_1", email: "jane@acme.test" });
    expect(await nine.getAccessToken()).toBe("at-1");
    jar.clear();
    expect(await nine.auth()).toBeNull();
    await expect(nine.getAccessToken()).rejects.toMatchObject({ code: "login_required" });
  });

  it("refreshes in Route Handlers and Server Actions, and saves the rotated refresh token", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    for (const [k, v] of cookies) jar.set(k, v);
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 290_000 });
    expect(await nine.getAccessToken()).toBe("at-2");
    expect(t.state.refreshCalls).toBe(1);
    expect((await nine.auth())?.user.name).toBe("Jane Doe"); // profile from the new ID token
    expect(await nine.getAccessToken()).toBe("at-2"); // saved: no second refresh
    expect(t.state.refreshCalls).toBe(1);
  });

  it("never refreshes in Server Components (they can't save the rotated token)", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    for (const [k, v] of cookies) jar.set(k, v);
    mode.writable = false;
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 290_000 });
    expect(await nine.getAccessToken()).toBe("at-1"); // about to expire, still valid
    vi.setSystemTime(Date.now() + 20_000);
    await expect(nine.getAccessToken()).rejects.toMatchObject({ code: "token_expired" });
    expect(t.state.refreshCalls).toBe(0);
  });

  it("ends the session when the refresh token was revoked", async () => {
    const t = await tenant();
    const nine = setup(t);
    const { cookies } = await signIn(t, nine);
    for (const [k, v] of cookies) jar.set(k, v);
    t.state.dead = true;
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 400_000 });
    const error = await nine.getAccessToken().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NineError);
    expect(error).toMatchObject({ code: "login_required" });
    expect(jar.size).toBe(0);
  });
});

describe("middleware", () => {
  it("refreshes before the page renders, once for concurrent requests, and forwards the new cookie", async () => {
    const t = await tenant();
    const nine = setup(t);
    const middleware = nine.middleware();
    const { cookies } = await signIn(t, nine);

    const fresh = await middleware(get("/dashboard", cookies));
    expect(fresh.headers.get("x-middleware-next")).toBe("1");
    expect(setCookies(fresh)).toEqual([]);

    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 290_000 });
    // A page and its prefetches arrive together with the same (old) cookie.
    const [a, b, c] = await Promise.all([middleware(get("/dashboard", cookies)), middleware(get("/settings", cookies)), middleware(get("/", cookies))]);
    expect(t.state.refreshCalls).toBe(1);
    expect(t.state.dead).toBe(false);
    for (const res of [a!, b!, c!]) {
      expect(setCookies(res).some((line) => line.startsWith("nine_session="))).toBe(true);
      // The page rendered for this request sees the new session (NextResponse.next({ request })).
      expect(res.headers.get("x-middleware-override-headers")).toContain("cookie");
    }
    const forwarded = new Map([["nine_session", a!.headers.get("x-middleware-request-cookie")!.replace(/^nine_session=/, "")]]);
    jar.clear();
    for (const [k, v] of forwarded) jar.set(k, v);
    mode.writable = false;
    expect(await nine.getAccessToken()).toBe("at-2");

    // A late request that still carries the old cookie gets the same tokens, not a reuse error.
    const late = await middleware(get("/late", cookies));
    expect(t.state.refreshCalls).toBe(1);
    expect(setCookies(late).some((line) => line.startsWith("nine_session="))).toBe(true);
  });

  it("protects paths: pages go to sign-in, API calls get 401, auth routes pass", async () => {
    const t = await tenant();
    const nine = setup(t);
    const middleware = nine.middleware({ protect: ["/dashboard", /^\/api\/private/] });
    const page = await middleware(get("/dashboard/team?tab=2", new Map(), { accept: "text/html" }));
    expect(page.status).toBe(307);
    expect(page.headers.get("location")).toBe(`${APP}/auth/login?returnTo=${encodeURIComponent("/dashboard/team?tab=2")}`);
    const api = await middleware(get("/api/private/x", new Map(), { accept: "application/json" }));
    expect(api.status).toBe(401);
    expect((await middleware(get("/dashboardish", new Map(), { accept: "text/html" }))).headers.get("x-middleware-next")).toBe("1");
    expect((await middleware(get("/auth/login", new Map(), { accept: "text/html" }))).headers.get("x-middleware-next")).toBe("1");

    const { cookies } = await signIn(t, nine);
    expect((await middleware(get("/dashboard", cookies, { accept: "text/html" }))).headers.get("x-middleware-next")).toBe("1");
  });

  it("clears a revoked session and sends the user to sign in", async () => {
    const t = await tenant();
    const nine = setup(t);
    const middleware = nine.middleware({ protect: ["/"] });
    const { cookies } = await signIn(t, nine);
    t.state.dead = true;
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 400_000 });
    const res = await middleware(get("/dashboard", cookies, { "sec-fetch-mode": "navigate" }));
    expect(res.status).toBe(307);
    expect(setCookies(res).some((line) => line.startsWith("nine_session=") && line.includes("Max-Age=0"))).toBe(true);
  });

  it("keeps the session when 9in can't be reached", async () => {
    const t = await tenant();
    const nine = setup(t);
    const middleware = nine.middleware({ protect: ["/"] });
    const { cookies } = await signIn(t, nine);
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 290_000 });
    vi.mocked(t.fetcher).mockRejectedValueOnce(new TypeError("fetch failed"));
    const res = await middleware(get("/dashboard", cookies, { accept: "text/html" }));
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(setCookies(res)).toEqual([]);
  });
});
