9in Next.js SDK
===============

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official Next.js SDK for [9in](https://9in.io), built on [`@9in-io/sdk`](https://github.com/9in-io/sdk).

`@9in-io/nextjs` signs users in to your Next.js app (App Router) on the server, with three small
files and a few environment variables:

- **Sign-in routes**: `/auth/login`, `/auth/signup`, `/auth/callback`, `/auth/logout` and
  `/auth/session`. The authorization code flow with PKCE runs on your server, with your client
  secret when the application has one.
- **An encrypted session cookie** (AES-256-GCM) with no tokens exposed to the browser.
- **`auth()` and `getAccessToken()`** in Server Components, Route Handlers and Server Actions.
- **Middleware** that refreshes tokens before pages render and protects the paths you choose.
- **Client Components**: `<SessionProvider>`, `useSession()`, `<SignedIn>`, `<SignedOut>`,
  `signIn()` and `signOut()` from `@9in-io/nextjs/client`.

Requires Next.js 14.2 or later and React 18 or later (peer dependencies). It runs on the Node and
Edge runtimes and has no dependencies besides `@9in-io/sdk`.

```bash
npm install @9in-io/nextjs
```

A single-page app with no server? Use [`@9in-io/react`](https://github.com/9in-io/react). The full
guide is [Server-rendered apps](https://9in.io/docs/server-apps/) in the 9in docs.

## 1. Configure

Create a **Regular Web App** application in the 9in console and add:

- Allowed callback URL: `https://your-app.com/auth/callback` (and `http://localhost:3000/auth/callback`)
- Allowed logout URL: `https://your-app.com/` (and `http://localhost:3000/`)

Then set these in `.env.local`:

```sh
NINE_ISSUER=https://acme.9in.io
NINE_CLIENT_ID=app_...
NINE_CLIENT_SECRET=...
NINE_SECRET=...            # 32+ characters: openssl rand -base64 32
NINE_BASE_URL=http://localhost:3000
# NINE_AUDIENCE=https://api.example.com   # access tokens for your API
```

`NINE_SECRET` encrypts the session cookie. Keep it out of the browser (no `NEXT_PUBLIC_`).

## 2. Add three files

```ts
// auth.ts
import { createNine } from "@9in-io/nextjs";

export const nine = createNine();
```

```ts
// app/auth/[...nine]/route.ts
import { nine } from "@/auth";

export const { GET, POST } = nine.handlers;
```

```ts
// proxy.ts (Next 16) or middleware.ts (Next 14 and 15)
import { nine } from "@/auth";

export default nine.middleware({ protect: ["/dashboard", "/settings"] });

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

That gives you these routes:

| Route | What it does |
| --- | --- |
| `/auth/login?returnTo=/dashboard` | Goes to the 9in sign-in page. Also takes `prompt`, `login_hint` and `locale`. |
| `/auth/signup` | Goes to the registration page. |
| `/auth/callback` | Finishes the sign-in and sets the session cookie. |
| `/auth/logout?returnTo=/` | Signs out here and at 9in. Add `local=1` to sign out only here. |
| `/auth/session` | `{ "user": { … } }` or `{ "user": null }`, for client code. |

Link to them with `<a href="/auth/login">`, not `<Link>`: they redirect to another site, and
prefetching them is pointless (prefetch requests are ignored).

## 3. Use the session

```tsx
// app/dashboard/page.tsx (a Server Component)
import { nine } from "@/auth";

export default async function Dashboard() {
  const session = await nine.auth(); // { user } or null
  return <h1>Hello {session?.user.name}</h1>;
}
```

Call your API with the user's access token:

```ts
// app/api/orders/route.ts, a Server Action, or a Server Component
const token = await nine.getAccessToken();
const res = await fetch("https://api.example.com/orders", { headers: { Authorization: `Bearer ${token}` } });
```

`session.user` holds the ID token's claims (`sub`, `email`, `name`, `picture`, `amr`, your
custom claims…). The session object has no tokens in it, so you can pass it to Client Components.

### Client Components

```tsx
// app/layout.tsx
import { SessionProvider } from "@9in-io/nextjs/client";
import { nine } from "@/auth";

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SessionProvider session={await nine.auth()}>{children}</SessionProvider>
      </body>
    </html>
  );
}
```

```tsx
"use client";
import { SignedIn, SignedOut, signIn, signOut, useSession } from "@9in-io/nextjs/client";

export function UserMenu() {
  const { user } = useSession(); // also: status ("loading" | "authenticated" | "unauthenticated"), update()
  return (
    <>
      <SignedOut>
        <button onClick={() => signIn()}>Sign in</button>
      </SignedOut>
      <SignedIn>
        {user?.name} <button onClick={() => signOut()}>Sign out</button>
      </SignedIn>
    </>
  );
}
```

`signIn()` comes back to the current page; `signUp()` opens the registration page.
Without a `session` prop, `<SessionProvider>` asks `/auth/session` once.

## Token refresh

9in rotates refresh tokens: each one works once, and using one twice ends the session (it looks
like a stolen token). So this package refreshes only where the new refresh token can be saved:

- **Middleware** (`proxy.ts` / `middleware.ts`) refreshes the access token a minute before it
  expires, sets the new cookie and passes it on to the page being rendered. Requests that arrive
  together share one refresh.
- **Route Handlers and Server Actions**: `getAccessToken()` refreshes when needed.
- **Server Components** can't set cookies, so `getAccessToken()` never refreshes there. It returns
  the token the middleware kept fresh, and throws `token_expired` if there's no middleware.

When the refresh token was revoked (the user signed out everywhere, or an admin ended the
session), the session cookie is removed and protected pages go to the sign-in page.

## Options

All of these are optional. `issuer`, `clientId`, `clientSecret`, `secret`, `baseUrl` and
`audience` default to the environment variables above.

```ts
createNine({
  issuer, clientId, clientSecret,
  secret,               // string, or [new, old] to rotate
  baseUrl,              // include Next's basePath if you use one
  basePath: "/auth",    // where the routes are mounted
  scope: "openid profile email offline_access",
  audience: "https://api.example.com", // access tokens for your API
  cookieName: "nine_session",
  sessionMaxAge: 30 * 24 * 3600, // seconds without use before the session ends
  refreshLeeway: 60,             // seconds before expiry to refresh
  afterSignInPath: "/",
  afterSignOutPath: "/",          // must be an allowed logout URL
  onError: (error, request) => Response.redirect(new URL(`/sign-in-failed?error=${error.code}`, request.url)),
});
```

`middleware({ protect })` takes path prefixes (`"/dashboard"` covers everything under it, `"/"`
covers every page), RegExps or a function of the request. Signed-out page visits go to the
sign-in page and come back; other requests (API calls) get a 401.

## Security

- The session and the sign-in transaction (state, nonce, PKCE verifier) are in `HttpOnly`,
  `SameSite=Lax` cookies, encrypted with AES-256-GCM. They're `Secure` when your URL is https.
  Large sessions are split over several cookies.
- Every sign-in uses PKCE, `state` and `nonce`. The ID token's signature, issuer, audience and
  expiry are checked, and so is the issuer in the callback (RFC 9207).
- `returnTo` only takes paths on your own site.
- Sign-out revokes the refresh token at 9in.

Every option and member is in the [SDK reference](https://9in.io/docs/reference/sdk/#9in-io-nextjs).

## Development

```bash
npm install
npm test            # vitest (Node 22.12+)
npm run typecheck
npm run build       # dist/
```

This package is developed in 9in's monorepo and copied here at each release (one commit per
version). Report bugs in [issues](https://github.com/9in-io/nextjs/issues).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in and SSOfy are by [Cubelet Ltd](https://cubelet.co.uk).
