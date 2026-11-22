# Changelog

## 0.3.0

Needs `@9in-io/sdk` 0.4.0.

- The `idTokenSecret` option is removed. 9in signs ID tokens with the tenant's asymmetric
  default key (never HMAC), so it never verified a real ID token; drop it from `createNine()`.
  A failed ID token check on the callback reaches `onError` as `invalid_id_token` (from
  `@9in-io/sdk` 0.4.0).

## 0.2.0

Breaking: the routes moved from `/auth` to `/nine`, the paths every 9in SDK uses
(`9in/laravel` serves `/nine/login`, `/nine/callback` and `/nine/logout` too).

- `basePath` defaults to `"/nine"`: `/nine/login`, `/nine/signup`, `/nine/callback`,
  `/nine/logout` and `/nine/session`. Move `app/auth/[...nine]/route.ts` to
  `app/nine/[...nine]/route.ts` and add `https://your-app.com/nine/callback` to the application's
  callback URLs, or keep the old URLs with `basePath: "/auth"` in `createNine()` and
  `basePath="/auth"` on `<SessionProvider>`, `signIn()`, `signUp()` and `signOut()`.
- The page to come back to is the `return_to` query parameter, like the other 9in SDKs and 9in's
  snake_case wire format. `/nine/login?returnTo=…` and `/nine/logout?returnTo=…` still work; the
  middleware and the client helpers send `return_to`. The `returnTo` option of `signIn()`,
  `signUp()` and `signOut()` is unchanged.

## 0.1.0

First release.

- `createNine()` reads `NINE_ISSUER`, `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET`, `NINE_SECRET` and `NINE_BASE_URL`.
- `nine.handlers`: `/auth/login`, `/auth/signup`, `/auth/callback`, `/auth/logout` and `/auth/session`.
- Encrypted session cookie (AES-256-GCM), split into several cookies when it's large, with secret rotation.
- `nine.auth()` and `nine.getAccessToken()` for Server Components, Route Handlers and Server Actions.
- `nine.middleware({ protect })` refreshes tokens before pages render (one refresh for concurrent requests) and protects paths.
- `@9in-io/nextjs/client`: `<SessionProvider>`, `useSession()`, `<SignedIn>`, `<SignedOut>`, `signIn()`, `signUp()` and `signOut()`.
