# Changelog

## 0.1.0

First release.

- `createNine()` reads `NINE_ISSUER`, `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET`, `NINE_SECRET` and `NINE_BASE_URL`.
- `nine.handlers`: `/auth/login`, `/auth/signup`, `/auth/callback`, `/auth/logout` and `/auth/session`.
- Encrypted session cookie (AES-256-GCM), split into several cookies when it's large, with secret rotation.
- `nine.auth()` and `nine.getAccessToken()` for Server Components, Route Handlers and Server Actions.
- `nine.middleware({ protect })` refreshes tokens before pages render (one refresh for concurrent requests) and protects paths.
- `@9in-io/nextjs/client`: `<SessionProvider>`, `useSession()`, `<SignedIn>`, `<SignedOut>`, `signIn()`, `signUp()` and `signOut()`.
