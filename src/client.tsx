"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import type { Session, User } from "./types.js";

export type { Session, User } from "./types.js";

export type SessionStatus = "loading" | "authenticated" | "unauthenticated";

export interface UseSession {
  /** The signed-in user, or null. */
  user: User | null;
  status: SessionStatus;
  /** Reads the session from the server again. */
  update: () => Promise<void>;
}

interface Value {
  state: { user: User | null; status: SessionStatus };
  update: () => Promise<void>;
}

const SessionContext = createContext<Value | null>(null);

const fromSession = (session: Session | null) => (session ? { user: session.user, status: "authenticated" as const } : { user: null, status: "unauthenticated" as const });

export interface SessionProviderProps {
  children?: ReactNode;
  /**
   * The session from `await nine.auth()` in a Server Component (no request from the browser,
   * no loading state). Leave it out and the provider asks `{basePath}/session`.
   */
  session?: Session | null;
  /** Where the routes are mounted. Default "/auth". */
  basePath?: string;
}

/** Makes the session available to Client Components (useSession, SignedIn, SignedOut). */
export function SessionProvider({ children, session, basePath = "/auth" }: SessionProviderProps) {
  const [state, setState] = useState<Value["state"]>(() => (session === undefined ? { user: null, status: "loading" } : fromSession(session)));

  const update = useCallback(async () => {
    try {
      const res = await fetch(`${basePath}/session`, { headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" });
      const body = res.ok ? ((await res.json()) as { user: User | null }) : { user: null };
      setState(fromSession(body.user ? { user: body.user } : null));
    } catch {
      setState((current) => (current.status === "loading" ? { user: null, status: "unauthenticated" } : current));
    }
  }, [basePath]);

  // A session from the server wins (it changes after navigation or router.refresh()).
  useEffect(() => {
    if (session === undefined) void update();
    else setState(fromSession(session));
  }, [session, update]);

  return <SessionContext.Provider value={{ state, update }}>{children}</SessionContext.Provider>;
}

/** The session in a Client Component. Must be used inside <SessionProvider>. */
export function useSession(): UseSession {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession() must be used inside <SessionProvider>");
  return { ...value.state, update: value.update };
}

/** Shows its children only to signed-in users (nothing while loading). */
export function SignedIn({ children }: { children?: ReactNode }) {
  return useSession().status === "authenticated" ? <>{children}</> : null;
}

/** Shows its children only to signed-out users (nothing while loading). */
export function SignedOut({ children }: { children?: ReactNode }) {
  return useSession().status === "unauthenticated" ? <>{children}</> : null;
}

export interface SignInOptions {
  /** A path to come back to. Default: the current page. */
  returnTo?: string;
  prompt?: "login" | "consent" | "none" | "select_account";
  /** Prefills the identifier on the sign-in page. */
  loginHint?: string;
  /** Language of the hosted pages, e.g. "de". */
  locale?: string;
  /** Default "/auth". */
  basePath?: string;
}

function go(path: string, params: Record<string, string | undefined>) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value) query.set(key, value);
  const qs = query.toString();
  window.location.assign(qs ? `${path}?${qs}` : path);
}

const here = () => window.location.pathname + window.location.search;

/** Goes to the 9in sign-in page. */
export function signIn(options: SignInOptions = {}): void {
  go(`${options.basePath ?? "/auth"}/login`, { returnTo: options.returnTo ?? here(), prompt: options.prompt, login_hint: options.loginHint, locale: options.locale });
}

/** Goes to the 9in registration page. */
export function signUp(options: Omit<SignInOptions, "prompt"> = {}): void {
  go(`${options.basePath ?? "/auth"}/signup`, { returnTo: options.returnTo ?? here(), login_hint: options.loginHint, locale: options.locale });
}

/** Signs out here and at 9in (`local: true` only here). */
export function signOut(options: { returnTo?: string; local?: boolean; basePath?: string } = {}): void {
  go(`${options.basePath ?? "/auth"}/logout`, { returnTo: options.returnTo, local: options.local ? "1" : undefined });
}
