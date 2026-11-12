import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider, SignedIn, SignedOut, signIn, signOut, signUp, useSession } from "../src/client";

function Name() {
  const { user, status } = useSession();
  return <p>{`${status}:${user?.name ?? "-"}`}</p>;
}

afterEach(() => vi.unstubAllGlobals());

describe("client", () => {
  it("renders a session passed from the server without a request", () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const html = renderToString(
      <SessionProvider session={{ user: { sub: "usr_1", name: "Jane" } }}>
        <Name />
        <SignedIn>in</SignedIn>
        <SignedOut>out</SignedOut>
      </SessionProvider>,
    );
    expect(html).toContain("<p>authenticated:Jane</p>");
    expect(html).toContain("in");
    expect(html).not.toContain("out");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("shows nothing for SignedIn/SignedOut while loading", () => {
    const html = renderToString(
      <SessionProvider>
        <Name />
        <SignedIn>in</SignedIn>
        <SignedOut>out</SignedOut>
      </SessionProvider>,
    );
    expect(html).toBe("<p>loading:-</p>");
  });

  it("navigates to the routes", () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/pricing", search: "?plan=pro", assign } });
    signIn();
    signUp({ locale: "de" });
    signIn({ returnTo: "/x", basePath: "/api/auth", prompt: "login" });
    signOut({ local: true });
    expect(assign.mock.calls.map(([url]) => url)).toEqual([
      "/auth/login?returnTo=%2Fpricing%3Fplan%3Dpro",
      "/auth/signup?returnTo=%2Fpricing%3Fplan%3Dpro&locale=de",
      "/api/auth/login?returnTo=%2Fx&prompt=login",
      "/auth/logout?local=1",
    ]);
  });

  it("needs the provider", () => {
    expect(() => renderToString(<Name />)).toThrow(/inside <SessionProvider>/);
  });
});
