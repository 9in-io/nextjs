// The parts of Next.js this package uses. Next.js is a peer dependency, imported at run time
// with the ".js" file names so the imports resolve both in Next's bundler and in plain Node ESM.
declare module "next/headers.js" {
  interface CookieStore {
    getAll(): { name: string; value: string }[];
    set(name: string, value: string, options?: Record<string, unknown>): unknown;
    delete(name: string): unknown;
  }
  export function cookies(): CookieStore | Promise<CookieStore>;
}

declare module "next/server.js" {
  export const NextResponse: {
    next(init?: { request?: { headers?: Headers } }): Response;
    redirect(url: string | URL, status?: number): Response;
  };
}
