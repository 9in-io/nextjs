/** Cookie parsing, Set-Cookie serialization and chunking (browsers keep about 4 KB per cookie). */

export interface CookieOptions {
  path: string;
  secure: boolean;
  /** seconds; 0 deletes */
  maxAge: number;
}

/** Leaves room for the name and attributes within the ~4096-byte limit. */
export const CHUNK_SIZE = 3800;

export function parseCookies(header: string | null | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!header) return map;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (!name || map.has(name)) continue;
    let value = part.slice(index + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    map.set(name, value);
  }
  return map;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  let out = `${name}=${value}; Path=${options.path}; HttpOnly; SameSite=Lax; Max-Age=${options.maxAge}`;
  if (options.maxAge === 0) out += "; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
  if (options.secure) out += "; Secure";
  return out;
}

/** Splits a value into `name` (when it fits) or `name.0`, `name.1`, … */
export function chunk(name: string, value: string): [string, string][] {
  if (value.length <= CHUNK_SIZE) return [[name, value]];
  const parts: [string, string][] = [];
  for (let i = 0; i * CHUNK_SIZE < value.length; i++) parts.push([`${name}.${i}`, value.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)]);
  return parts;
}

/** Joins what `chunk` wrote; null when the cookie isn't there. */
export function unchunk(name: string, cookies: Map<string, string>): string | null {
  const whole = cookies.get(name);
  if (whole !== undefined) return whole;
  let value = "";
  for (let i = 0; cookies.has(`${name}.${i}`); i++) value += cookies.get(`${name}.${i}`);
  return value || null;
}

/** The names of all cookies that belong to `name` (whole or chunked). */
export function chunkNames(name: string, names: Iterable<string>): string[] {
  const pattern = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\.\\d+)?$`);
  return [...names].filter((n) => pattern.test(n));
}
