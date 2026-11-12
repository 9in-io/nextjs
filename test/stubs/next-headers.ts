// Stands in for next/headers in tests: one cookie jar, writable (Route Handler) or not (Server Component).
export const jar = new Map<string, string>();
export const writes: { name: string; value: string; options?: Record<string, unknown> }[] = [];
export const mode = { writable: true };

export function cookies() {
  return Promise.resolve({
    getAll: () => [...jar].map(([name, value]) => ({ name, value })),
    set(name: string, value: string, options?: Record<string, unknown>) {
      if (!mode.writable) throw new Error("Cookies can only be modified in a Server Action or Route Handler.");
      writes.push({ name, value, ...(options ? { options } : {}) });
      if (options?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
    },
    delete(name: string) {
      if (!mode.writable) throw new Error("Cookies can only be modified in a Server Action or Route Handler.");
      jar.delete(name);
    },
  });
}
