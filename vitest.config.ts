import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// next/headers only works inside a Next.js request, so tests use a stand-in cookie jar.
export default defineConfig({
  resolve: {
    conditions: ["@9in/source"],
    alias: {
      "next/headers.js": fileURLToPath(new URL("./test/stubs/next-headers.ts", import.meta.url)),
    },
  },
});
