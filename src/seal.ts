/**
 * Encrypted cookie values: AES-256-GCM with a key derived from your secret (HKDF-SHA-256), and
 * the cookie's purpose as additional data, so a value sealed for one cookie can't be used as
 * another. Web Crypto only (Node 18+, Edge).
 */

const encoder = new TextEncoder();
const keys = new Map<string, Promise<CryptoKey>>();

function deriveKey(secret: string): Promise<CryptoKey> {
  let key = keys.get(secret);
  if (!key) {
    key = crypto.subtle
      .importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"])
      .then((material) =>
        crypto.subtle.deriveKey(
          { name: "HKDF", hash: "SHA-256", salt: encoder.encode("9in-nextjs"), info: encoder.encode("cookie encryption") },
          material,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        ),
      );
    keys.set(secret, key);
  }
  return key;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** Encrypts `value` (JSON) with the first secret. */
export async function seal(value: unknown, secrets: readonly string[], purpose: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = encoder.encode(JSON.stringify(value));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(purpose) }, await deriveKey(secrets[0]!), data));
  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv);
  out.set(sealed, iv.length);
  return toBase64Url(out);
}

/** Decrypts a sealed value with any of the secrets (so you can rotate them); null when it doesn't open. */
export async function unseal<T>(text: string, secrets: readonly string[], purpose: string): Promise<T | null> {
  const bytes = fromBase64Url(text);
  if (!bytes || bytes.length < 12 + 16) return null;
  for (const secret of secrets) {
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: encoder.encode(purpose) }, await deriveKey(secret), bytes.subarray(12));
      return JSON.parse(new TextDecoder().decode(plain)) as T;
    } catch {
      // try the next secret
    }
  }
  return null;
}
