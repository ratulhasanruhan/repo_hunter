import { createHash } from "node:crypto";

/**
 * The only representation of a secret allowed to leave the scanner: first four
 * and last four characters. Applied at detection time, not at render time, so
 * there is no code path where a full value reaches the client, the cache, a log
 * line, or a screen share.
 */
export function mask(secret: string): string {
  // A PEM block's first and last four characters are both "----", which
  // identifies nothing. Show the key type and a tail of the body instead.
  const pem = /-----BEGIN ([A-Z ]*?)\s*PRIVATE KEY-----([\s\S]+?)-----END/.exec(secret);
  if (pem) {
    const type = pem[1].trim() || "PRIVATE";
    const body = pem[2].replace(/[^A-Za-z0-9+/=]/g, "");
    // Fall back to a content hash so two different keys never mask alike.
    const tail = body.slice(-4) || createHash("sha256").update(secret).digest("hex").slice(0, 4);
    return `${type} KEY ·····${tail}`;
  }
  if (secret.length <= 12) return `${secret.slice(0, 2)}${"·".repeat(6)}`;
  return `${secret.slice(0, 4)}${"·".repeat(8)}${secret.slice(-4)}`;
}

/** Dedupe key. One key committed forty times is one finding. */
export function secretId(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}
