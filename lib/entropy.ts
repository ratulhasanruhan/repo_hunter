/**
 * Generic high-entropy detection.
 *
 * A long random-looking string is not evidence of a secret on its own — hashes,
 * UUIDs, minified identifiers and base64 blobs all look the same. So a candidate
 * is only reported when it clears the entropy floor AND at least two independent
 * signals corroborate it. This is the highest-false-positive detector in the
 * project, which is why it is the last one to run and the easiest one to ignore.
 */
import { isSensitiveFile, isTestPath } from "./patterns";

const ENTROPY_FLOOR = 4.5;
const MIN_LEN = 20;
const MAX_LEN = 120;

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const SECRETISH_NAME =
  /(api[_-]?key|secret|passwd|password|token|credential|auth|private[_-]?key|access[_-]?key|client[_-]?secret|bearer|session|signature)/i;

/** Shapes that are high-entropy by construction and carry no credential value. */
const KNOWN_NON_SECRET = [
  /^[0-9a-f]{32}$/i, // md5 / git-ish hex
  /^[0-9a-f]{40}$/i, // sha1 / commit sha
  /^[0-9a-f]{64}$/i, // sha256
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // uuid
  /^sha(256|512)-[A-Za-z0-9+/=]+$/, // SRI integrity hash
  /^[A-Za-z0-9+/=]{20,}$/u, // handled below only with corroboration
];

/** base64 that decodes to a known binary header is an embedded asset, not a key. */
function decodesToBinary(candidate: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(candidate) || candidate.length % 4 !== 0) return false;
  try {
    const buf = Buffer.from(candidate, "base64");
    if (buf.length < 4) return false;
    const sig = buf.subarray(0, 8);
    const magics: number[][] = [
      [0x89, 0x50, 0x4e, 0x47], // PNG
      [0xff, 0xd8, 0xff], // JPEG
      [0x47, 0x49, 0x46, 0x38], // GIF
      [0x50, 0x4b, 0x03, 0x04], // ZIP
      [0x25, 0x50, 0x44, 0x46], // PDF
      [0x00, 0x00, 0x01, 0x00], // ICO
      [0x1f, 0x8b], // gzip
    ];
    if (magics.some((m) => m.every((b, i) => sig[i] === b))) return true;
    // Mostly-unprintable decode means it is data, not a credential.
    let printable = 0;
    for (const b of buf.subarray(0, 64)) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
    return printable / Math.min(64, buf.length) < 0.75;
  } catch {
    return false;
  }
}

export interface EntropyCandidate {
  value: string;
  entropy: number;
  /** The corroborating signals that let this through, for display. */
  signals: string[];
}

const TOKEN_RE = /[A-Za-z0-9+/_=-]{20,120}/g;

/**
 * Scan one line of one file. Returns candidates that clear the floor and have
 * at least two corroborating signals.
 */
export function entropyCandidates(line: string, path: string): EntropyCandidate[] {
  if (line.length > 4000) return []; // minified or generated
  const out: EntropyCandidate[] = [];
  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(line))) {
    const value = m[0];
    if (value.length < MIN_LEN || value.length > MAX_LEN) continue;
    if (KNOWN_NON_SECRET.slice(0, 5).some((re) => re.test(value))) continue;
    if (decodesToBinary(value)) continue;

    const entropy = shannonEntropy(value);
    if (entropy < ENTROPY_FLOOR) continue;

    const signals: string[] = [];
    // 1. The name it is bound to says "secret".
    const before = line.slice(0, m.index);
    if (SECRETISH_NAME.test(before)) signals.push("secret-ish variable name");
    // 2. The file it lives in is a config / env / CI file.
    if (isSensitiveFile(path) || SECRETISH_NAME.test(path)) signals.push("config or env file");
    // 3. It sits on the right-hand side of an assignment.
    if (/[:=]\s*["'`]?\s*$/.test(before) || /^\s*["'`]?\s*[:=]/.test(line.slice(m.index + value.length))) {
      signals.push("assignment right-hand side");
    }
    // 4. Mixed alphabet — vendor keys mix case and digits; hashes do not.
    if (/[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value)) {
      signals.push("mixed-case alphanumeric");
    }
    if (signals.length < 2) continue;
    // Test fixtures need one more signal than production code.
    if (isTestPath(path) && signals.length < 3) continue;

    out.push({ value, entropy, signals });
  }
  return out;
}
