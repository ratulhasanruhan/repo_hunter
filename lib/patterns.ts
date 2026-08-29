/**
 * Provider pattern table.
 *
 * Two classes:
 *   "prefixed" — a vendor-issued shape with a distinctive prefix. Near-zero false
 *                positives, so a match alone is enough to report.
 *   "recon"    — not a credential. Internal hostnames, private IPs, employee
 *                emails. Reported separately as the reconnaissance layer.
 *
 * The third class (high-entropy generic strings) lives in entropy.ts, because it
 * needs corroborating signals rather than a pattern alone.
 */
import type { DetectorClass } from "./types";

export interface PatternDef {
  provider: string;
  kind: string;
  detector: DetectorClass;
  re: RegExp;
  /** Capture group holding the secret itself. Defaults to 0 (whole match). */
  group?: number;
  /** Structurally a sandbox/test credential — scored well below a live-mode one. */
  testMode?: boolean;
  /** Scope power hint used by score.ts before validation resolves. */
  power?: number;
  /** Dollar range if abused, shown instead of a severity label. */
  cost?: string;
}

export const PATTERNS: PatternDef[] = [
  // ---- OpenAI -------------------------------------------------------------
  {
    provider: "openai",
    kind: "OpenAI API key",
    detector: "prefixed",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    power: 8,
    cost: "$500–$50,000 (uncapped inference billing)",
  },
  // ---- Anthropic ----------------------------------------------------------
  {
    provider: "anthropic",
    kind: "Anthropic API key",
    detector: "prefixed",
    re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}\b/g,
    power: 8,
    cost: "$500–$50,000 (uncapped inference billing)",
  },
  // ---- GitHub -------------------------------------------------------------
  {
    provider: "github",
    kind: "GitHub personal access token",
    detector: "prefixed",
    re: /\bghp_[A-Za-z0-9]{36}\b/g,
    power: 9,
    cost: "Source access + supply-chain write. Unbounded.",
  },
  {
    provider: "github",
    kind: "GitHub OAuth token",
    detector: "prefixed",
    re: /\bgho_[A-Za-z0-9]{36}\b/g,
    power: 8,
    cost: "Source access on the granted scopes.",
  },
  {
    provider: "github",
    kind: "GitHub app/refresh token",
    detector: "prefixed",
    re: /\bgh[usr]_[A-Za-z0-9]{36}\b/g,
    power: 8,
    cost: "Source access on the granted scopes.",
  },
  {
    provider: "github",
    kind: "GitHub fine-grained PAT",
    detector: "prefixed",
    re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
    power: 9,
    cost: "Source access + supply-chain write. Unbounded.",
  },
  // ---- AWS ----------------------------------------------------------------
  {
    provider: "aws",
    kind: "AWS access key id",
    detector: "prefixed",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    power: 10,
    cost: "$1,000–$100,000+ (compute mining, data exfiltration)",
  },
  // ---- Stripe -------------------------------------------------------------
  {
    provider: "stripe",
    kind: "Stripe live secret key",
    detector: "prefixed",
    re: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
    power: 10,
    cost: "Direct funds movement. Bounded only by account balance.",
  },
  {
    provider: "stripe",
    kind: "Stripe live restricted key",
    detector: "prefixed",
    re: /\brk_live_[A-Za-z0-9]{20,}\b/g,
    power: 7,
    cost: "Scoped account access — read or write depending on grant.",
  },
  {
    provider: "stripe",
    kind: "Stripe publishable key (live)",
    detector: "prefixed",
    re: /\bpk_live_[A-Za-z0-9]{20,}\b/g,
    power: 1,
    cost: "None. Publishable keys are designed to ship to browsers.",
  },
  {
    provider: "stripe",
    kind: "Stripe test key",
    detector: "prefixed",
    re: /\b[sr]k_test_[A-Za-z0-9]{20,}\b/g,
    testMode: true,
    power: 1,
    cost: "None. Test mode touches no real money.",
  },
  // ---- Slack --------------------------------------------------------------
  {
    provider: "slack",
    kind: "Slack token",
    detector: "prefixed",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    power: 7,
    cost: "Message history exfiltration; posting as the workspace bot.",
  },
  {
    provider: "slack",
    kind: "Slack webhook",
    detector: "prefixed",
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_+/]{8,}\/B[A-Za-z0-9_+/]{8,}\/[A-Za-z0-9_+/]{20,}/g,
    power: 4,
    cost: "Unauthenticated posting into the target channel.",
  },
  // ---- Google -------------------------------------------------------------
  {
    provider: "google",
    kind: "Google API key",
    detector: "prefixed",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    power: 6,
    cost: "$100–$10,000 (metered API quota on the owning project)",
  },
  {
    provider: "google",
    kind: "Google OAuth client secret",
    detector: "prefixed",
    re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
    power: 7,
    cost: "Identity impersonation against the OAuth consent screen.",
  },
  // ---- SendGrid -----------------------------------------------------------
  {
    provider: "sendgrid",
    kind: "SendGrid API key",
    detector: "prefixed",
    re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    power: 7,
    cost: "Phishing from a domain with your sending reputation.",
  },
  // ---- GitLab -------------------------------------------------------------
  {
    provider: "gitlab",
    kind: "GitLab personal access token",
    detector: "prefixed",
    re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    power: 8,
    cost: "Source access + CI pipeline write.",
  },
  // ---- npm ----------------------------------------------------------------
  {
    provider: "npm",
    kind: "npm access token",
    detector: "prefixed",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    power: 9,
    cost: "Package publish rights. Supply-chain compromise.",
  },
  // ---- Twilio -------------------------------------------------------------
  {
    provider: "twilio",
    kind: "Twilio API key",
    detector: "prefixed",
    re: /\bSK[0-9a-fA-F]{32}\b/g,
    power: 6,
    cost: "$100–$20,000 (toll fraud via outbound SMS/voice)",
  },
  // ---- Keys and structured credentials ------------------------------------
  {
    provider: "pem",
    kind: "Private key (PEM)",
    detector: "prefixed",
    // The whole armored block, not just the header: keying on the header alone
    // would collapse every RSA key in the repo into a single finding.
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{40,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    power: 9,
    cost: "Server impersonation, decryption of captured traffic.",
  },
  {
    provider: "jwt",
    kind: "JSON Web Token",
    detector: "prefixed",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    power: 5,
    cost: "Session hijack until the token expires.",
  },
  {
    provider: "database",
    kind: "Database connection string with password",
    detector: "prefixed",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:@/"']+:[^\s:@/"']{4,}@[^\s"'<>]+/g,
    power: 9,
    cost: "Full read/write on production data.",
  },

  // ---- Recon layer: not credentials, but the map that precedes an attack ---
  {
    provider: "recon",
    kind: "Private IP address",
    detector: "recon",
    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
  },
  {
    provider: "recon",
    kind: "Internal hostname",
    detector: "recon",
    re: /\b[a-z0-9][a-z0-9-]{1,60}\.(?:internal|corp|intranet|lan|local|priv)\b/gi,
  },
  {
    provider: "recon",
    kind: "Staging / pre-production URL",
    detector: "recon",
    re: /\bhttps?:\/\/(?:[a-z0-9-]+\.)*(?:staging|stage|dev|qa|uat|preprod|test)[a-z0-9-]*\.[a-z0-9.-]{3,}\b/gi,
  },
  {
    provider: "recon",
    kind: "S3 bucket",
    detector: "recon",
    re: /\b[a-z0-9][a-z0-9.-]{2,62}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b/gi,
  },
  {
    provider: "recon",
    kind: "Employee email address",
    detector: "recon",
    // Consumer mailboxes are excluded: a committer's gmail address is already
    // in every commit header, so reporting it adds noise, not reconnaissance.
    re: /\b[A-Za-z0-9._%+-]+@(?!(?:example|test|sample|domain|email|gmail|googlemail|yahoo|hotmail|outlook|icloud|proton(?:mail)?|aol|qq|163)\.|localhost|sentry\.io|users\.noreply)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
];

/**
 * Placeholder markers. A "secret" containing one of these is a fixture, not a leak.
 * Checked case-insensitively against the matched value.
 */
const PLACEHOLDER_MARKERS = [
  "xxxx",
  "example",
  "dummy",
  "changeme",
  "placeholder",
  "your_",
  "yourkey",
  "<your",
  "insert",
  "redacted",
  "sample",
  "notreal",
  "fake",
  "test_key",
  "0000000000",
  "1234567890",
  "aaaaaaaaaa",
  "abcdefghij",
];

export function isPlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((m) => v.includes(m))) return true;
  // A value made of one repeated character carries no entropy and no risk.
  const body = value.replace(/^[a-z]+[_-]/i, "");
  if (body.length > 8 && new Set(body).size <= 3) return true;
  return false;
}

/**
 * Paths that generate noise without generating risk. Lockfiles restate published
 * hashes, bundles restate source, vendored trees restate other people's code.
 */
const SUPPRESSED_PATH = [
  /(^|\/)node_modules\//,
  /(^|\/)vendor\//,
  /(^|\/)third_party\//,
  /(^|\/)\.yarn\//,
  /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|Cargo\.lock|poetry\.lock|go\.sum)$/,
  /\.min\.(js|css)$/,
  /\.(map|lock)$/,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)\.next\//,
  /\.(png|jpe?g|gif|bmp|ico|webp|svg|pdf|zip|gz|tar|bz2|7z|rar|mp[34]|mov|avi|woff2?|ttf|eot|otf|class|jar|so|dylib|dll|exe|wasm|pyc|o|a)$/i,
];

export function isSuppressedPath(path: string): boolean {
  return SUPPRESSED_PATH.some((re) => re.test(path));
}

/** Files where a secret-shaped string is far more likely to be the real thing. */
export function isSensitiveFile(path: string): boolean {
  const base = path.split("/").pop() ?? "";
  return (
    /^\.env(\..+)?$/.test(base) ||
    /\.(env|pem|key|p12|pfx|keystore|jks|ovpn|netrc|npmrc|pypirc)$/i.test(base) ||
    /^(credentials|secrets?|config|settings|application|docker-compose|terraform)\b/i.test(base) ||
    /(^|\/)\.(aws|ssh|docker|kube)\//.test(path) ||
    /(^|\/)\.github\/workflows\//.test(path) ||
    /\.(ya?ml|tfvars|properties|ini|cfg|conf|toml)$/i.test(base)
  );
}

/** Test fixtures — real leaks happen here too, but the prior is much lower. */
export function isTestPath(path: string): boolean {
  return /(^|\/)(tests?|spec|specs|__tests__|__mocks__|fixtures?|examples?|samples?|docs?)\//i.test(path);
}

/**
 * PEM blocks are excised from a blob before the entropy detector runs. Their
 * base64 body is high-entropy by construction, and the key itself has already
 * been reported by the prefixed pattern above — without this, one leaked service
 * account key produces twenty-five duplicate "high-entropy string" findings.
 */
export const PEM_BLOCK_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{40,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g;
