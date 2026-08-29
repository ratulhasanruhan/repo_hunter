/**
 * Read-only provider probes.
 *
 * Rules, enforced by construction rather than by discipline:
 *   - Every request below is a GET (or a documented no-op POST like Slack's
 *     auth.test / AWS STS GetCallerIdentity). Nothing here creates, charges,
 *     sends, or deletes. We are handling someone else's credential.
 *   - 3 second timeout, run in parallel, never blocks the render.
 *   - "unknown" is a real answer. A network failure is not evidence of a dead key.
 *   - No secret value is ever logged, thrown, or attached to an error.
 */
import { createHmac, createHash } from "node:crypto";
import type { Liveness, ValidationDetail } from "./types";

const TIMEOUT_MS = 3000;

export interface ValidationResult {
  liveness: Liveness;
  detail?: ValidationDetail;
}

const DEAD: ValidationResult = { liveness: "dead" };
const UNKNOWN: ValidationResult = { liveness: "unknown" };

async function get(url: string, headers: Record<string, string>): Promise<Response | null> {
  try {
    return await fetch(url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(TIMEOUT_MS),
      cache: "no-store",
    });
  } catch {
    // Timeout, DNS failure, offline. Not evidence either way.
    return null;
  }
}

/** GitHub: the token metadata on any authenticated request carries the scopes. */
async function github(secret: string): Promise<ValidationResult> {
  const res = await get("https://api.github.com/user", {
    Authorization: `Bearer ${secret}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "RepoHunter",
  });
  if (!res) return UNKNOWN;
  if (res.status === 401) return DEAD;
  if (!res.ok) return UNKNOWN;
  const scopeHeader = res.headers.get("x-oauth-scopes") ?? "";
  const scopes = scopeHeader.split(",").map((s) => s.trim()).filter(Boolean);
  let identity: string | undefined;
  try {
    const body = (await res.json()) as { login?: string };
    identity = body.login;
  } catch {
    /* body shape is not load-bearing */
  }
  const write = scopes.some((s) => /^(repo|write|admin|delete)/.test(s)) || scopes.length === 0;
  return {
    liveness: "live",
    detail: {
      scopes: scopes.length ? scopes : ["fine-grained (scopes not exposed in header)"],
      identity,
      write,
    },
  };
}

/** OpenAI: listing models is the canonical side-effect-free validity check. */
async function openai(secret: string): Promise<ValidationResult> {
  const res = await get("https://api.openai.com/v1/models", { Authorization: `Bearer ${secret}` });
  if (!res) return UNKNOWN;
  if (res.status === 401 || res.status === 403) return DEAD;
  if (!res.ok) return UNKNOWN;
  let count = 0;
  try {
    const body = (await res.json()) as { data?: unknown[] };
    count = body.data?.length ?? 0;
  } catch {
    /* ignore */
  }
  return {
    liveness: "live",
    detail: { note: count ? `${count} models accessible` : "accepted", write: true },
  };
}

/** Anthropic: same idea — GET /v1/models. */
async function anthropic(secret: string): Promise<ValidationResult> {
  const res = await get("https://api.anthropic.com/v1/models?limit=1", {
    "x-api-key": secret,
    "anthropic-version": "2023-06-01",
  });
  if (!res) return UNKNOWN;
  if (res.status === 401 || res.status === 403) return DEAD;
  if (!res.ok) return UNKNOWN;
  return { liveness: "live", detail: { note: "accepted", write: true } };
}

/**
 * AWS: STS GetCallerIdentity. It is the one AWS call that requires no permissions
 * at all and mutates nothing — it just echoes who you are. Signed with SigV4.
 */
async function aws(secret: string, secondary?: string): Promise<ValidationResult> {
  // An access key id is useless without its secret key. If we did not also find
  // the paired secret in the repo, we honestly cannot say.
  if (!secondary) return UNKNOWN;
  const region = "us-east-1";
  const host = "sts.amazonaws.com";
  const body = "Action=GetCallerIdentity&Version=2011-06-15";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);

  const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
  const hmac = (key: Buffer | string, s: string) => createHmac("sha256", key).update(s).digest();

  const canonical = [
    "POST",
    "/",
    "",
    `content-type:application/x-www-form-urlencoded; charset=utf-8`,
    `host:${host}`,
    `x-amz-date:${amzDate}`,
    "",
    "content-type;host;x-amz-date",
    sha256(body),
  ].join("\n");

  const scope = `${dateStamp}/${region}/sts/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const signing = hmac(hmac(hmac(hmac(`AWS4${secondary}`, dateStamp), region), "sts"), "aws4_request");
  const signature = createHmac("sha256", signing).update(toSign).digest("hex");

  try {
    const res = await fetch(`https://${host}/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "X-Amz-Date": amzDate,
        Authorization: `AWS4-HMAC-SHA256 Credential=${secret}/${scope}, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`,
      },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text();
    if (res.status === 403) return DEAD;
    if (!res.ok) return UNKNOWN;
    const account = /<Account>(\d+)<\/Account>/.exec(text)?.[1];
    const arn = /<Arn>([^<]+)<\/Arn>/.exec(text)?.[1];
    return {
      liveness: "live",
      detail: {
        identity: arn ?? account,
        note: account ? `account ${account}` : undefined,
        write: !/readonly/i.test(arn ?? ""),
      },
    };
  } catch {
    return UNKNOWN;
  }
}

/** Stripe: retrieving the balance reads state and moves no money. */
async function stripe(secret: string): Promise<ValidationResult> {
  const res = await get("https://api.stripe.com/v1/balance", {
    Authorization: `Bearer ${secret}`,
  });
  if (!res) return UNKNOWN;
  if (res.status === 401) return DEAD;
  if (!res.ok) return UNKNOWN;
  const liveMode = secret.includes("_live_");
  return {
    liveness: "live",
    detail: {
      note: liveMode ? "live mode — real funds" : "test mode",
      write: liveMode && secret.startsWith("sk_"),
    },
  };
}

/** Slack: auth.test is explicitly the identity probe. It posts nothing. */
async function slack(secret: string): Promise<ValidationResult> {
  try {
    const res = await fetch("https://slack.com/api/auth.test", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secret}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return UNKNOWN;
    const body = (await res.json()) as { ok?: boolean; team?: string; user?: string; error?: string };
    if (!body.ok) {
      return body.error === "invalid_auth" || body.error === "token_revoked" ? DEAD : UNKNOWN;
    }
    return {
      liveness: "live",
      detail: {
        identity: [body.user, body.team].filter(Boolean).join(" @ ") || undefined,
        note: "workspace reachable",
        write: true,
      },
    };
  } catch {
    return UNKNOWN;
  }
}

/** Google: tokeninfo reports scopes for an OAuth token; API keys probe a free endpoint. */
async function google(secret: string): Promise<ValidationResult> {
  if (secret.startsWith("AIza")) {
    // Google answers an invalid API key with HTTP 400 and API_KEY_INVALID, not
    // 401 — so status code alone cannot decide this. The reason code can.
    const res = await get(
      `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(secret)}`,
      {},
    );
    if (!res) return UNKNOWN;
    if (res.ok) return { liveness: "live", detail: { note: "accepted" } };

    const text = await res.text().catch(() => "");
    if (/API_KEY_INVALID|API key not valid|API key expired/i.test(text)) return DEAD;

    // The key authenticated; the request itself was rejected. That only happens
    // once the key is past the API front-end, so the key is real.
    if (res.status === 400 && /Required parameter|Invalid Value|cx/i.test(text)) {
      return { liveness: "live", detail: { note: "accepted by the Google API front-end" } };
    }
    if (res.status === 403) {
      if (/SERVICE_DISABLED|has not been used in project|API_KEY_SERVICE_BLOCKED/i.test(text)) {
        return {
          liveness: "live",
          detail: { note: "key belongs to a real project; this API is not enabled on it" },
        };
      }
      if (/API_KEY_HTTP_REFERRER_BLOCKED|API_KEY_IP_ADDRESS_BLOCKED|API_KEY_ANDROID_APP_BLOCKED|API_KEY_IOS_APP_BLOCKED/i.test(text)) {
        return {
          liveness: "live",
          detail: { note: "valid, but restricted to specific referrers or addresses" },
        };
      }
    }
    // Anything else — quota, an unfamiliar error shape — is genuinely unknown.
    return UNKNOWN;
  }

  const res = await get(
    `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(secret)}`,
    {},
  );
  if (!res) return UNKNOWN;
  if (res.status === 400 || res.status === 401) return DEAD;
  if (!res.ok) return UNKNOWN;
  try {
    const body = (await res.json()) as { scope?: string; email?: string };
    return {
      liveness: "live",
      detail: { scopes: body.scope?.split(" "), identity: body.email },
    };
  } catch {
    return { liveness: "live" };
  }
}

/** SendGrid: the scopes endpoint enumerates permissions and sends no mail. */
async function sendgrid(secret: string): Promise<ValidationResult> {
  const res = await get("https://api.sendgrid.com/v3/scopes", {
    Authorization: `Bearer ${secret}`,
  });
  if (!res) return UNKNOWN;
  if (res.status === 401 || res.status === 403) return DEAD;
  if (!res.ok) return UNKNOWN;
  try {
    const body = (await res.json()) as { scopes?: string[] };
    const scopes = body.scopes ?? [];
    return {
      liveness: "live",
      detail: { scopes, write: scopes.some((s) => /send|create|update|delete/.test(s)) },
    };
  } catch {
    return { liveness: "live" };
  }
}

/** GitLab: /user is the token identity endpoint. */
async function gitlab(secret: string): Promise<ValidationResult> {
  const res = await get("https://gitlab.com/api/v4/user", { "PRIVATE-TOKEN": secret });
  if (!res) return UNKNOWN;
  if (res.status === 401) return DEAD;
  if (!res.ok) return UNKNOWN;
  try {
    const body = (await res.json()) as { username?: string };
    return { liveness: "live", detail: { identity: body.username, write: true } };
  } catch {
    return { liveness: "live" };
  }
}

/** npm: whoami resolves the token to an account and publishes nothing. */
async function npmToken(secret: string): Promise<ValidationResult> {
  const res = await get("https://registry.npmjs.org/-/whoami", {
    Authorization: `Bearer ${secret}`,
  });
  if (!res) return UNKNOWN;
  if (res.status === 401 || res.status === 403) return DEAD;
  if (!res.ok) return UNKNOWN;
  try {
    const body = (await res.json()) as { username?: string };
    return { liveness: "live", detail: { identity: body.username, write: true } };
  } catch {
    return { liveness: "live" };
  }
}

/** JWTs are self-describing: expiry is in the payload, no network call needed. */
function jwt(secret: string): ValidationResult {
  try {
    const payload = JSON.parse(Buffer.from(secret.split(".")[1], "base64url").toString("utf8")) as {
      exp?: number;
      iss?: string;
      sub?: string;
      email?: string;
      role?: string;
    };
    if (typeof payload.exp === "number") {
      if (payload.exp * 1000 < Date.now()) return { liveness: "dead", detail: { note: "expired" } };
      const days = Math.round((payload.exp * 1000 - Date.now()) / 86_400_000);
      return {
        liveness: "live",
        detail: {
          identity: payload.email ?? payload.sub ?? payload.iss,
          note: `valid for ${days} more day${days === 1 ? "" : "s"}`,
          write: payload.role ? /admin|service|write/i.test(payload.role) : undefined,
        },
      };
    }
    // No exp claim means it never expires on its own.
    return {
      liveness: "unknown",
      detail: { identity: payload.email ?? payload.sub, note: "no expiry claim — cannot verify signature" },
    };
  } catch {
    return UNKNOWN;
  }
}

const PROBES: Record<string, (secret: string, secondary?: string) => Promise<ValidationResult> | ValidationResult> = {
  github,
  openai,
  anthropic,
  aws,
  stripe,
  slack,
  google,
  sendgrid,
  gitlab,
  npm: npmToken,
  jwt,
};

/** Providers with no safe read-only probe are honestly reported as unknown. */
export function isValidatable(provider: string): boolean {
  return provider in PROBES;
}

export async function validateSecret(
  provider: string,
  secret: string,
  secondary?: string,
): Promise<ValidationResult> {
  const probe = PROBES[provider];
  if (!probe) return UNKNOWN;
  try {
    return await probe(secret, secondary);
  } catch {
    return UNKNOWN;
  }
}

/** Validate a batch in parallel, bounded so we do not open 200 sockets at once. */
export async function validateAll<T extends { provider: string }>(
  items: T[],
  secretOf: (item: T) => string,
  secondaryOf: (item: T) => string | undefined,
  onResult: (item: T, result: ValidationResult) => void,
  concurrency = 12,
): Promise<void> {
  const queue = [...items];
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    for (;;) {
      const item = queue.shift();
      if (!item) return;
      const result = await validateSecret(item.provider, secretOf(item), secondaryOf(item));
      onResult(item, result);
    }
  });
  await Promise.all(workers);
}
