/**
 * Findings do not fix anything. These are the artifacts that do.
 *
 * The rotation steps deliberately spell out the ordering people get wrong:
 * you create the replacement and cut consumers over BEFORE you revoke the old
 * credential, or you take an outage. And deleting the file from the repo
 * rotates nothing at all — the credential is still valid, it is just harder for
 * you to find than it is for the person who already cloned you.
 */
import type { Finding, RepoMeta } from "./types";

export interface RotationGuide {
  provider: string;
  console: string;
  steps: string[];
}

const ROTATION: Record<string, RotationGuide> = {
  aws: {
    provider: "AWS",
    console: "https://console.aws.amazon.com/iam/home#/users",
    steps: [
      "IAM → Users → the user this key belongs to → Security credentials.",
      "Create a second access key. IAM allows two active keys per user precisely so you can rotate without downtime.",
      "Deploy the new key to every consumer: CI secrets, task definitions, Lambda env, developer machines.",
      "Set the OLD key to Inactive — do not delete yet. If something breaks you can flip it back in seconds.",
      "Wait one full deploy cycle, then check the old key's 'Last used' timestamp in IAM.",
      "Once 'Last used' stops moving, delete the old key.",
      "Review CloudTrail for the exposure window. A key public for months should be assumed used: look for CreateUser, RunInstances, and GetObject from unfamiliar IPs.",
    ],
  },
  github: {
    provider: "GitHub",
    console: "https://github.com/settings/tokens",
    steps: [
      "Settings → Developer settings → Personal access tokens. Find the token by its last-used date.",
      "Create a replacement with the narrowest scopes that actually work — most leaked tokens have far more scope than the job needs.",
      "Update consumers (Actions secrets, CI, local git credential helper), then delete the old token.",
      "Check Settings → Sessions and the security log for access you do not recognise.",
      "If the token had `repo` scope on org repos, tell the org owner. It could read every private repo you can.",
    ],
  },
  openai: {
    provider: "OpenAI",
    console: "https://platform.openai.com/api-keys",
    steps: [
      "Create a new secret key, deploy it, then revoke the old one from the same page.",
      "Check Usage for spend that is not yours — a leaked key is usually found by a billing alert, not a scanner.",
      "Set a hard monthly spend cap under Billing → Limits. An uncapped key is the expensive failure mode.",
    ],
  },
  anthropic: {
    provider: "Anthropic",
    console: "https://console.anthropic.com/settings/keys",
    steps: [
      "Console → API keys → create a replacement, deploy it, then delete the exposed key.",
      "Review Usage for the exposure window.",
      "Set a spend limit on the workspace so the next leak is bounded.",
    ],
  },
  stripe: {
    provider: "Stripe",
    console: "https://dashboard.stripe.com/apikeys",
    steps: [
      "Developers → API keys → Roll key. Stripe supports a grace period; set it to an hour rather than immediate.",
      "Deploy the new key everywhere before the grace period ends.",
      "Review Payments and Payouts for the exposure window. A live secret key can move money.",
      "If the key was `sk_live_`, contact Stripe support and tell them it was public — they can advise on chargeback exposure.",
    ],
  },
  slack: {
    provider: "Slack",
    console: "https://api.slack.com/apps",
    steps: [
      "api.slack.com/apps → the app → OAuth & Permissions → Revoke the token.",
      "Reinstall the app to mint a fresh token, then update your deployment.",
      "Check the workspace audit log (Enterprise) or channel history for messages you did not send.",
    ],
  },
  google: {
    provider: "Google Cloud",
    console: "https://console.cloud.google.com/apis/credentials",
    steps: [
      "APIs & Services → Credentials → create a replacement key.",
      "Add an application restriction (HTTP referrer or IP) and an API restriction to the new key. An unrestricted API key is the reason this one mattered.",
      "Deploy, then delete the exposed key.",
      "Check billing for anomalous quota consumption during the exposure window.",
    ],
  },
  sendgrid: {
    provider: "SendGrid",
    console: "https://app.sendgrid.com/settings/api_keys",
    steps: [
      "Settings → API Keys → create a replacement with restricted access, not Full Access.",
      "Deploy, then delete the exposed key.",
      "Check Activity Feed for mail you did not send. A leaked sending key is a phishing platform with your domain's reputation attached.",
      "Verify your SPF/DKIM records are still yours.",
    ],
  },
  gitlab: {
    provider: "GitLab",
    console: "https://gitlab.com/-/user_settings/personal_access_tokens",
    steps: [
      "User settings → Access tokens → revoke the exposed token.",
      "Create a replacement with the minimum scopes, then update CI variables.",
      "Check the audit events for the exposure window.",
    ],
  },
  npm: {
    provider: "npm",
    console: "https://www.npmjs.com/settings/~/tokens",
    steps: [
      "Revoke the token immediately — publish rights are a supply-chain compromise, not just an account one.",
      "Check every package you own for versions you did not publish. `npm view <pkg> time` lists publish timestamps.",
      "Create a replacement as a granular access token scoped to specific packages, and enable 2FA for publishing.",
    ],
  },
  twilio: {
    provider: "Twilio",
    console: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
    steps: [
      "Create a new API key, deploy, then delete the exposed one.",
      "Check the usage log for outbound SMS or voice you did not initiate — toll fraud is the standard abuse of a leaked Twilio key.",
      "Set a usage trigger so the next one is caught in hours instead of months.",
    ],
  },
  pem: {
    provider: "Private key",
    console: "",
    steps: [
      "Treat the key as compromised permanently. There is no rotation that un-publishes a private key.",
      "Generate a new keypair and deploy the new public key to every host or service that trusted the old one.",
      "Remove the old public key from `authorized_keys`, the CA, or the certificate that referenced it.",
      "If this was a TLS key, reissue the certificate and revoke the old one — anyone with this key can decrypt captured traffic and impersonate the host.",
    ],
  },
  database: {
    provider: "Database",
    console: "",
    steps: [
      "Change the password for that database user now. A connection string is a full credential, not a hint.",
      "Update every consumer's configuration, then confirm the old password fails.",
      "Check whether the host is reachable from the public internet. If it is, that is the more urgent finding.",
      "Review connection and query logs for the exposure window.",
    ],
  },
  jwt: {
    provider: "JWT",
    console: "",
    steps: [
      "Invalidate the session server-side if your issuer supports revocation; otherwise it stays valid until `exp`.",
      "If this token was signed with a shared secret that also leaked, rotate the signing secret — that invalidates every token you ever issued, so plan the cutover.",
      "Shorten token lifetimes. A token with a long expiry is a long-lived credential wearing a short-lived costume.",
    ],
  },
};

const GENERIC: RotationGuide = {
  provider: "Generic",
  console: "",
  steps: [
    "Identify the system this credential authenticates to.",
    "Create a replacement credential and deploy it to every consumer.",
    "Revoke the exposed credential only after the replacement is confirmed working.",
    "Review that system's access logs for the full exposure window.",
  ],
};

export function rotationFor(provider: string): RotationGuide {
  return ROTATION[provider] ?? GENERIC;
}

/**
 * A `git filter-repo` invocation scoped to exactly the paths we found.
 * Deliberately verbose about the consequences: this rewrites every commit hash
 * after the first touched commit, which breaks every existing clone, every open
 * PR, and every hash anyone has written down.
 */
export function filterRepoCommand(findings: Finding[], meta: RepoMeta): string {
  const paths = [...new Set(findings.flatMap((f) => f.paths))].sort();
  if (!paths.length) return "";
  const args = paths.map((p) => `  --path '${p.replace(/'/g, "'\\''")}' \\`).join("\n");
  return `# Rewrites history. Every existing clone of ${meta.owner}/${meta.name} becomes incompatible.
# Do this AFTER rotating the credentials, never instead of it.

git clone --mirror https://github.com/${meta.owner}/${meta.name}.git ${meta.name}-rewrite.git
cd ${meta.name}-rewrite.git

git filter-repo \\
${args}
  --invert-paths

# Inspect the result before you push. This is not reversible on the remote.
git log --oneline | head

git push --force --mirror origin

# Then tell every collaborator to re-clone. Their existing clones still contain
# the secrets and will re-introduce them on the next push if they do not.`;
}

/** A .gitignore covering the file types that actually leaked here. */
export function gitignoreFor(findings: Finding[]): string {
  const paths = findings.flatMap((f) => f.paths);
  const rules = new Set<string>();
  for (const p of paths) {
    const base = p.split("/").pop() ?? p;
    const ext = base.includes(".") ? base.slice(base.lastIndexOf(".")) : "";
    if (/^\.env/.test(base)) {
      rules.add(".env");
      rules.add(".env.*");
      rules.add("!.env.example");
    } else if ([".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"].includes(ext)) {
      rules.add(`*${ext}`);
    } else if (base === "credentials" || base === "secrets.json" || /secret/i.test(base)) {
      rules.add(base);
    } else if (ext) {
      // Do not blanket-ignore .yml or .ts — ignore the specific file that leaked.
      rules.add(p);
    }
  }
  const always = [
    "# Always",
    ".env",
    ".env.*",
    "!.env.example",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    ".aws/credentials",
    ".npmrc",
    "secrets.json",
    "credentials.json",
    "service-account*.json",
  ];
  const specific = [...rules].filter((r) => !always.includes(r)).sort();
  return [
    ...always,
    ...(specific.length ? ["", "# Files that leaked in this repository's history"] : []),
    ...specific,
    "",
  ].join("\n");
}

/**
 * A pre-commit hook. This is the artifact that turns a one-time report into
 * something that stays installed, so it only checks staged content and it exits
 * fast enough that people do not disable it.
 */
export function preCommitHook(): string {
  return String.raw`#!/bin/sh
# RepoHunter pre-commit hook — blocks the next leak.
#
# Install:  cp this to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Bypass (only when you are certain):  git commit --no-verify
#
# Checks staged content only, with one grep pass per file. Hooks get disabled
# when they are slow, so this one keeps to a single grep pass per staged file.

set -eu

files=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$files" ] && exit 0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# Prefixed vendor patterns only. These have near-zero false positives, which is
# what makes failing the commit outright the right call.
cat > "$tmp/patterns" <<'PATTERNS'
sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}
sk-ant-(api03|admin01)-[A-Za-z0-9_-]{80,}
gh[pousr]_[A-Za-z0-9]{36}
github_pat_[A-Za-z0-9_]{60,}
(AKIA|ASIA)[0-9A-Z]{16}
(sk|rk)_live_[A-Za-z0-9]{20,}
xox[baprs]-[A-Za-z0-9-]{10,}
AIza[0-9A-Za-z_-]{35}
SG.[A-Za-z0-9_-]{16,}.[A-Za-z0-9_-]{16,}
glpat-[A-Za-z0-9_-]{20,}
npm_[A-Za-z0-9]{36}
GOCSPX-[A-Za-z0-9_-]{28}
-----BEGIN [A-Z ]*PRIVATE KEY-----
(postgres|postgresql|mysql|mongodb|mongodb+srv|redis)://[^[:space:]:@/]+:[^[:space:]:@/]{4,}@
PATTERNS

found=0

for f in $files; do
  # Skip what the scanner skips: vendored trees, lockfiles, bundles, binaries.
  case "$f" in
    node_modules/*|*/node_modules/*|vendor/*|*/vendor/*) continue ;;
    *.lock|*-lock.json|*.min.js|*.min.css|*.map) continue ;;
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip|*.gz|*.woff|*.woff2) continue ;;
  esac

  # Read the staged blob once. Cap at 1MB — larger files are generated, not written.
  git show ":$f" 2>/dev/null | head -c 1048576 > "$tmp/blob" || continue
  grep -Iq . "$tmp/blob" 2>/dev/null || continue   # binary

  hit=$(grep -nEf "$tmp/patterns" "$tmp/blob" 2>/dev/null | head -1 | cut -d: -f1 || true)
  if [ -n "$hit" ]; then
    # Report where, never what. Printing the match would leak it to the terminal
    # scrollback, the CI log, and anyone watching the screen share.
    printf '  %s:%s  matches a credential pattern
' "$f" "$hit" >&2
    found=1
  fi
done

if [ "$found" -ne 0 ]; then
  cat >&2 <<'MSG'

Commit blocked: staged content matches a known credential pattern.

If it is a real credential: remove it and rotate it. It may already be in your
reflog or a stash, so removing the line is not enough on its own.

If it is a placeholder: make it look like one (sk-example-..., xxxx, changeme).

To override: git commit --no-verify

MSG
  exit 1
fi

exit 0
`;
}
