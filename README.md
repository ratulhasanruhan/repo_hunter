# RepoHunter

Paste a public GitHub URL. RepoHunter finds every credential ever committed to
that repo's history, checks which ones still work, and shows how long each has
been exposed.

**Live:** https://repohunter.onrender.com

No AI in the scan path. Regex, entropy, and a git walk — deterministic, fast,
and defensible. Every finding traces back to a commit hash.

---

## What it's for

`gitleaks` and `trufflehog` already scan git history, and they're good at it.
The gap they leave is everything that happens *after* the match:

| Question | Typical scanner | RepoHunter |
|---|---|---|
| Does this string look like a secret? | yes | yes |
| **Does it still work?** | rarely | probes a read-only endpoint per provider |
| **How long has it been public?** | no | days since the first commit that introduced it |
| **Which of these 300 hits matter?** | flat list | ranked, three tiers, dead ones collapsed |
| **Will deleting the file help?** | no | checks forks — if any exist, rewriting is futile |

The practical difference: a flat list of 300 matches gets ignored. "This key is
live, has full write scope, and has been public for 412 days" gets acted on.

Two details do most of the work:

- **It scans history, not HEAD.** The dangerous secrets are the ones somebody
  already deleted — deleting a file removes it from your working tree and leaves
  it in history forever.
- **It dedupes by secret value.** One key committed 40 times is *one* finding
  with 40 occurrences, not 40 rows. Without this the output is unreadable.

---

## Using it

Paste any public GitHub repo URL and press **Scan history**. You'll get:

- **Findings**, ranked by danger and grouped into three tiers — *live and
  dangerous*, *live but low scope*, and *dead or unverifiable*. The third group
  is collapsed by default, because most findings land there and hiding them is
  what makes the rest readable.
- Per finding: provider, masked value, live status with real scopes, **days
  exposed**, an estimated cost of abuse, first commit and author, occurrence
  count, and whether the file still exists at HEAD.
- **A timeline** — each secret as a mark from its first commit to today, or to
  the commit that removed it, coloured by live status.
- **A fix kit** — per-provider rotation steps, a `git filter-repo` command
  scoped to the exact paths found, a `.gitignore`, and a pre-commit hook.
- **Extras** — non-credential recon leaks (internal hostnames, private IPs,
  connection strings), a dependency check against the OSV advisory database,
  and findings grouped by author.

Press <kbd>C</kbd> to reload the last result if the network drops mid-demo.

### Limits

Repos over **500 MB** or **20,000 commits** are declined before cloning, with a
message saying so. A scan that hangs is worse than one that declines. Blobs over
1 MB are skipped as bundles or datasets, not hand-written secrets.

Wordlist and dataset repos are the wrong target — their contents are
credential-shaped on purpose, so every match is a false positive.

Results are held in memory for one hour and then dropped. There's no database,
no accounts, and no scanning of private repos.

---

## Running it yourself

Needs **Node 22+** and a **git binary** on PATH.

```bash
npm install
npm run dev          # http://localhost:3000
```

Or as a container, which is how it's deployed:

```bash
docker build -t repohunter .
docker run -p 3000:3000 repohunter
```

> **Host requirement:** the scan shells out to `git clone --mirror`,
> `git log --raw` and `git cat-file --batch`, so it needs a real git binary and
> a writable temp directory. That rules out Lambda-style serverless hosts —
> Vercel's Node runtime has no git and the app will refuse to scan there. Use a
> container host (Render, Railway, Fly, Cloud Run) or a VM. See
> [DEPLOY.md](DEPLOY.md).

---

## How it works

1. **Mirror clone** — `git clone --mirror` fetches every ref, including branches
   whose secrets were "deleted".
2. **Index** — one pass of `git log --all --reverse --raw` builds a map from blob
   SHA to every commit and path that content appeared at. Identical content
   committed repeatedly collapses to a single blob here, which is where most of
   the speed comes from.
3. **Read** — one `git cat-file --batch` process streams each unique blob's bytes
   exactly once. Binary blobs are skipped on a NUL-byte check.
4. **Match** — prefixed provider patterns first (`ghp_`, `AKIA`, `sk-ant-`, …),
   then high-entropy generic strings, which are only reported when at least two
   independent signals corroborate them.
5. **Dedupe** — findings are keyed by SHA-256 of the secret value.
6. **Validate** — each unique secret is probed in parallel against a read-only
   endpoint. Streamed over SSE so results arrive after the findings they belong
   to and never block the render.
7. **Score** — `liveness × scope power × exposure days × public multiplier`.

Measured: 4,316 commits in ~11s on Render's free tier, ~8s locally.

### Validation

Read-only probes are implemented for **GitHub, AWS, OpenAI, Anthropic, Stripe,
Slack, Google, SendGrid, GitLab, npm**, and JWTs are decoded locally for their
expiry claim.

Every probe is side-effect-free — token metadata, STS `GetCallerIdentity`,
balance retrieval, `auth.test`, model listing. Nothing creates, charges, sends,
or deletes anything, because these are someone else's credentials. Probes time
out at 3 seconds, and `unknown` is a legitimate result: a network failure is not
evidence that a key is dead.

---

## Handling secrets

These are enforced in code, not left to discipline:

- Secrets are masked to **first four and last four characters** at the moment of
  detection, so no full value reaches the client, the cache, or a screenshot.
- No secret value is written to disk, to a log, or to the scan cache.
- Validation holds a value in memory only for the duration of its probe.
- Clones are removed from the temp directory when the scan finishes.
