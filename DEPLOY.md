# Deploying RepoHunter

RepoHunter walks git history with git plumbing: `git clone --mirror`,
`git log --all --raw`, `git cat-file --batch`. That means the host must provide

  1. a real `git` binary on PATH,
  2. a writable temp directory,
  3. a request timeout long enough for a full scan (~8s typical, 300s cap).

## This rules out Lambda-style serverless

Vercel's Node.js functions, AWS Lambda and Cloudflare Workers ship no `git`
binary and mount a read-only filesystem. The build succeeds there — it is a
normal Next.js build — but every scan fails at the preflight in `lib/walk.ts`
with a message saying exactly this. That is deliberate: a clear refusal beats a
bare ENOENT.

## Use a container host

Any of Render, Railway, Fly.io, Google Cloud Run, or a plain VM:

    docker build -t repohunter .
    docker run -p 3000:3000 repohunter

The image installs `git` in the runner stage and runs the Next standalone
server. `output: "standalone"` is gated behind `DOCKER_BUILD=1` so a default
`npm run build` is unchanged for hosts that do their own packaging.

## Local

    npm install && npm run dev
