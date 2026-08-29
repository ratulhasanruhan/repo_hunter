/**
 * Git history traversal.
 *
 * Scanning HEAD is the wrong tool for this job: the interesting secrets are the
 * ones someone already deleted, which live on in history forever. So we mirror
 * the repo and walk every blob reachable from every ref.
 *
 * The walk is two passes over cheap plumbing rather than one pass over porcelain:
 *   1. `git log --all --raw` builds blob-sha -> [(commit, path, author, date)].
 *      Identical content committed forty times collapses to one blob here, which
 *      is where most of the speed comes from.
 *   2. `git cat-file --batch` streams the unique blobs' bytes once each.
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Occurrence } from "./types";

export const LIMITS = {
  /** Repo size from the GitHub API, in KB. */
  maxRepoKb: 500 * 1024,
  maxCommits: 20_000,
  /** Blobs above this are bundles, datasets or media — not hand-written secrets. */
  maxBlobBytes: 1024 * 1024,
  maxBlobs: 60_000,
  cloneTimeoutMs: 120_000,
};

export class ScanLimitError extends Error {}

function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd });
    let stdout = "";
    let stderr = "";
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          child.kill("SIGKILL");
          reject(new ScanLimitError(`\`${cmd} ${args[0]}\` exceeded ${opts.timeoutMs}ms`));
        }, opts.timeoutMs)
      : null;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? -1 });
    });
  });
}

/** Undo git's C-style quoting of non-ASCII / special paths in --raw output. */
function unquotePath(p: string): string {
  if (!p.startsWith('"')) return p;
  const body = p.slice(1, -1);
  const bytes: number[] = [];
  for (let i = 0; i < body.length; i++) {
    if (body[i] !== "\\") {
      bytes.push(body.charCodeAt(i));
      continue;
    }
    const n = body[++i];
    if (n >= "0" && n <= "7") {
      bytes.push(parseInt(body.slice(i, i + 3), 8));
      i += 2;
    } else {
      const map: Record<string, number> = { n: 10, t: 9, r: 13, '"': 34, "\\": 92 };
      bytes.push(map[n] ?? n.charCodeAt(0));
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

export interface HistoryIndex {
  /** blob sha -> every place that exact content was committed, oldest first. */
  blobs: Map<string, Occurrence[]>;
  commitCount: number;
  /** Blob shas present in the working tree at HEAD. */
  headBlobs: Set<string>;
  headPaths: Set<string>;
}

export async function mirrorClone(
  url: string,
  onProgress?: (msg: string) => void,
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "repohunter-"));
  const target = join(dir, "repo.git");
  onProgress?.("cloning");
  // --mirror gets every ref; without it, deleted branches (and their secrets) are invisible.
  const res = await run(
    "git",
    ["clone", "--mirror", "--quiet", url, target],
    { timeoutMs: LIMITS.cloneTimeoutMs },
  );
  if (res.code !== 0) {
    await rm(dir, { recursive: true, force: true });
    const reason = res.stderr.trim().split("\n").pop() ?? "unknown error";
    throw new Error(`Clone failed: ${reason}`);
  }
  return target;
}

export async function cleanup(repoDir: string): Promise<void> {
  await rm(join(repoDir, ".."), { recursive: true, force: true });
}

/**
 * Pass 1: build the blob -> occurrence index by streaming `git log --raw`.
 * `--reverse` means the first occurrence we record for a blob is genuinely the
 * first time it entered history, which is what "exposed for N days" measures.
 */
export function buildIndex(
  repoDir: string,
  onProgress?: (commits: number) => void,
): Promise<HistoryIndex> {
  return new Promise((resolve, reject) => {
    const blobs = new Map<string, Occurrence[]>();
    let commitCount = 0;
    let current: { commit: string; date: number; author: string; email: string } | null = null;

    const child = spawn(
      "git",
      [
        "log",
        "--all",
        "--reverse",
        "--no-renames",
        "--no-abbrev",
        "--raw",
        "--encoding=UTF-8",
        "--format=\x01%H\x1f%at\x1f%an\x1f%ae",
      ],
      { cwd: repoDir },
    );

    let buf = "";
    let failed: Error | null = null;

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.startsWith("\x01")) {
          const [commit, at, author, email] = line.slice(1).split("\x1f");
          current = { commit, date: Number(at), author, email: email ?? "" };
          commitCount++;
          if (commitCount > LIMITS.maxCommits) {
            failed = new ScanLimitError(
              `Repository exceeds the ${LIMITS.maxCommits.toLocaleString()}-commit limit.`,
            );
            child.kill("SIGKILL");
            return;
          }
          if (commitCount % 200 === 0) onProgress?.(commitCount);
        } else if (line.startsWith(":") && current) {
          // :<srcmode> <dstmode> <srcsha> <dstsha> <status>\t<path>
          const tab = line.indexOf("\t");
          if (tab === -1) continue;
          const fields = line.slice(1, tab).split(" ");
          const dstSha = fields[3];
          const status = fields[4] ?? "";
          if (!dstSha || /^0+$/.test(dstSha)) continue; // deletion — no new content
          if (status.startsWith("D")) continue;
          const path = unquotePath(line.slice(tab + 1));
          const occ: Occurrence = {
            commit: current.commit,
            date: current.date,
            author: current.author,
            authorEmail: current.email,
            path,
          };
          const list = blobs.get(dstSha);
          if (list) {
            // Same content at the same path in a later commit adds nothing.
            if (!list.some((o) => o.path === path && o.commit === occ.commit)) list.push(occ);
          } else {
            blobs.set(dstSha, [occ]);
          }
        }
      }
    });

    child.on("error", reject);
    child.on("close", async () => {
      if (failed) return reject(failed);
      onProgress?.(commitCount);
      try {
        const head = await headContents(repoDir);
        resolve({ blobs, commitCount, headBlobs: head.blobs, headPaths: head.paths });
      } catch (e) {
        reject(e);
      }
    });
  });
}

async function headContents(repoDir: string): Promise<{ blobs: Set<string>; paths: Set<string> }> {
  const blobs = new Set<string>();
  const paths = new Set<string>();
  const res = await run("git", ["ls-tree", "-r", "--full-tree", "HEAD"], { cwd: repoDir });
  if (res.code !== 0) return { blobs, paths };
  for (const line of res.stdout.split("\n")) {
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const sha = line.slice(0, tab).split(" ")[2];
    if (sha) blobs.add(sha);
    paths.add(unquotePath(line.slice(tab + 1)));
  }
  return { blobs, paths };
}

/** Sizes and types for a set of objects, so we can skip the big ones cheaply. */
export function batchCheck(repoDir: string, shas: string[]): Promise<Map<string, number>> {
  return new Promise((resolve, reject) => {
    const sizes = new Map<string, number>();
    const child = spawn("git", ["cat-file", "--batch-check"], { cwd: repoDir });
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (c: string) => {
      buf += c;
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const [sha, type, size] = buf.slice(0, nl).split(" ");
        buf = buf.slice(nl + 1);
        if (type === "blob") sizes.set(sha, Number(size));
      }
    });
    child.on("error", reject);
    child.on("close", () => resolve(sizes));
    child.stdin.end(shas.join("\n") + "\n");
  });
}

/**
 * Pass 2: stream the bytes of the selected blobs, one `cat-file` process for all
 * of them. The callback is synchronous on purpose — buffering every blob's
 * content into an array would defeat the point of streaming.
 */
export function readBlobs(
  repoDir: string,
  shas: string[],
  onBlob: (sha: string, content: string) => void,
  onProgress?: (done: number, bytes: number) => void,
): Promise<{ count: number; bytes: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["cat-file", "--batch"], { cwd: repoDir });
    let pending: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    // Header state: null = expecting "<sha> blob <size>\n", else collecting body.
    let header: { sha: string; size: number } | null = null;
    let done = 0;
    let bytes = 0;

    child.stdout.on("data", (chunk: Buffer) => {
      pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
      for (;;) {
        if (!header) {
          const nl = pending.indexOf(0x0a);
          if (nl === -1) return;
          const line = pending.subarray(0, nl).toString("utf8");
          pending = pending.subarray(nl + 1);
          const [sha, type, size] = line.split(" ");
          if (type !== "blob") {
            // "<sha> missing" or a non-blob; nothing follows, keep parsing.
            continue;
          }
          header = { sha, size: Number(size) };
        }
        // Body is exactly `size` bytes followed by a newline git appends.
        if (pending.length < header.size + 1) return;
        const body = pending.subarray(0, header.size);
        pending = pending.subarray(header.size + 1);
        bytes += header.size;
        done++;
        // A NUL in the first 8KB means binary: no readable secret to find.
        if (body.subarray(0, 8192).indexOf(0) === -1) {
          onBlob(header.sha, body.toString("utf8"));
        }
        if (done % 250 === 0) onProgress?.(done, bytes);
        header = null;
      }
    });

    child.on("error", reject);
    child.on("close", () => {
      onProgress?.(done, bytes);
      resolve({ count: done, bytes });
    });
    child.stdin.end(shas.join("\n") + "\n");
  });
}

/** Read one path at HEAD — used for manifest parsing in the dependency check. */
export async function readAtHead(repoDir: string, path: string): Promise<string | null> {
  const res = await run("git", ["show", `HEAD:${path}`], { cwd: repoDir });
  return res.code === 0 ? res.stdout : null;
}
