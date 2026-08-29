/**
 * Repo metadata, and the public-exposure question.
 *
 * Forks are the finding that most changes what the user should do. If the repo
 * is public and forked, rewriting history does not help — the fork still holds
 * every object you just rewrote away. The advice flips from "rewrite" to
 * "rotate now; rewriting is theatre".
 */
import { LIMITS, ScanLimitError } from "./walk";
import type { RepoMeta } from "./types";

export interface ParsedRepo {
  owner: string;
  name: string;
  cloneUrl: string;
}

export function parseRepoUrl(input: string): ParsedRepo {
  const raw = input.trim();
  const patterns = [
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s?#]+?)(?:\.git)?\/?(?:[?#].*)?$/i,
    /^git@github\.com:([^/\s]+)\/([^/\s]+?)(?:\.git)?$/i,
    /^([A-Za-z0-9][\w.-]*)\/([\w.-]+?)(?:\.git)?$/,
  ];
  for (const re of patterns) {
    const m = re.exec(raw);
    if (m) {
      const [, owner, name] = m;
      return { owner, name, cloneUrl: `https://github.com/${owner}/${name}.git` };
    }
  }
  throw new Error("Not a GitHub repository URL. Expected github.com/owner/repo.");
}

interface GhRepo {
  private: boolean;
  fork: boolean;
  forks_count: number;
  stargazers_count: number;
  size: number;
  default_branch: string;
  message?: string;
}

export async function fetchRepoMeta(repo: ParsedRepo): Promise<Omit<RepoMeta, "commits">> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "RepoHunter",
  };
  // Optional: raises the 60/hr anonymous rate limit. Never required.
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  let data: GhRepo | null = null;
  try {
    const res = await fetch(`https://api.github.com/repos/${repo.owner}/${repo.name}`, {
      headers,
      signal: AbortSignal.timeout(8000),
      cache: "no-store",
    });
    if (res.status === 404) {
      throw new Error(
        `${repo.owner}/${repo.name} not found. RepoHunter scans public repositories only.`,
      );
    }
    if (res.ok) data = (await res.json()) as GhRepo;
  } catch (e) {
    if (e instanceof Error && e.message.includes("not found")) throw e;
    // Rate-limited or offline: proceed without metadata rather than refusing to scan.
  }

  if (data && data.size > LIMITS.maxRepoKb) {
    throw new ScanLimitError(
      `${repo.owner}/${repo.name} is ${(data.size / 1024).toFixed(0)} MB. ` +
        `The limit is ${LIMITS.maxRepoKb / 1024} MB — a scan that hangs is worse than one that declines.`,
    );
  }

  const forks = data?.forks_count ?? 0;
  const isPublic = data ? !data.private : true;

  return {
    url: `https://github.com/${repo.owner}/${repo.name}`,
    owner: repo.owner,
    name: repo.name,
    isPublic,
    forks,
    stars: data?.stargazers_count ?? 0,
    sizeKb: data?.size ?? 0,
    defaultBranch: data?.default_branch ?? "main",
    rewriteIsFutile: isPublic && forks > 0,
  };
}
