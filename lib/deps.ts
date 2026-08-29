/**
 * Dependency check.
 *
 * The repo is already cloned, so parsing its manifests is nearly free. Versions
 * are checked against OSV.dev, which is a real advisory database with no API key
 * — a hardcoded list of "known bad versions" would go stale the week after the
 * demo and would not be defensible.
 */
import type { DependencyIssue } from "./types";
import { readAtHead } from "./walk";

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  severity?: { type: string; score: string }[];
}

const MANIFESTS = [
  "package.json",
  "requirements.txt",
  "go.mod",
  "Gemfile",
  "pyproject.toml",
] as const;

function cleanVersion(v: string): string | null {
  const m = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)/.exec(v);
  return m ? m[1] : null;
}

function parsePackageJson(text: string): OsvQuery[] {
  try {
    const json = JSON.parse(text) as Record<string, Record<string, string> | undefined>;
    const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
    return Object.entries(deps)
      .map(([name, range]) => {
        const version = cleanVersion(String(range));
        return version ? { package: { name, ecosystem: "npm" }, version } : null;
      })
      .filter((q): q is OsvQuery => q !== null);
  } catch {
    return [];
  }
}

function parseRequirements(text: string): OsvQuery[] {
  const out: OsvQuery[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;#]*)/.exec(line);
    if (m) out.push({ package: { name: m[1], ecosystem: "PyPI" }, version: m[2] });
  }
  return out;
}

function parseGoMod(text: string): OsvQuery[] {
  const out: OsvQuery[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*(?:require\s+)?([a-z0-9][\w.\-/]*\.[a-z]{2,}\/[\w.\-/]+)\s+v([0-9][\w.\-+]*)/i.exec(line);
    if (m && !line.includes("//") ) out.push({ package: { name: m[1], ecosystem: "Go" }, version: `v${m[2]}` });
  }
  return out;
}

function parseGemfile(text: string): OsvQuery[] {
  const out: OsvQuery[] = [];
  for (const line of text.split("\n")) {
    const m = /gem\s+["']([\w.-]+)["']\s*,\s*["'][~><=\s]*([0-9][\w.]*)["']/.exec(line);
    if (m) out.push({ package: { name: m[1], ecosystem: "RubyGems" }, version: m[2] });
  }
  return out;
}

function severityOf(v: OsvVuln): string {
  const ds = v.database_specific?.severity;
  if (ds) return ds.toUpperCase();
  const cvss = v.severity?.find((s) => s.type.startsWith("CVSS"));
  if (!cvss) return "UNKNOWN";
  const score = Number(/\/?(\d+\.\d+)$/.exec(cvss.score)?.[1] ?? NaN);
  if (Number.isNaN(score)) return "UNKNOWN";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MODERATE";
  return "LOW";
}

export async function checkDependencies(repoDir: string): Promise<DependencyIssue[]> {
  const queries: (OsvQuery & { manifest: string })[] = [];

  for (const manifest of MANIFESTS) {
    const text = await readAtHead(repoDir, manifest);
    if (!text) continue;
    let parsed: OsvQuery[] = [];
    if (manifest === "package.json") parsed = parsePackageJson(text);
    else if (manifest === "requirements.txt") parsed = parseRequirements(text);
    else if (manifest === "go.mod") parsed = parseGoMod(text);
    else if (manifest === "Gemfile") parsed = parseGemfile(text);
    for (const q of parsed) queries.push({ ...q, manifest });
  }

  if (!queries.length) return [];
  const capped = queries.slice(0, 500);

  try {
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: capped.map(({ package: p, version }) => ({ package: p, version })) }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return [];
    const body = (await res.json()) as { results: { vulns?: { id: string }[] }[] };

    const hits: DependencyIssue[] = [];
    const needDetail: string[] = [];
    body.results.forEach((r, i) => {
      if (!r.vulns?.length) return;
      const q = capped[i];
      hits.push({
        ecosystem: q.package.ecosystem,
        package: q.package.name,
        version: q.version,
        manifest: q.manifest,
        advisories: r.vulns.slice(0, 4).map((v) => ({ id: v.id, summary: "", severity: "UNKNOWN" })),
      });
      needDetail.push(...r.vulns.slice(0, 4).map((v) => v.id));
    });

    // querybatch returns ids only; fetch summaries for the ones we will show.
    const details = new Map<string, OsvVuln>();
    await Promise.all(
      [...new Set(needDetail)].slice(0, 40).map(async (id) => {
        try {
          const r = await fetch(`https://api.osv.dev/v1/vulns/${id}`, {
            signal: AbortSignal.timeout(6000),
          });
          if (r.ok) details.set(id, (await r.json()) as OsvVuln);
        } catch {
          /* a missing summary is not worth failing the scan over */
        }
      }),
    );

    for (const hit of hits) {
      for (const adv of hit.advisories) {
        const d = details.get(adv.id);
        if (d) {
          adv.summary = d.summary ?? d.details?.slice(0, 160) ?? "";
          adv.severity = severityOf(d);
        }
      }
    }

    const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, UNKNOWN: 4 };
    return hits.sort(
      (a, b) => (rank[a.advisories[0].severity] ?? 4) - (rank[b.advisories[0].severity] ?? 4),
    );
  } catch {
    return [];
  }
}
