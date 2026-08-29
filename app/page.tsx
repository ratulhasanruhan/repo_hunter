"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ScanInput } from "@/components/ScanInput";
import { Progress } from "@/components/Progress";
import { FindingRow } from "@/components/FindingRow";
import { Timeline } from "@/components/Timeline";
import { FixKit } from "@/components/FixKit";
import { sortFindings, TIER_LABEL, TIER_NOTE } from "@/lib/score";
import type {
  AuthorCluster,
  DependencyIssue,
  Finding,
  ReconFinding,
  RepoMeta,
  ScanResult,
  Tier,
} from "@/lib/types";

type ScanEvent =
  | { type: "phase"; phase: string; message: string }
  | { type: "progress"; commits: number; blobs: number; bytes: number }
  | { type: "meta"; meta: RepoMeta }
  | { type: "findings"; findings: Finding[]; recon: ReconFinding[]; authors: AuthorCluster[] }
  | { type: "validated"; id: string; finding: Finding }
  | { type: "dependencies"; dependencies: DependencyIssue[] }
  | { type: "done"; scanId: string; stats: ScanResult["stats"] }
  | { type: "error"; message: string };

const CACHE_KEY = "repohunter:last-scan";

interface State {
  busy: boolean;
  phase: string;
  commits: number;
  blobs: number;
  bytes: number;
  meta: RepoMeta | null;
  findings: Finding[];
  recon: ReconFinding[];
  authors: AuthorCluster[];
  dependencies: DependencyIssue[];
  stats: ScanResult["stats"] | null;
  error: string | null;
  started: boolean;
}

const EMPTY: State = {
  busy: false,
  phase: "",
  commits: 0,
  blobs: 0,
  bytes: 0,
  meta: null,
  findings: [],
  recon: [],
  authors: [],
  dependencies: [],
  stats: null,
  error: null,
  started: false,
};

export default function Page() {
  const [s, setS] = useState<State>(EMPTY);
  const [showDead, setShowDead] = useState(false);
  const [hasCache, setHasCache] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    try {
      setHasCache(Boolean(localStorage.getItem(CACHE_KEY)));
    } catch {
      setHasCache(false);
    }
    return () => sourceRef.current?.close();
  }, []);

  const loadCached = useCallback(() => {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      if (!raw) return;
      const cached = JSON.parse(raw) as ScanResult;
      setS({
        ...EMPTY,
        started: true,
        meta: cached.meta,
        findings: cached.findings,
        recon: cached.recon,
        authors: cached.authors,
        dependencies: cached.dependencies,
        stats: cached.stats,
        phase: "Loaded from cache",
      });
    } catch {
      /* a corrupt cache is not worth an error state */
    }
  }, []);

  // Section 14: keep one cached result loadable by keypress, in case the
  // network drops mid-demo.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA)$/.test(target.tagName)) return;
      if (e.key === "c" || e.key === "C") loadCached();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [loadCached]);

  const scan = useCallback((url: string) => {
    sourceRef.current?.close();
    setS({ ...EMPTY, busy: true, started: true, phase: "Starting" });
    setShowDead(false);

    const es = new EventSource(`/api/scan?url=${encodeURIComponent(url)}`);
    sourceRef.current = es;

    es.onmessage = (msg) => {
      const ev = JSON.parse(msg.data) as ScanEvent;
      setS((prev) => {
        switch (ev.type) {
          case "phase":
            return { ...prev, phase: ev.message };
          case "progress":
            return { ...prev, commits: ev.commits, blobs: ev.blobs || prev.blobs, bytes: ev.bytes || prev.bytes };
          case "meta":
            return { ...prev, meta: ev.meta, commits: ev.meta.commits };
          case "findings":
            return { ...prev, findings: ev.findings, recon: ev.recon, authors: ev.authors };
          case "validated":
            return {
              ...prev,
              findings: sortFindings(
                prev.findings.map((f) => (f.id === ev.id ? ev.finding : f)),
              ),
            };
          case "dependencies":
            return { ...prev, dependencies: ev.dependencies };
          case "done":
            return { ...prev, busy: false, stats: ev.stats, phase: "Complete" };
          case "error":
            return { ...prev, busy: false, error: ev.message };
          default:
            return prev;
        }
      });
      if (ev.type === "done" || ev.type === "error") es.close();
    };

    es.onerror = () => {
      es.close();
      setS((prev) =>
        prev.stats || prev.error
          ? { ...prev, busy: false }
          : { ...prev, busy: false, error: "Connection to the scanner was lost." },
      );
    };
  }, []);

  // Cache the completed result. Every value in it is already masked.
  useEffect(() => {
    if (!s.stats || !s.meta) return;
    try {
      localStorage.setItem(
        CACHE_KEY,
        JSON.stringify({
          id: "cached",
          meta: s.meta,
          findings: s.findings,
          recon: s.recon,
          authors: s.authors,
          dependencies: s.dependencies,
          stats: s.stats,
          createdAt: Date.now(),
        } satisfies ScanResult),
      );
      setHasCache(true);
    } catch {
      /* quota or private mode — the cache is a convenience, not a requirement */
    }
  }, [s.stats, s.meta, s.findings, s.recon, s.authors, s.dependencies]);

  const tiers: Tier[] = ["live-dangerous", "live-low", "dead"];
  const byTier = (t: Tier) => s.findings.filter((f) => f.tier === t);
  const liveCount = s.findings.filter((f) => f.liveness === "live").length;
  const complete = Boolean(s.stats) || s.phase === "Loaded from cache";

  return (
    <main className="shell">
      <header className="masthead">
        <h1 className="wordmark">
          Repo<span>Hunter</span>
        </h1>
        <p>
          Every credential ever committed to a repository&rsquo;s history, which ones still work,
          and how long each has been public.
        </p>
      </header>

      <ScanInput onScan={scan} busy={s.busy} />

      {hasCache && !s.started && (
        <p className="samples" style={{ marginTop: 8 }}>
          Press <kbd>C</kbd> to reload the last scan result.
        </p>
      )}

      {s.busy && (
        <Progress
          phase={s.phase}
          commits={s.commits}
          blobs={s.blobs}
          bytes={s.bytes}
          findings={s.findings.length}
        />
      )}

      {s.error && (
        <div className="error">
          <b>Scan stopped.</b> {s.error}
        </div>
      )}

      {complete && s.meta && (
        <>
          <section className="verdict">
            <p className={`verdict-count ${liveCount > 0 ? "has-live" : ""}`}>
              {liveCount > 0 ? liveCount : s.findings.length}
            </p>
            <p className="verdict-line">
              {liveCount > 0 ? (
                <>
                  credential{liveCount === 1 ? "" : "s"} in{" "}
                  <span className="mono">
                    {s.meta.owner}/{s.meta.name}
                  </span>{" "}
                  still validate against their provider. The oldest has been public for{" "}
                  <span className="mono">
                    {Math.max(
                      ...s.findings.filter((f) => f.liveness === "live").map((f) => f.exposureDays),
                    ).toLocaleString()}
                  </span>{" "}
                  days.
                </>
              ) : s.findings.length > 0 ? (
                <>
                  secret-shaped strings in{" "}
                  <span className="mono">
                    {s.meta.owner}/{s.meta.name}
                  </span>
                  . None of them still validate.
                </>
              ) : (
                <>
                  No credentials found in{" "}
                  <span className="mono">
                    {s.meta.owner}/{s.meta.name}
                  </span>
                  &rsquo;s history.
                </>
              )}
            </p>
            <p className="verdict-meta">
              <span>{s.meta.commits.toLocaleString()} commits</span>
              <span>{s.stats?.blobs.toLocaleString() ?? "—"} blobs</span>
              <span>{s.meta.isPublic ? "public" : "private"}</span>
              <span>{s.meta.forks.toLocaleString()} forks</span>
              {s.stats && <span>{(s.stats.durationMs / 1000).toFixed(1)}s</span>}
            </p>
          </section>

          {s.meta.rewriteIsFutile && liveCount > 0 && (
            <div className="callout urgent" style={{ marginTop: 24 }}>
              <h3>Rewriting history will not undo this</h3>
              <p>
                This repository is public and has {s.meta.forks.toLocaleString()} fork
                {s.meta.forks === 1 ? "" : "s"}. Every fork keeps its own copy of the objects a
                rewrite would remove. Rotate the credentials first; the rewrite is housekeeping.
              </p>
            </div>
          )}

          {s.findings.length > 0 && (
            <section className="section">
              <div className="section-head">
                <h2>Exposure timeline</h2>
                <span className="count">{Math.min(s.findings.length, 26)} shown</span>
              </div>
              <p className="section-note">
                Each bar runs from the commit that introduced the secret to the last commit that
                still contained it. Where a bar stops but a dashed line continues, the file was
                deleted and the credential is still valid.
              </p>
              <Timeline findings={s.findings} />
            </section>
          )}

          {tiers.map((tier) => {
            const rows = byTier(tier);
            if (!rows.length) return null;
            const collapsed = tier === "dead" && !showDead;
            return (
              <section className={`section tier-${tier}`} key={tier}>
                <div className="section-head">
                  <h2>{TIER_LABEL[tier]}</h2>
                  <span className="count">{rows.length}</span>
                  {tier === "dead" && (
                    <button
                      className="copy"
                      style={{ position: "static", marginLeft: "auto" }}
                      onClick={() => setShowDead((v) => !v)}
                    >
                      {collapsed ? "Show" : "Hide"}
                    </button>
                  )}
                </div>
                <p className="section-note">{TIER_NOTE[tier]}</p>
                {!collapsed && rows.map((f) => <FindingRow key={f.id} finding={f} />)}
              </section>
            );
          })}

          {s.findings.length === 0 && (
            <p className="empty">
              No prefixed provider patterns and no corroborated high-entropy strings across the
              full history. That is a clean result, not an inconclusive one.
            </p>
          )}

          {s.findings.length > 0 && (
            <section className="section">
              <div className="section-head">
                <h2>Fix kit</h2>
              </div>
              <p className="section-note">
                Findings do not fix anything. These do.
              </p>
              <FixKit findings={s.findings} meta={s.meta} />
            </section>
          )}

          {s.recon.length > 0 && (
            <section className="section">
              <div className="section-head">
                <h2>Reconnaissance layer</h2>
                <span className="count">{s.recon.length}</span>
              </div>
              <p className="section-note">
                Not credentials. Internal hostnames, private ranges and addresses that describe your
                infrastructure to someone deciding where to point the credentials above.
              </p>
              <table className="table">
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Value</th>
                    <th>Seen</th>
                    <th>First path</th>
                  </tr>
                </thead>
                <tbody>
                  {s.recon.slice(0, 40).map((r) => (
                    <tr key={r.id}>
                      <td className="prose">{r.kind}</td>
                      <td>{r.value}</td>
                      <td>{r.count}</td>
                      <td style={{ color: "var(--muted)" }}>{r.paths[0]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {s.dependencies.length > 0 && (
            <section className="section">
              <div className="section-head">
                <h2>Dependency advisories</h2>
                <span className="count">{s.dependencies.length}</span>
              </div>
              <p className="section-note">
                Declared versions at HEAD, checked against OSV.dev. Ranges are resolved to their
                floor, so a caret range that has since been bumped may show here.
              </p>
              <table className="table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Severity</th>
                    <th>Advisory</th>
                  </tr>
                </thead>
                <tbody>
                  {s.dependencies.slice(0, 25).map((d) => (
                    <tr key={`${d.ecosystem}:${d.package}`}>
                      <td>{d.package}</td>
                      <td style={{ color: "var(--muted)" }}>{d.version}</td>
                      <td className={`sev ${d.advisories[0].severity}`}>
                        {d.advisories[0].severity}
                      </td>
                      <td className="prose">
                        {d.advisories[0].summary || d.advisories[0].id}
                        {d.advisories.length > 1 && ` (+${d.advisories.length - 1} more)`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {s.authors.length > 0 && (
            <section className="section">
              <div className="section-head">
                <h2>Where onboarding should focus</h2>
              </div>
              <p className="section-note">
                Findings grouped by the author of the commit that introduced them. A committed key
                is a tooling gap, not a character flaw — the fix is the pre-commit hook in the fix
                kit, applied to everyone, not a conversation with one person.
              </p>
              <table className="table">
                <thead>
                  <tr>
                    <th>Author</th>
                    <th>Findings</th>
                    <th>Still live</th>
                  </tr>
                </thead>
                <tbody>
                  {s.authors.map((a) => (
                    <tr key={a.email || a.author}>
                      <td>{a.author}</td>
                      <td>{a.findings}</td>
                      <td style={{ color: a.live ? "var(--warn)" : "var(--muted)" }}>{a.live}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </>
      )}

      <p className="footnote">
        Secrets are masked to their first and last four characters at the point of detection. Full
        values are never written to disk, to a log, or to this page. Validation uses read-only
        provider endpoints only — nothing is created, charged, sent, or deleted.
      </p>
    </main>
  );
}
