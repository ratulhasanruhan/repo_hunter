"use client";

import { useMemo, useState } from "react";
import type { Finding, RepoMeta } from "@/lib/types";
import { filterRepoCommand, gitignoreFor, preCommitHook, rotationFor } from "@/lib/fixkit";

type Tab = "rotate" | "history" | "gitignore" | "hook";

export function FixKit({ findings, meta }: { findings: Finding[]; meta: RepoMeta }) {
  const [tab, setTab] = useState<Tab>("rotate");

  const actionable = useMemo(
    () => findings.filter((f) => f.liveness === "live" || f.liveness === "unknown"),
    [findings],
  );

  const providers = useMemo(() => {
    const seen = new Map<string, number>();
    for (const f of actionable) seen.set(f.provider, (seen.get(f.provider) ?? 0) + 1);
    return [...seen.entries()].sort((a, b) => b[1] - a[1]);
  }, [actionable]);

  const filterCmd = useMemo(() => filterRepoCommand(actionable, meta), [actionable, meta]);
  const ignore = useMemo(() => gitignoreFor(actionable), [actionable]);
  const hook = useMemo(() => preCommitHook(), []);

  return (
    <div>
      <div className="tabs" role="tablist">
        {(
          [
            ["rotate", "Rotation steps"],
            ["history", "Rewrite history"],
            ["gitignore", ".gitignore"],
            ["hook", "Pre-commit hook"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "rotate" && (
        <div style={{ marginTop: 18 }}>
          {providers.length === 0 ? (
            <p className="empty">Nothing to rotate. Every finding is already revoked.</p>
          ) : (
            providers.map(([provider, count]) => {
              const guide = rotationFor(provider);
              return (
                <div key={provider} className="callout" style={{ marginTop: 12 }}>
                  <h3>
                    {guide.provider} — {count} credential{count === 1 ? "" : "s"}
                  </h3>
                  <ol
                    style={{
                      margin: "10px 0 0",
                      paddingLeft: 18,
                      color: "var(--muted)",
                      display: "grid",
                      gap: 6,
                      fontSize: 12.5,
                    }}
                  >
                    {guide.steps.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ol>
                </div>
              );
            })
          )}
        </div>
      )}

      {tab === "history" && (
        <div style={{ marginTop: 18 }}>
          {meta.rewriteIsFutile && (
            <div className="callout urgent">
              <h3>Rewriting will not help here</h3>
              <p>
                {meta.owner}/{meta.name} is public and has {meta.forks.toLocaleString()}{" "}
                fork{meta.forks === 1 ? "" : "s"}. Each fork holds its own copy of every object you
                would rewrite away, and GitHub keeps forked objects reachable through the fork
                network even after the original is gone.
              </p>
              <p>
                Rotate the credentials. Treat the rewrite below as tidying, not as remediation —
                the exposure ended when you rotated, not when you rewrote.
              </p>
            </div>
          )}
          {filterCmd ? (
            <CodeBlock code={filterCmd} />
          ) : (
            <p className="empty">No paths to rewrite.</p>
          )}
        </div>
      )}

      {tab === "gitignore" && (
        <div style={{ marginTop: 18 }}>
          <p className="section-note">
            Append to <code>.gitignore</code>. Covers the file types that leaked here, plus the
            usual suspects.
          </p>
          <CodeBlock code={ignore} />
        </div>
      )}

      {tab === "hook" && (
        <div style={{ marginTop: 18 }}>
          <p className="section-note">
            Save as <code>.git/hooks/pre-commit</code> and <code>chmod +x</code> it. It checks only
            staged content, at roughly 13ms per file — hooks like this get disabled when they are
            slow, so this one does a single grep pass per file rather than one per pattern.
          </p>
          <CodeBlock code={hook} />
        </div>
      )}
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="code-block">
      <button
        className="copy"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 1400);
          } catch {
            setCopied(false);
          }
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
      <pre>{code}</pre>
    </div>
  );
}
