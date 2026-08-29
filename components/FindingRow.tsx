"use client";

import { useState } from "react";
import type { Finding } from "@/lib/types";
import { rotationFor } from "@/lib/fixkit";

const dateFmt = new Intl.DateTimeFormat("en-CA", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  timeZone: "UTC",
});

function fmtDate(unix: number): string {
  return dateFmt.format(new Date(unix * 1000));
}

function livenessBadge(f: Finding) {
  switch (f.liveness) {
    case "live":
      return <span className={`badge ${f.tier === "live-dangerous" ? "live" : "warn"}`}>Live</span>;
    case "dead":
      return <span className="badge">Revoked</span>;
    case "pending":
      return <span className="badge pending">Checking…</span>;
    default:
      return <span className="badge">Unverified</span>;
  }
}

export function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const f = finding;
  const rotation = rotationFor(f.provider);
  const isDead = f.tier === "dead";

  return (
    <div className={`finding ${f.tier} ${isDead ? "dead" : ""}`}>
      <button
        className="finding-head"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <i className="status-stripe" aria-hidden />
        <span>
          <span className="finding-title">
            <span className="finding-kind">{f.kind}</span>
            <span className="finding-masked mono">{f.masked}</span>
            {livenessBadge(f)}
            {f.liveAtHead && <span className="badge">Still at HEAD</span>}
            {f.detector === "entropy" && <span className="badge">Entropy match</span>}
          </span>
          <span className="finding-sub">
            <span>{f.paths[0]}</span>
            {f.paths.length > 1 && <span>+{f.paths.length - 1} more paths</span>}
            <span>
              {f.occurrences.length} commit{f.occurrences.length === 1 ? "" : "s"}
            </span>
            {f.validation?.identity && <span>{f.validation.identity}</span>}
          </span>
        </span>
        <span className="finding-right">
          <span className="exposure">
            <b>{f.exposureDays.toLocaleString()}</b>
            <span>days exposed</span>
          </span>
          <span className={`chev ${open ? "open" : ""}`} aria-hidden>
            ▸
          </span>
        </span>
      </button>

      {open && (
        <div className="finding-detail">
          <dl className="kv">
            <dt>Status</dt>
            <dd>
              {f.liveness === "live"
                ? "Valid — the provider accepted this credential just now."
                : f.liveness === "dead"
                  ? "Rejected by the provider. Already revoked or expired."
                  : "Not verified. No safe read-only probe, or the provider did not answer."}
            </dd>

            {f.validation?.scopes?.length ? (
              <>
                <dt>Scopes</dt>
                <dd>{f.validation.scopes.join(", ")}</dd>
              </>
            ) : null}

            {f.validation?.note ? (
              <>
                <dt>Provider note</dt>
                <dd>{f.validation.note}</dd>
              </>
            ) : null}

            <dt>First committed</dt>
            <dd>
              {fmtDate(f.firstSeen.date)} · {f.firstSeen.commit.slice(0, 10)} ·{" "}
              {f.firstSeen.author}
            </dd>

            <dt>Last committed</dt>
            <dd>
              {fmtDate(f.lastSeen.date)} · {f.lastSeen.commit.slice(0, 10)}
            </dd>

            <dt>Paths</dt>
            <dd>{f.paths.join("\n")}</dd>

            <dt>At HEAD</dt>
            <dd>
              {f.liveAtHead
                ? "Yes — this content is still in the working tree."
                : "No — deleted from the working tree, but still reachable in history. Deleting the file did not revoke the credential."}
            </dd>

            <dt>Value</dt>
            <dd>
              {f.masked} · {f.length} chars · sha256 {f.id.slice(0, 12)}
            </dd>
          </dl>

          <p className="cost">
            <b>Estimated cost if abused.</b> {f.costRange}
          </p>

          <div className="rotation">
            <h4>Rotate — {rotation.provider}</h4>
            <ol>
              {rotation.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
            {rotation.console && (
              <p style={{ marginTop: 10, fontSize: 12 }}>
                <a
                  className="mono"
                  href={rotation.console}
                  target="_blank"
                  rel="noreferrer noopener"
                  style={{ color: "var(--muted)" }}
                >
                  {rotation.console}
                </a>
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
