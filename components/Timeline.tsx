"use client";

import type { Finding } from "@/lib/types";

/**
 * One chart: repo history left to right, one mark per finding.
 *
 * The solid bar is the period the secret sat in the working tree. Where a file
 * was deleted but the credential still validates, a dashed line carries on to
 * today — that gap is the entire thesis of the product in one picture: removing
 * the file ended the bar and revoked nothing.
 */

const W = 900;
const ROW_H = 18;
const PAD_L = 8;
const PAD_R = 8;
const TOP = 26;
const MAX_ROWS = 26;

const COLOR: Record<string, string> = {
  "live-dangerous": "var(--live)",
  "live-low": "var(--warn)",
  dead: "var(--dead)",
};

export function Timeline({ findings }: { findings: Finding[] }) {
  const rows = findings.slice(0, MAX_ROWS);
  if (!rows.length) return null;

  const now = Date.now() / 1000;
  const earliest = Math.min(...rows.map((f) => f.firstSeen.date));
  // A little breathing room so the first mark is not flush against the axis.
  const span = Math.max(now - earliest, 86_400 * 30);
  const t0 = earliest - span * 0.03;
  const t1 = now + span * 0.02;

  const x = (t: number) => PAD_L + ((t - t0) / (t1 - t0)) * (W - PAD_L - PAD_R);
  const height = TOP + rows.length * ROW_H + 14;

  const ticks = yearTicks(t0, t1);

  return (
    <div className="timeline">
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} role="img"
        aria-label={`Exposure timeline for ${rows.length} findings`}>
        {ticks.map((t) => (
          <g key={t.unix}>
            <line className="tl-grid" x1={x(t.unix)} y1={TOP - 8} x2={x(t.unix)} y2={height - 12} />
            <text className="tl-label" x={x(t.unix)} y={TOP - 14} textAnchor="middle">
              {t.label}
            </text>
          </g>
        ))}

        <line className="tl-axis" x1={PAD_L} y1={TOP - 8} x2={W - PAD_R} y2={TOP - 8} />

        {rows.map((f, i) => {
          const y = TOP + i * ROW_H + ROW_H / 2;
          const color = COLOR[f.tier];
          // In-tree period: first commit until removal (approximated by the last
          // commit that still contained it), or until now if still at HEAD.
          const endInTree = f.liveAtHead ? now : f.lastSeen.date;
          const x0 = x(f.firstSeen.date);
          const x1 = Math.max(x(endInTree), x0 + 2);
          const stillValid = f.liveness === "live" && !f.liveAtHead;

          return (
            <g className="tl-row" key={f.id}>
              <title>
                {`${f.kind} — ${f.masked}\n${f.exposureDays.toLocaleString()} days exposed\n${
                  f.liveness === "live" ? "Still valid" : f.liveness === "dead" ? "Revoked" : "Unverified"
                }\n${f.paths[0]}`}
              </title>
              <rect x={0} y={y - ROW_H / 2} width={W} height={ROW_H} fill="transparent" />
              {stillValid && (
                <line
                  x1={x1}
                  y1={y}
                  x2={x(now)}
                  y2={y}
                  stroke={color}
                  strokeWidth={1}
                  strokeDasharray="2 3"
                  opacity={0.75}
                />
              )}
              <rect
                className="tl-bar"
                x={x0}
                y={y - 3}
                width={x1 - x0}
                height={6}
                rx={1}
                fill={color}
              />
              <circle cx={x0} cy={y} r={2.5} fill={color} />
            </g>
          );
        })}
      </svg>

      <div className="legend">
        <span>
          <i style={{ background: "var(--live)" }} />
          Live, high scope
        </span>
        <span>
          <i style={{ background: "var(--warn)" }} />
          Live, low scope
        </span>
        <span>
          <i style={{ background: "var(--dead)" }} />
          Dead or unverifiable
        </span>
        <span>
          <i
            style={{
              background:
                "repeating-linear-gradient(90deg, var(--muted) 0 2px, transparent 2px 5px)",
              height: 1,
            }}
          />
          File removed, credential still valid
        </span>
        {findings.length > MAX_ROWS && <span>Showing top {MAX_ROWS} of {findings.length}</span>}
      </div>
    </div>
  );
}

function yearTicks(t0: number, t1: number): { unix: number; label: string }[] {
  const start = new Date(t0 * 1000).getUTCFullYear();
  const end = new Date(t1 * 1000).getUTCFullYear();
  const years = end - start;
  // Keep roughly six to ten labels regardless of how long the repo has run.
  const step = years > 18 ? 4 : years > 9 ? 2 : 1;
  const out: { unix: number; label: string }[] = [];
  for (let y = start + 1; y <= end; y += step) {
    out.push({ unix: Date.UTC(y, 0, 1) / 1000, label: String(y) });
  }
  return out;
}
