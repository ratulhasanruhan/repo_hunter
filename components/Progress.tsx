"use client";

/**
 * The scan is the animation. Nothing else on the page moves.
 */
export function Progress({
  phase,
  commits,
  blobs,
  bytes,
  findings,
}: {
  phase: string;
  commits: number;
  blobs: number;
  bytes: number;
  findings: number;
}) {
  return (
    <div className="progress" role="status" aria-live="polite">
      <div className="progress-phase">
        <i className="pulse" aria-hidden />
        {phase}
      </div>
      <div className="counters">
        <Counter value={commits} label="commits walked" />
        <Counter value={blobs} label="blobs read" />
        <Counter value={mb(bytes)} label="megabytes" />
        <Counter value={findings} label="unique secrets" />
      </div>
      <div className="bar" aria-hidden>
        <i />
      </div>
    </div>
  );
}

function Counter({ value, label }: { value: number | string; label: string }) {
  return (
    <div>
      <div className="counter-value">
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      <div className="counter-label">{label}</div>
    </div>
  );
}

function mb(bytes: number): string {
  return (bytes / 1_048_576).toFixed(1);
}
