"use client";

import { useState } from "react";

// Samples must be under the 500 MB size guard and be real applications.
// Wordlist and dataset repos are excluded on purpose: their contents are
// credential-shaped by design, so every match is a false positive.
const SAMPLES = [
  "github.com/octocat/Hello-World",
];

export function ScanInput({
  onScan,
  busy,
}: {
  onScan: (url: string) => void;
  busy: boolean;
}) {
  const [value, setValue] = useState("");

  return (
    <>
      <form
        className="scan-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim() && !busy) onScan(value.trim());
        }}
      >
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="github.com/owner/repo"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          aria-label="Public GitHub repository URL"
          disabled={busy}
        />
        <button type="submit" disabled={busy || !value.trim()}>
          {busy ? "Scanning" : "Scan history"}
        </button>
      </form>
      <p className="samples">
        Try{" "}
        {SAMPLES.map((s, i) => (
          <span key={s}>
            {i > 0 && " · "}
            <button type="button" onClick={() => setValue(s)} disabled={busy}>
              {s.replace("github.com/", "")}
            </button>
          </span>
        ))}
      </p>
    </>
  );
}
