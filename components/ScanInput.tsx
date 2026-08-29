"use client";

import { useState } from "react";

const SAMPLES = [
  "github.com/octocat/Hello-World",
  "github.com/danielmiessler/SecLists",
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
