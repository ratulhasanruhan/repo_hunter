"use client";

import { useState } from "react";

export function ScanInput({
  onScan,
  busy,
}: {
  onScan: (url: string) => void;
  busy: boolean;
}) {
  const [value, setValue] = useState("");

  return (
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
  );
}
