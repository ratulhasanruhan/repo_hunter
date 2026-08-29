/**
 * In-memory scan cache. No database — a scan result is a transient artifact, and
 * persisting it would mean persisting a map of who is currently exploitable.
 *
 * Findings placed in here already carry masked values only; there is no code
 * path that writes a raw secret into this map.
 */
import type { ScanResult } from "./types";

const TTL_MS = 60 * 60 * 1000;

declare global {
  var __repohunterStore: Map<string, ScanResult> | undefined;
}

// Survives Next's dev-mode module reloading; still process-local, still ephemeral.
const store: Map<string, ScanResult> = globalThis.__repohunterStore ?? new Map();
globalThis.__repohunterStore = store;

function sweep(): void {
  const cutoff = Date.now() - TTL_MS;
  for (const [id, result] of store) if (result.createdAt < cutoff) store.delete(id);
}

export function putScan(result: ScanResult): void {
  sweep();
  store.set(result.id, result);
}

export function getScan(id: string): ScanResult | null {
  sweep();
  return store.get(id) ?? null;
}
