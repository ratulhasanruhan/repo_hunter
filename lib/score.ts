/**
 * Ranking.
 *
 *   score = liveness x scope_power x exposure x public_multiplier
 *
 * Exposure enters as log10(1 + days) rather than raw days. Raw days would swamp
 * every other term — a dead test key from 2019 would outrank a live admin key
 * from last week — and the ranking exists to answer "what do I fix first", not
 * "what is oldest". Age still gets its own column, sorted independently.
 */
import type { Finding, Liveness, Tier } from "./types";

const LIVENESS_WEIGHT: Record<Liveness, number> = {
  live: 10,
  unknown: 2,
  pending: 2,
  dead: 0.2,
};

export function exposureDays(firstSeenUnix: number): number {
  return Math.max(0, Math.floor((Date.now() / 1000 - firstSeenUnix) / 86_400));
}

export interface ScoreInputs {
  liveness: Liveness;
  /** 1–10 from the pattern table. */
  power: number;
  /** Confirmed write/admin scope from validation. */
  write?: boolean;
  testMode?: boolean;
  exposureDays: number;
  isPublic: boolean;
  forks: number;
  liveAtHead: boolean;
}

export function scoreFinding(i: ScoreInputs): number {
  const liveness = LIVENESS_WEIGHT[i.liveness];

  let scope = i.power;
  if (i.write === true) scope *= 1.5;
  if (i.write === false) scope *= 0.6;
  if (i.testMode) scope *= 0.2;

  const exposure = 1 + Math.log10(1 + i.exposureDays);

  // Forks are the term that matters most here: they are why rewriting history
  // does not undo the leak.
  const publicMultiplier = i.isPublic ? 1 + Math.log10(1 + i.forks) * 0.6 : 0.5;

  // A secret still sitting at HEAD is being served to every new cloner.
  const headMultiplier = i.liveAtHead ? 1.15 : 1;

  return liveness * scope * exposure * publicMultiplier * headMultiplier;
}

export function tierOf(liveness: Liveness, power: number, write?: boolean, testMode?: boolean): Tier {
  if (liveness !== "live") return "dead";
  if (testMode) return "live-low";
  if (write === true || power >= 7) return "live-dangerous";
  return "live-low";
}

export const TIER_LABEL: Record<Tier, string> = {
  "live-dangerous": "Live and dangerous",
  "live-low": "Live, low scope",
  dead: "Dead or unverifiable",
};

export const TIER_NOTE: Record<Tier, string> = {
  "live-dangerous": "Confirmed valid, with write or high-value scope. Rotate these first.",
  "live-low": "Confirmed valid, but limited scope or test mode. Rotate, without panic.",
  dead: "Revoked, expired, or with no safe read-only probe. Kept for the record.",
};

export function sortFindings(findings: Finding[]): Finding[] {
  const order: Record<Tier, number> = { "live-dangerous": 0, "live-low": 1, dead: 2 };
  return [...findings].sort(
    (a, b) => order[a.tier] - order[b.tier] || b.score - a.score || b.exposureDays - a.exposureDays,
  );
}
