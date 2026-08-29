/**
 * Scan orchestration.
 *
 * The one invariant that shapes this file: raw secret values live in local
 * variables for the duration of the scan, are passed to the validators, and are
 * then dropped. They are never written into a Finding, never put in the cache,
 * never serialised to the client, and never logged. Everything that leaves here
 * is masked at the point of detection.
 */
import { randomUUID } from "node:crypto";
import {
  PATTERNS,
  PEM_BLOCK_RE,
  isPlaceholder,
  isSuppressedPath,
  isSensitiveFile,
} from "./patterns";
import { entropyCandidates } from "./entropy";
import { mask, secretId } from "./mask";
import { buildIndex, cleanup, mirrorClone, batchCheck, readBlobs, LIMITS, ScanLimitError } from "./walk";
import { fetchRepoMeta, parseRepoUrl } from "./github";
import { validateAll, isValidatable } from "./validate";
import { exposureDays, scoreFinding, sortFindings, tierOf } from "./score";
import { checkDependencies } from "./deps";
import { putScan } from "./store";
import type {
  AuthorCluster,
  Finding,
  Occurrence,
  ReconFinding,
  ScanResult,
} from "./types";

export type ScanEvent =
  | { type: "phase"; phase: string; message: string }
  | { type: "progress"; commits: number; blobs: number; bytes: number }
  | { type: "meta"; meta: ScanResult["meta"] }
  | { type: "findings"; findings: Finding[]; recon: ReconFinding[]; authors: AuthorCluster[] }
  | { type: "validated"; id: string; finding: Finding }
  | { type: "dependencies"; dependencies: ScanResult["dependencies"] }
  | { type: "done"; scanId: string; stats: ScanResult["stats"] }
  | { type: "error"; message: string };

/** Accumulator holding the raw value. Never leaves this module. */
interface Candidate {
  id: string;
  provider: string;
  kind: string;
  detector: Finding["detector"];
  raw: string;
  power: number;
  cost: string;
  testMode?: boolean;
  /** AWS secret access key paired from the same blob, if one was present. */
  secondary?: string;
  occurrences: Occurrence[];
  blobs: Set<string>;
}

const MAX_FINDINGS = 2000;
const ENTROPY_MAX_BLOB = 256 * 1024;

/**
 * An AWS access key id is unusable without its secret access key, so STS cannot
 * answer for it alone. Look for the partner in the same blob.
 *
 * The secret has no distinguishing prefix — it is just 40 base64 characters — so
 * the only signal is the name it sits next to. Match the bare token and inspect
 * the text immediately before it; folding the name into the pattern itself would
 * move the match start past the very hint we need to read.
 */
const AWS_SECRET_RE = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g;
const AWS_SECRET_HINT = /(secret|aws|credential)/i;

export async function runScan(
  inputUrl: string,
  emit: (event: ScanEvent) => void,
): Promise<void> {
  const started = Date.now();
  let repoDir: string | null = null;

  try {
    const repo = parseRepoUrl(inputUrl);
    emit({ type: "phase", phase: "meta", message: `Resolving ${repo.owner}/${repo.name}` });
    const metaBase = await fetchRepoMeta(repo);

    emit({ type: "phase", phase: "clone", message: "Mirroring every ref" });
    repoDir = await mirrorClone(repo.cloneUrl);

    // ---- Pass 1: history index ------------------------------------------
    emit({ type: "phase", phase: "walk", message: "Walking history" });
    // The counter ticking through commits is the only animation in the product,
    // so progress is emitted from inside the walk rather than batched after it.
    const index = await buildIndex(repoDir, (commits) => {
      emit({ type: "progress", commits, blobs: 0, bytes: 0 });
    });
    emit({ type: "progress", commits: index.commitCount, blobs: 0, bytes: 0 });

    const meta = { ...metaBase, commits: index.commitCount };
    emit({ type: "meta", meta });

    // ---- Blob selection --------------------------------------------------
    // Drop blobs whose every path is suppressed (lockfiles, bundles, vendored code).
    const interesting: string[] = [];
    for (const [sha, occs] of index.blobs) {
      if (occs.every((o) => isSuppressedPath(o.path))) continue;
      interesting.push(sha);
    }
    const sizes = await batchCheck(repoDir, interesting);
    const toRead = interesting
      .filter((sha) => {
        const size = sizes.get(sha);
        return size !== undefined && size > 0 && size <= LIMITS.maxBlobBytes;
      })
      .slice(0, LIMITS.maxBlobs);

    // ---- Pass 2: read blobs, match, dedupe -------------------------------
    emit({ type: "phase", phase: "scan", message: `Reading ${toRead.length.toLocaleString()} unique blobs` });

    const candidates = new Map<string, Candidate>();
    const recon = new Map<string, ReconFinding>();
    let scannedBlobs = 0;
    let scannedBytes = 0;

    const onBlob = (sha: string, content: string) => {
      const occs = index.blobs.get(sha);
      if (!occs) return;
      const path = occs.find((o) => !isSuppressedPath(o.path))?.path ?? occs[0].path;

      // Harvest possible AWS secret access keys once per blob, for pairing.
      const awsSecrets: string[] = [];
      if (content.includes("AKIA") || content.includes("ASIA") || /aws/i.test(content)) {
        AWS_SECRET_RE.lastIndex = 0;
        let am: RegExpExecArray | null;
        while ((am = AWS_SECRET_RE.exec(content))) {
          const before = content.slice(Math.max(0, am.index - 48), am.index);
          if (AWS_SECRET_HINT.test(before) && !isPlaceholder(am[0])) awsSecrets.push(am[0]);
          if (awsSecrets.length > 4) break;
        }
      }

      const record = (
        provider: string,
        kind: string,
        detector: Finding["detector"],
        value: string,
        power: number,
        cost: string,
        testMode?: boolean,
      ) => {
        if (candidates.size >= MAX_FINDINGS) return;
        const id = secretId(value);
        let c = candidates.get(id);
        if (!c) {
          c = {
            id,
            provider,
            kind,
            detector,
            raw: value,
            power,
            cost,
            testMode,
            occurrences: [],
            blobs: new Set(),
          };
          candidates.set(id, c);
        }
        if (provider === "aws" && !c.secondary && awsSecrets.length) c.secondary = awsSecrets[0];
        if (!c.blobs.has(sha)) {
          c.blobs.add(sha);
          for (const o of occs) {
            if (!c.occurrences.some((e) => e.commit === o.commit && e.path === o.path)) {
              c.occurrences.push(o);
            }
          }
        }
      };

      for (const p of PATTERNS) {
        if (p.detector === "recon") continue;
        p.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let hits = 0;
        while ((m = p.re.exec(content))) {
          const value = p.group ? m[p.group] : m[0];
          if (!value || isPlaceholder(value)) continue;
          // sk-ant- keys also match the looser OpenAI sk- pattern; let the
          // specific one own them.
          if (p.provider === "openai" && value.startsWith("sk-ant-")) continue;
          record(p.provider, p.kind, "prefixed", value, p.power ?? 5, p.cost ?? "Unknown.", p.testMode);
          if (++hits > 200) break; // a file of nothing but keys is a fixture
        }
      }

      // Recon layer: the map that precedes an attack. Cheap, and much wider coverage.
      for (const p of PATTERNS) {
        if (p.detector !== "recon") continue;
        p.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let hits = 0;
        while ((m = p.re.exec(content))) {
          const value = m[0];
          if (isPlaceholder(value)) continue;
          const key = `${p.kind}:${value.toLowerCase()}`;
          const existing = recon.get(key);
          if (existing) {
            existing.count++;
            if (!existing.paths.includes(path) && existing.paths.length < 6) existing.paths.push(path);
          } else if (recon.size < 400) {
            recon.set(key, {
              id: key,
              kind: p.kind,
              value,
              count: 1,
              paths: [path],
              firstSeen: occs[0],
            });
          }
          if (++hits > 50) break;
        }
      }

      // Entropy detection runs last and only where a secret plausibly lives.
      if (content.length <= ENTROPY_MAX_BLOB) {
        // Private keys are already reported by name; their base64 body would
        // otherwise flood this detector with duplicates of a known finding.
        PEM_BLOCK_RE.lastIndex = 0;
        const lines = content.replace(PEM_BLOCK_RE, "").split("\n");
        if (lines.length <= 20_000) {
          let found = 0;
          for (const line of lines) {
            for (const cand of entropyCandidates(line, path)) {
              if (isPlaceholder(cand.value)) continue;
              // Skip anything a prefixed pattern already owns.
              if (candidates.has(secretId(cand.value))) continue;
              record(
                "generic",
                `High-entropy string (${cand.entropy.toFixed(1)} bits/char)`,
                "entropy",
                cand.value,
                isSensitiveFile(path) ? 5 : 3,
                "Unknown — provider not identified, so no probe exists.",
              );
              if (++found > 30) return;
            }
          }
        }
      }
    };

    const readStats = await readBlobs(repoDir, toRead, onBlob, (done, bytes) => {
      scannedBlobs = done;
      scannedBytes = bytes;
      emit({ type: "progress", commits: index.commitCount, blobs: done, bytes });
    });
    scannedBlobs = readStats.count;
    scannedBytes = readStats.bytes;
    emit({ type: "progress", commits: index.commitCount, blobs: scannedBlobs, bytes: scannedBytes });

    // ---- Build findings (masked, unvalidated) ----------------------------
    const findings: Finding[] = [];
    for (const c of candidates.values()) {
      c.occurrences.sort((a, b) => a.date - b.date);
      const firstSeen = c.occurrences[0];
      const lastSeen = c.occurrences[c.occurrences.length - 1];
      const days = exposureDays(firstSeen.date);
      const liveAtHead = [...c.blobs].some((sha) => index.headBlobs.has(sha));
      const liveness = isValidatable(c.provider) ? "pending" : "unknown";
      findings.push({
        id: c.id,
        provider: c.provider,
        kind: c.kind,
        detector: c.detector,
        masked: mask(c.raw),
        length: c.raw.length,
        liveness,
        occurrences: c.occurrences,
        firstSeen,
        lastSeen,
        exposureDays: days,
        liveAtHead,
        paths: [...new Set(c.occurrences.map((o) => o.path))],
        testMode: c.testMode,
        costRange: c.cost,
        score: scoreFinding({
          liveness,
          power: c.power,
          testMode: c.testMode,
          exposureDays: days,
          isPublic: meta.isPublic,
          forks: meta.forks,
          liveAtHead,
        }),
        tier: tierOf(liveness, c.power, undefined, c.testMode),
      });
    }

    const authors = clusterAuthors(findings);
    emit({
      type: "findings",
      findings: sortFindings(findings),
      recon: [...recon.values()].sort((a, b) => b.count - a.count).slice(0, 120),
      authors,
    });

    // ---- Validation: streams in, never blocks the render -----------------
    emit({ type: "phase", phase: "validate", message: "Probing providers (read-only)" });
    const byId = new Map(findings.map((f) => [f.id, f]));
    const pending = findings.filter((f) => f.liveness === "pending");
    const results: { id: string; finding: Finding }[] = [];

    await validateAll(
      pending.map((f) => ({ provider: f.provider, id: f.id })),
      (item) => candidates.get(item.id)!.raw,
      (item) => candidates.get(item.id)!.secondary,
      (item, result) => {
        const f = byId.get(item.id)!;
        const c = candidates.get(item.id)!;
        f.liveness = result.liveness;
        f.validation = result.detail;
        f.tier = tierOf(result.liveness, c.power, result.detail?.write, c.testMode);
        f.score = scoreFinding({
          liveness: result.liveness,
          power: c.power,
          write: result.detail?.write,
          testMode: c.testMode,
          exposureDays: f.exposureDays,
          isPublic: meta.isPublic,
          forks: meta.forks,
          liveAtHead: f.liveAtHead,
        });
        results.push({ id: f.id, finding: f });
      },
    );

    for (const r of results) emit({ type: "validated", id: r.id, finding: r.finding });

    // ---- Dependency health ----------------------------------------------
    emit({ type: "phase", phase: "deps", message: "Checking dependencies against OSV" });
    const dependencies = await checkDependencies(repoDir);
    emit({ type: "dependencies", dependencies });

    // ---- Cache and finish -------------------------------------------------
    const stats = {
      commits: index.commitCount,
      blobs: scannedBlobs,
      bytes: scannedBytes,
      durationMs: Date.now() - started,
    };
    const result: ScanResult = {
      id: randomUUID(),
      meta,
      findings: sortFindings(findings),
      recon: [...recon.values()].sort((a, b) => b.count - a.count).slice(0, 120),
      dependencies,
      authors: clusterAuthors(findings),
      stats,
      createdAt: Date.now(),
    };
    putScan(result);
    emit({ type: "done", scanId: result.id, stats });
  } catch (e) {
    const message =
      e instanceof ScanLimitError
        ? e.message
        : e instanceof Error
          ? e.message
          : "Scan failed for an unknown reason.";
    emit({ type: "error", message });
  } finally {
    if (repoDir) await cleanup(repoDir).catch(() => {});
  }
}

/**
 * Author clustering. Framed as where onboarding should focus — a leaked key is
 * a tooling failure, not a character flaw, and the UI says so out loud.
 */
function clusterAuthors(findings: Finding[]): AuthorCluster[] {
  const map = new Map<string, AuthorCluster>();
  for (const f of findings) {
    const { author, authorEmail } = f.firstSeen;
    const key = authorEmail || author;
    const entry = map.get(key) ?? { author, email: authorEmail, findings: 0, live: 0 };
    entry.findings++;
    if (f.liveness === "live") entry.live++;
    map.set(key, entry);
  }
  return [...map.values()].sort((a, b) => b.findings - a.findings).slice(0, 10);
}
