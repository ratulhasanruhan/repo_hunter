export type Liveness = "live" | "dead" | "unknown" | "pending";

export type Tier = "live-dangerous" | "live-low" | "dead";

export type DetectorClass = "prefixed" | "entropy" | "recon";

/** A single (commit, path) sighting of a secret. */
export interface Occurrence {
  commit: string;
  /** Unix seconds. */
  date: number;
  author: string;
  authorEmail: string;
  path: string;
}

/** One unique secret, keyed by SHA-256 of its value. */
export interface Finding {
  /** SHA-256 of the raw secret value. The raw value is never stored. */
  id: string;
  provider: string;
  /** Human label, e.g. "OpenAI API key". */
  kind: string;
  detector: DetectorClass;
  /** first4…last4 only. This is the ONLY form of the value that ever leaves the scanner. */
  masked: string;
  length: number;
  liveness: Liveness;
  /** Populated only when liveness === "live". */
  validation?: ValidationDetail;
  occurrences: Occurrence[];
  firstSeen: Occurrence;
  lastSeen: Occurrence;
  /** Days between firstSeen and now. */
  exposureDays: number;
  /** Does a file containing this secret still exist at HEAD? */
  liveAtHead: boolean;
  paths: string[];
  score: number;
  tier: Tier;
  costRange: string;
  /** Set when a pattern is structurally a test/sandbox credential. */
  testMode?: boolean;
}

export interface ValidationDetail {
  /** e.g. "repo, workflow, admin:org" */
  scopes?: string[];
  /** Account / principal / workspace the credential resolves to. */
  identity?: string;
  /** Free-form provider note, e.g. "live mode". */
  note?: string;
  /** True when the credential can write, not just read. */
  write?: boolean;
}

export interface ReconFinding {
  id: string;
  kind: string;
  /** Recon values are not credentials; shown in full since that is the point. */
  value: string;
  count: number;
  paths: string[];
  firstSeen: Occurrence;
}

export interface DependencyIssue {
  ecosystem: string;
  package: string;
  version: string;
  advisories: { id: string; summary: string; severity: string }[];
  manifest: string;
}

export interface RepoMeta {
  url: string;
  owner: string;
  name: string;
  isPublic: boolean;
  forks: number;
  stars: number;
  sizeKb: number;
  defaultBranch: string;
  commits: number;
  /** Rewriting history cannot recall what forks already hold. */
  rewriteIsFutile: boolean;
}

export interface AuthorCluster {
  author: string;
  email: string;
  findings: number;
  live: number;
}

export interface ScanResult {
  id: string;
  meta: RepoMeta;
  findings: Finding[];
  recon: ReconFinding[];
  dependencies: DependencyIssue[];
  authors: AuthorCluster[];
  stats: {
    commits: number;
    blobs: number;
    bytes: number;
    durationMs: number;
  };
  createdAt: number;
}
