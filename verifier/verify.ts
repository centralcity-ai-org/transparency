// Verifies Central City's public agent count end to end, from public data only:
//   1. every checkpoint's hash, the chain of prev_hash links and the append-only consistency
//      proofs (verifyChain);
//   2. every checkpoint's Ed25519 signature against the published key set (/.well-known/jwks.json).
//      v1 signatures are withheld for privacy, so a v1 checkpoint is not checkable: it is reported
//      under `unchecked`, never as valid and never as a failure. No v1 checkpoint may be dated
//      after V1_LAST_DATE, and v2 starts a new chain (see verifyChain);
//   3. the latest checkpoint's Merkle root, recomputed from the published leaves;
//   4. the withdrawn list against the latest checkpoint;
//   5. optionally, a witness folder (this repository's agent-count/) against the service, byte
//      for byte (see sameWitnessedDay), and one agent's inclusion proof.
import {
  type AgentProof,
  type Checkpoint as FullCheckpoint,
  type PublicCheckpoint,
  isWithheld,
  fromHex,
  merkleRoot,
  toHex,
  verifyAgentProof,
  verifyChain,
  verifyCheckpointSignature,
} from './count-log.js';

/**
 * A checkpoint as a service may serve it: v2, a withheld v1, or (from a service that predates
 * the withheld form) a full legacy v1, whose hash and signature are checked as before.
 */
export type Checkpoint = PublicCheckpoint | FullCheckpoint;

/** Whether a checkpoint carries per-category counts (a full legacy v1). */
export const hasSubcounts = (checkpoint: Checkpoint) => 'subcounts' in checkpoint;

export interface Jwk {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
}
export interface Leaf {
  idx: number;
  leaf_hash: string;
  day: string;
}
export interface PublicLog {
  checkpoints: Checkpoint[];
  keys: Jwk[];
  leaves: Leaf[];
  withdrawn: { idx: number; reason: string; day: string }[];
}
export interface Report {
  ok: boolean;
  checkpoints: number;
  latest: { date: string; tree_size: number; withdrawn: number; counted: number; root: string } | null;
  problems: string[];
  /** Checkpoints that are not checkable: v1 signatures are withheld for privacy. */
  unchecked: string[];
}

/**
 * The witness file for a checkpoint: the same path and bytes the service publishes. The witness
 * job (witness/update.ts) refuses to write one that carries per-category counts (hasSubcounts).
 */
export function witnessFile(folder: string, checkpoint: Checkpoint) {
  const [year] = checkpoint.date.split('-');
  return {
    path: `${folder}/${year}/${checkpoint.date}.json`,
    content: `${JSON.stringify(checkpoint, null, 2)}\n`,
  };
}

/** Never a plain VERIFIED when some entries could not be checked. */
export function resultLine(report: Pick<Report, 'ok' | 'unchecked'>): string {
  if (!report.ok) return 'RESULT: FAILED';
  const n = report.unchecked.length;
  if (n === 0) return 'RESULT: VERIFIED';
  return `RESULT: VERIFIED (${n} ${n === 1 ? 'entry' : 'entries'} not checkable: withheld)`;
}

export async function verifyLog(log: PublicLog): Promise<Report> {
  const problems: string[] = [];
  const checkpoints = [...log.checkpoints].sort((a, b) => a.date.localeCompare(b.date));
  for (const problem of await verifyChain(checkpoints))
    problems.push(`${problem.date}: ${problem.problem}`);

  const unchecked: string[] = [];
  const keys = new Map(log.keys.filter((key) => key.kid).map((key) => [key.kid!, key]));
  for (const checkpoint of checkpoints) {
    if (isWithheld(checkpoint)) {
      unchecked.push(`${checkpoint.date}: not checkable (v1, signature withheld for privacy)`);
      continue;
    }
    if (!checkpoint.signature) {
      problems.push(`${checkpoint.date}: not signed`);
      continue;
    }
    const key = keys.get(checkpoint.signature.kid);
    if (!key) problems.push(`${checkpoint.date}: signing key ${checkpoint.signature.kid} is not published`);
    else if (!(await verifyCheckpointSignature(checkpoint.hash, checkpoint.signature.sig, key)))
      problems.push(`${checkpoint.date}: bad signature`);
  }

  const latest = checkpoints.at(-1) ?? null;
  if (latest) {
    const leaves = [...log.leaves].sort((a, b) => a.idx - b.idx);
    if (leaves.length < latest.tree_size)
      problems.push(`${latest.date}: only ${leaves.length} of ${latest.tree_size} leaves are published`);
    else {
      leaves.slice(0, latest.tree_size).forEach((leaf, index) => {
        if (leaf.idx !== index) problems.push(`leaf ${index}: missing or out of order`);
      });
      const root = toHex(await merkleRoot(leaves.slice(0, latest.tree_size).map((l) => fromHex(l.leaf_hash))));
      if (root !== latest.root) problems.push(`${latest.date}: the published leaves do not give the checkpoint root`);
    }
    const withdrawn = log.withdrawn.filter((entry) => entry.idx < latest.tree_size);
    if (withdrawn.length !== latest.withdrawn)
      problems.push(`${latest.date}: ${withdrawn.length} withdrawn entries published, checkpoint says ${latest.withdrawn}`);
    if (new Set(withdrawn.map((entry) => entry.idx)).size !== withdrawn.length)
      problems.push(`${latest.date}: a leaf is withdrawn twice`);
  }
  return {
    ok: problems.length === 0,
    checkpoints: checkpoints.length,
    latest: latest && {
      date: latest.date,
      tree_size: latest.tree_size,
      withdrawn: latest.withdrawn,
      counted: latest.tree_size - latest.withdrawn,
      root: latest.root,
    },
    problems,
    unchecked,
  };
}

/** The tree fields every form of a v1 checkpoint publishes. */
const V1_TREE_FIELDS = ['v', 'date', 'tree_size', 'withdrawn', 'root', 'consistency'] as const;
/** Further v1 fields compared when both copies carry them. */
const V1_OPTIONAL_FIELDS = ['prev_hash', 'hash', 'signature'] as const;

/**
 * Whether a witnessed file records the same day the service publishes: byte for byte, with one
 * exception for v1 days. A v1 day may be witnessed in an older form than the service serves now
 * (with or without its signed fields); the file is kept as it is (files are only ever added). The
 * two copies are the same day when the tree fields match exactly, and so does every signed field
 * both copies carry.
 */
export function sameWitnessedDay(content: string, live: Checkpoint): boolean {
  if (content === witnessFile('', live).content) return true;
  if (live.v !== 1) return false;
  let witnessed: Record<string, unknown>;
  try {
    witnessed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return false;
  }
  if (witnessed === null || typeof witnessed !== 'object' || witnessed.v !== 1) return false;
  const current = live as unknown as Record<string, unknown>;
  const same = (key: string) => JSON.stringify(witnessed[key]) === JSON.stringify(current[key]);
  if (!V1_TREE_FIELDS.every(same)) return false;
  return V1_OPTIONAL_FIELDS.every((key) => !(key in witnessed) || !(key in current) || same(key));
}

/**
 * What the witness job does with the service's checkpoints, given the files it already has
 * (`read` returns a file's content, or undefined when there is none): files to add, witnessed
 * days whose content changed, and days refused because they carry per-category counts. When any
 * day is refused, nothing is added.
 */
export function witnessPlan(
  folder: string,
  checkpoints: readonly Checkpoint[],
  read: (path: string) => string | undefined,
): { add: { path: string; content: string }[]; changed: string[]; refused: string[] } {
  const refused = checkpoints.filter(hasSubcounts).map((cp) => cp.date);
  const add: { path: string; content: string }[] = [];
  const changed: string[] = [];
  for (const checkpoint of checkpoints) {
    const file = witnessFile(folder, checkpoint);
    const existing = read(file.path);
    if (existing === undefined) add.push(file);
    else if (!sameWitnessedDay(existing, checkpoint)) changed.push(file.path);
  }
  return { add: refused.length ? [] : add, changed, refused };
}

/** Compares witness files (path → content) with the service's checkpoints. */
export function compareWitness(
  folder: string,
  files: ReadonlyMap<string, string>,
  checkpoints: readonly Checkpoint[],
): string[] {
  const problems: string[] = [];
  const expected = new Map(checkpoints.map((cp) => [witnessFile(folder, cp).path, cp]));
  for (const [path, content] of files) {
    const live = expected.get(path);
    if (live === undefined) problems.push(`${path}: witnessed, but the service no longer publishes it`);
    else if (!sameWitnessedDay(content, live)) problems.push(`${path}: the service now publishes different content`);
  }
  return problems;
}

export async function verifyAgent(
  agentId: string,
  proof: AgentProof,
  checkpoints: readonly Checkpoint[],
): Promise<string | null> {
  const checkpoint = checkpoints.find((cp) => cp.date === proof.checkpoint_date);
  if (!checkpoint) return `no published checkpoint for ${proof.checkpoint_date}`;
  const result = await verifyAgentProof(agentId, proof, checkpoint);
  return result.ok ? null : result.step;
}
