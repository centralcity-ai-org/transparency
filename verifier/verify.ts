// Verifies Central City's public agent count end to end, from public data only:
//   1. every checkpoint's hash, the chain of prev_hash links and the append-only consistency
//      proofs (verifyChain);
//   2. every checkpoint's Ed25519 signature against the published key set (/.well-known/jwks.json).
//      A v1 checkpoint published with subcounts_withheld signs fields that are not public, so its
//      signature cannot be tied to the published fields: it is reported under `unchecked`, never
//      as valid and never as a failure;
//   3. the latest checkpoint's Merkle root, recomputed from the published leaves;
//   4. the withdrawn list against the latest checkpoint;
//   5. optionally, a witness folder (this repository's agent-count/) against the service, byte
//      for byte, and one agent's inclusion proof.
import {
  type AgentProof,
  type PublicCheckpoint as Checkpoint,
  isWithheld,
  fromHex,
  merkleRoot,
  toHex,
  verifyAgentProof,
  verifyChain,
  verifyCheckpointSignature,
} from './count-log.js';

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
  /** Checkpoints whose signature is not checkable because signed fields are withheld. */
  unchecked: string[];
}

/** The witness file for a checkpoint: the same path and bytes the service publishes. */
export function witnessFile(folder: string, checkpoint: Checkpoint) {
  const [year] = checkpoint.date.split('-');
  return {
    path: `${folder}/${year}/${checkpoint.date}.json`,
    content: `${JSON.stringify(checkpoint, null, 2)}\n`,
  };
}

export async function verifyLog(log: PublicLog): Promise<Report> {
  const problems: string[] = [];
  const checkpoints = [...log.checkpoints].sort((a, b) => a.date.localeCompare(b.date));
  for (const problem of await verifyChain(checkpoints))
    problems.push(`${problem.date}: ${problem.problem}`);

  const unchecked: string[] = [];
  const keys = new Map(log.keys.filter((key) => key.kid).map((key) => [key.kid!, key]));
  for (const checkpoint of checkpoints) {
    if (!checkpoint.signature) {
      problems.push(`${checkpoint.date}: not signed`);
      continue;
    }
    if (isWithheld(checkpoint)) {
      unchecked.push(`${checkpoint.date}: signature not checkable, fields withheld`);
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

/** Compares witness files (path → content) with the service's checkpoints. */
export function compareWitness(
  folder: string,
  files: ReadonlyMap<string, string>,
  checkpoints: readonly Checkpoint[],
): string[] {
  const problems: string[] = [];
  const expected = new Map(checkpoints.map((cp) => [witnessFile(folder, cp).path, witnessFile(folder, cp).content]));
  for (const [path, content] of files) {
    const live = expected.get(path);
    if (live === undefined) problems.push(`${path}: witnessed, but the service no longer publishes it`);
    else if (live !== content) problems.push(`${path}: the service now publishes different content`);
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
