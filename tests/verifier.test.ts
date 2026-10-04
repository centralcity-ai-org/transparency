import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  type Checkpoint,
  type CheckpointBody,
  type PublicCheckpoint,
  subcountsCommitment,
  toPublicCheckpoint,
  agentLeafHash,
  checkpointHash,
  checkpointSigningInput,
  consistencyProof,
  fromHex,
  hashLeaf,
  inclusionProof,
  merkleRoot,
  toHex,
  verifyConsistency,
  verifyInclusion,
} from '../verifier/count-log.js';
import { compareWitness, verifyAgent, verifyLog, witnessFile, type PublicLog } from '../verifier/verify.js';

const vectors = JSON.parse(readFileSync(new URL('./rfc6962-vectors.json', import.meta.url), 'utf8'));

test('RFC 6962 reference vectors: roots, audit paths, consistency proofs', async () => {
  const leaves = await Promise.all(vectors.leaves.map((hex: string) => hashLeaf(fromHex(hex))));
  for (let n = 1; n <= leaves.length; n++) {
    const root = await merkleRoot(leaves.slice(0, n));
    assert.equal(toHex(root), vectors.roots[n - 1], `root ${n}`);
    for (let m = 0; m < n; m++) {
      const path = await inclusionProof(leaves.slice(0, n), m);
      assert.ok(await verifyInclusion(leaves[m]!, m, n, path, root), `path ${m},${n}`);
    }
    for (let m = 1; m < n; m++) {
      const proof = await consistencyProof(leaves.slice(0, n), m);
      assert.ok(await verifyConsistency(m, n, fromHex(vectors.roots[m - 1]), root, proof), `cons ${m},${n}`);
    }
  }
});

/** A synthetic public log: `days` checkpoints over growing trees, signed with a fresh key. */
async function syntheticLog(sizes: number[], versions: (1 | 2)[] = sizes.map(() => 2)) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string }), kid: 'test-key' };
  const agents = Array.from({ length: Math.max(...sizes) }, (_, idx) => ({
    id: randomUUID(),
    salt: randomBytes(32),
    day: `2026-09-${String(10 + Math.floor(idx / 3)).padStart(2, '0')}`,
  }));
  const leafHashes = await Promise.all(agents.map((a) => agentLeafHash(a.id, a.salt, a.day)));
  const checkpoints: PublicCheckpoint[] = [];
  let previous: { hash: string; tree_size: number } | null = null;
  for (const [index, size] of sizes.entries()) {
    const root = toHex(await merkleRoot(leafHashes.slice(0, size)));
    // Synthetic split only; it is never published (v1 is served withheld, v2 commits to it).
    const split = { in_person_accounts: size - 1, in_ai_workspaces: 1, unclaimed: 0, revoked: 0 };
    const common: { date: string; tree_size: number; withdrawn: number; root: string; prev_hash: string | null } = {
      date: `2026-09-${String(20 + index).padStart(2, '0')}`,
      tree_size: size,
      withdrawn: 0,
      root,
      prev_hash: (previous?.hash ?? null) as string | null,
    };
    const body: CheckpointBody =
      versions[index] === 1
        ? { v: 1, ...common, subcounts: split }
        : { v: 2, ...common, subcounts_commitment: await subcountsCommitment(split, randomBytes(32)) };
    const hash = await checkpointHash(body);
    const sig = sign(null, checkpointSigningInput(hash), privateKey).toString('base64url');
    const consistency: string[] =
      previous && previous.tree_size > 0 && previous.tree_size < size
        ? (await consistencyProof(leafHashes.slice(0, size), previous.tree_size)).map(toHex)
        : [];
    const checkpoint: Checkpoint = { ...body, hash, signature: { kid: 'test-key', sig }, consistency };
    checkpoints.push(toPublicCheckpoint(checkpoint));
    previous = checkpoint;
  }
  const log: PublicLog = {
    checkpoints,
    keys: [jwk],
    leaves: leafHashes.map((hash, idx) => ({ idx, leaf_hash: toHex(hash), day: agents[idx]!.day })),
    withdrawn: [],
  };
  return { log, agents, leafHashes };
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

test('a valid log verifies', async () => {
  const { log } = await syntheticLog([3, 5, 9]);
  const report = await verifyLog(log);
  assert.deepEqual(report.problems, []);
  assert.equal(report.ok, true);
  assert.deepEqual(report.latest && [report.latest.date, report.latest.counted], ['2026-09-22', 9]);
});

test('tampering is detected: leaf, root, chain, signature, unknown key, missing leaves', async () => {
  const { log } = await syntheticLog([3, 5, 9]);
  const cases: Array<[string, (l: PublicLog) => void, RegExp]> = [
    ['leaf', (l) => (l.leaves[4]!.leaf_hash = '00'.repeat(32)), /do not give the checkpoint root/],
    ['count', (l) => (l.checkpoints[1]!.tree_size = 6), /hash does not match/],
    ['chain', (l) => (l.checkpoints[2]!.prev_hash = '11'.repeat(32)), /does not link|hash does not match/],
    ['signature', (l) => (l.checkpoints[0]!.signature!.sig = l.checkpoints[1]!.signature!.sig), /bad signature/],
    ['key', (l) => (l.keys[0]!.kid = 'other'), /is not published/],
    ['unsigned', (l) => (l.checkpoints[2]!.signature = null), /not signed/],
    ['missing', (l) => l.leaves.pop(), /leaves are published/],
    ['withdrawn', (l) => l.withdrawn.push({ idx: 1, reason: 'abuse_purge', day: '2026-09-21' }), /withdrawn entries/],
  ];
  for (const [name, tamper, expected] of cases) {
    const copy = clone(log);
    tamper(copy);
    const report = await verifyLog(copy);
    assert.equal(report.ok, false, name);
    assert.ok(report.problems.some((p) => expected.test(p)), `${name}: ${report.problems.join('; ')}`);
  }
});

test('a rewritten history (not append-only) fails the consistency proof', async () => {
  const { log } = await syntheticLog([3, 5]);
  const other = await syntheticLog([3, 5]);
  // Day 2 from another log, re-linked to day 1: the hash chain holds, the tree does not extend.
  const forged = clone(other.log.checkpoints[1]!);
  forged.prev_hash = log.checkpoints[0]!.hash;
  const { hash: _h, signature: _s, consistency: _c, ...body } = forged;
  forged.hash = await checkpointHash(body as CheckpointBody);
  const report = await verifyLog({ ...log, checkpoints: [log.checkpoints[0]!, forged] });
  assert.ok(report.problems.some((p) => /append-only/.test(p)), report.problems.join('; '));
});

test('witness files: the service format, and changed or vanished days are reported', async () => {
  const { log } = await syntheticLog([2, 4]);
  const file = witnessFile('agent-count', log.checkpoints[0]!);
  assert.equal(file.path, 'agent-count/2026/2026-09-20.json');
  assert.equal(file.content, `${JSON.stringify(log.checkpoints[0], null, 2)}\n`);
  const files = new Map(log.checkpoints.map((cp) => [witnessFile('agent-count', cp).path, witnessFile('agent-count', cp).content]));
  assert.deepEqual(compareWitness('agent-count', files, log.checkpoints), []);
  files.set('agent-count/2026/2026-09-20.json', file.content.replace('"tree_size": 2', '"tree_size": 3'));
  files.set('agent-count/2026/2026-09-01.json', '{}\n');
  const problems = compareWitness('agent-count', files, log.checkpoints);
  assert.equal(problems.length, 2);
});

test('an owner proof checks one agent against the published root', async () => {
  const { log, agents, leafHashes } = await syntheticLog([3, 7]);
  const idx = 5;
  const proof = {
    idx,
    salt: toHex(agents[idx]!.salt),
    created_day: agents[idx]!.day,
    checkpoint_date: '2026-09-21',
    tree_size: 7,
    audit_path: (await inclusionProof(leafHashes.slice(0, 7), idx)).map(toHex),
  };
  assert.equal(await verifyAgent(agents[idx]!.id, proof, log.checkpoints), null);
  assert.match((await verifyAgent(randomUUID(), proof, log.checkpoints))!, /does not lead/);
  assert.match((await verifyAgent(agents[idx]!.id, { ...proof, checkpoint_date: '2026-01-01' }, log.checkpoints))!, /no published checkpoint/);
});

test('fetchLog reads the public routes (paged leaves) and reports an unpublished log', async () => {
  const { fetchLog, NotPublished } = await import('../verifier/fetch.js');
  const { log } = await syntheticLog([3, 7]);
  const seen: string[] = [];
  const fake = (async (input: URL | string) => {
    const url = new URL(String(input));
    seen.push(url.pathname + url.search);
    const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    if (url.pathname === '/api/public/count-log/checkpoints') return json({ checkpoints: log.checkpoints });
    if (url.pathname === '/.well-known/jwks.json') return json({ keys: log.keys });
    if (url.pathname === '/api/public/count-log/leaves') {
      const from = Number(url.searchParams.get('from'));
      const to = Number(url.searchParams.get('to'));
      return json({ from, tree_size: 7, leaves: log.leaves.slice(from, to) });
    }
    if (url.pathname === '/api/public/count-log/withdrawn') return json({ withdrawn: [] });
    return new Response('{}', { status: 404 });
  }) as typeof fetch;
  const fetched = await fetchLog('https://example.com', fake);
  assert.equal(fetched.leaves.length, 7);
  assert.equal((await verifyLog(fetched)).ok, true);
  assert.ok(seen.includes('/api/public/count-log/leaves?from=0&to=7'));
  const missing = (async () => new Response('{}', { status: 404 })) as unknown as typeof fetch;
  await assert.rejects(fetchLog('https://example.com', missing), NotPublished);
  await assert.rejects(fetchLog('http://example.com', fake), /https/);
});

test('v2 checkpoints: the signature covers the body including subcounts_commitment', async () => {
  const { log } = await syntheticLog([3, 5]);
  const cp = log.checkpoints[1]!;
  assert.equal(cp.v, 2);
  assert.ok(!('subcounts' in cp));
  assert.match((cp as { subcounts_commitment: string }).subcounts_commitment, /^[0-9a-f]{64}$/);
  const report = await verifyLog(log);
  assert.deepEqual([report.problems, report.unchecked], [[], []]);
  // A changed commitment no longer matches the signed hash.
  const copy = clone(log);
  (copy.checkpoints[1] as { subcounts_commitment: string }).subcounts_commitment = 'ab'.repeat(32);
  assert.ok((await verifyLog(copy)).problems.some((p) => /hash does not match/.test(p)));
});

test('withheld v1 then v2: chain, consistency and inclusion are checked; v1 signatures are not checkable, not invalid', async () => {
  const { log, agents } = await syntheticLog([3, 5, 9], [1, 1, 2]);
  for (const cp of log.checkpoints.slice(0, 2)) {
    assert.equal((cp as { subcounts_withheld?: boolean }).subcounts_withheld, true);
    assert.ok(!('subcounts' in cp));
  }
  assert.equal(log.checkpoints[2]!.prev_hash, log.checkpoints[1]!.hash);
  const report = await verifyLog(log);
  assert.deepEqual(report.problems, []);
  assert.equal(report.ok, true);
  assert.deepEqual(report.unchecked, [
    '2026-09-20: signature not checkable, fields withheld',
    '2026-09-21: signature not checkable, fields withheld',
  ]);
  // Chain and consistency still catch tampering on withheld entries.
  const shrunk = clone(log);
  shrunk.checkpoints[1]!.tree_size = 4;
  assert.ok((await verifyLog(shrunk)).problems.some((p) => /append-only/.test(p)));
  const relinked = clone(log);
  relinked.checkpoints[1]!.hash = 'ee'.repeat(32);
  assert.ok((await verifyLog(relinked)).problems.some((p) => /does not link/.test(p)));
  // Inclusion against a withheld v1 root.
  const proofs = await Promise.all(
    [0, 1, 2].map(async (idx) => ({
      idx,
      leaf: await agentLeafHash(agents[idx]!.id, agents[idx]!.salt, agents[idx]!.day),
    })),
  );
  const leaves = log.leaves.slice(0, 3).map((l) => fromHex(l.leaf_hash));
  const path = await inclusionProof(leaves, 1);
  assert.ok(await verifyInclusion(proofs[1]!.leaf, 1, 3, path, fromHex(log.checkpoints[0]!.root)));
});
