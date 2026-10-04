import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import {
  type Checkpoint,
  type CheckpointBody,
  type PublicCheckpoint,
  type PublicCheckpointV2,
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
  V1_LAST_DATE,
  verifyChain,
  verifyConsistency,
  verifyInclusion,
} from '../verifier/count-log.js';
import {
  compareWitness,
  resultLine,
  sameWitnessedDay,
  verifyAgent,
  verifyLog,
  witnessFile,
  witnessPlan,
  type Checkpoint as VerifiedCheckpoint,
  type PublicLog,
} from '../verifier/verify.js';

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
async function syntheticLog(
  sizes: number[],
  versions: (1 | 2)[] = sizes.map(() => 2),
  options: { full?: boolean } = {},
) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string }), kid: 'test-key' };
  const agents = Array.from({ length: Math.max(...sizes) }, (_, idx) => ({
    id: randomUUID(),
    salt: randomBytes(32),
    day: `2026-09-${String(10 + Math.floor(idx / 3)).padStart(2, '0')}`,
  }));
  const leafHashes = await Promise.all(agents.map((a) => agentLeafHash(a.id, a.salt, a.day)));
  const checkpoints: VerifiedCheckpoint[] = [];
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
      // v2 starts a new chain: the first v2 checkpoint after v1 has no previous hash.
      prev_hash:
        versions[index] === 2 && versions[index - 1] === 1 ? null : ((previous?.hash ?? null) as string | null),
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
    // full: a legacy service that still served v1 with its counts.
    checkpoints.push(options.full ? checkpoint : toPublicCheckpoint(checkpoint));
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
/** A published v2 checkpoint (these synthetic logs are v2 unless versions say otherwise). */
const v2 = (cp: VerifiedCheckpoint | undefined) => cp as PublicCheckpointV2;

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
    ['chain', (l) => (v2(l.checkpoints[2]).prev_hash = '11'.repeat(32)), /does not link|hash does not match/],
    ['signature', (l) => (v2(l.checkpoints[0]).signature!.sig = v2(l.checkpoints[1]).signature!.sig), /bad signature/],
    ['key', (l) => (l.keys[0]!.kid = 'other'), /is not published/],
    ['unsigned', (l) => (v2(l.checkpoints[2]).signature = null), /not signed/],
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
  const forged = v2(clone(other.log.checkpoints[1]));
  forged.prev_hash = v2(log.checkpoints[0]).hash;
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

test('withheld v1 then v2: sizes, consistency and inclusion are checked; v1 entries are not checkable, not invalid', async () => {
  const { log, agents } = await syntheticLog([3, 5, 9], [1, 1, 2]);
  for (const cp of log.checkpoints.slice(0, 2)) {
    assert.deepEqual(Object.keys(cp), [
      'v',
      'date',
      'tree_size',
      'withdrawn',
      'root',
      'subcounts_withheld',
      'signature_withheld',
      'consistency',
    ]);
    // No hash, signature or link is published for a v1 checkpoint; the only digests left are
    // tree nodes.
    for (const hex of JSON.stringify(cp).match(/[0-9a-f]{64}/g) ?? [])
      assert.ok(hex === cp.root || cp.consistency.includes(hex), hex);
  }
  const report = await verifyLog(log);
  assert.deepEqual(report.problems, []);
  assert.equal(report.ok, true);
  assert.deepEqual(report.unchecked, [
    '2026-09-20: not checkable (v1, signature withheld for privacy)',
    '2026-09-21: not checkable (v1, signature withheld for privacy)',
  ]);
  // Consistency still catches tampering on withheld entries.
  const shrunk = clone(log);
  shrunk.checkpoints[1]!.tree_size = 4;
  assert.ok((await verifyLog(shrunk)).problems.some((p) => /append-only/.test(p)));
  const rerooted = clone(log);
  rerooted.checkpoints[0]!.root = 'ee'.repeat(32);
  assert.ok((await verifyLog(rerooted)).problems.some((p) => /append-only/.test(p)));
  // Inclusion against a withheld v1 root.
  const leaf = await agentLeafHash(agents[1]!.id, agents[1]!.salt, agents[1]!.day);
  const leaves = log.leaves.slice(0, 3).map((l) => fromHex(l.leaf_hash));
  const path = await inclusionProof(leaves, 1);
  assert.ok(await verifyInclusion(leaf, 1, 3, path, fromHex(log.checkpoints[0]!.root)));
});

test('v2 starts a new chain: only the first v2 checkpoint has no previous hash', async () => {
  const { log } = await syntheticLog([3, 5, 9, 12], [1, 1, 2, 2]);
  const [, , first, second] = log.checkpoints as [unknown, unknown, Checkpoint, Checkpoint];
  assert.equal(first.prev_hash, null);
  assert.equal(second.prev_hash, first.hash);
  assert.deepEqual((await verifyLog(log)).problems, []);
  // A first v2 checkpoint that links to something else is rejected.
  const linked = clone(log);
  const body = { ...(linked.checkpoints[2] as Checkpoint), prev_hash: 'cd'.repeat(32) };
  const { hash: _h, signature: _s, consistency: _c, ...rest } = body;
  linked.checkpoints[2] = { ...body, hash: await checkpointHash(rest as CheckpointBody) } as PublicCheckpoint;
  assert.ok((await verifyLog(linked)).problems.some((p) => /first v2 checkpoint/.test(p)));
  // A later v2 checkpoint may not start another chain.
  const restarted = clone(log);
  (restarted.checkpoints[3] as Checkpoint).prev_hash = null;
  assert.ok((await verifyLog(restarted)).problems.some((p) => /does not link|hash does not match/.test(p)));
});

test(`a v1 checkpoint dated after ${V1_LAST_DATE} fails; on that day it is valid`, async () => {
  const { log } = await syntheticLog([3, 5], [1, 1]);
  const onCutoff = clone(log.checkpoints);
  onCutoff[1]!.date = V1_LAST_DATE;
  assert.deepEqual(await verifyChain(onCutoff), []);
  const late = clone(log);
  late.checkpoints[1]!.date = '2026-10-05';
  const report = await verifyLog(late);
  assert.equal(report.ok, false);
  assert.ok(
    report.problems.some((p) => p.startsWith('2026-10-05: a v1 checkpoint after 2026-10-04')),
    report.problems.join('; '),
  );
});

test('the CLI result is never a plain VERIFIED when entries were not checkable', () => {
  assert.equal(resultLine({ ok: true, unchecked: [] }), 'RESULT: VERIFIED');
  assert.equal(resultLine({ ok: true, unchecked: ['a'] }), 'RESULT: VERIFIED (1 entry not checkable: withheld)');
  assert.equal(
    resultLine({ ok: true, unchecked: ['a', 'b', 'c'] }),
    'RESULT: VERIFIED (3 entries not checkable: withheld)',
  );
  assert.equal(resultLine({ ok: false, unchecked: ['a'] }), 'RESULT: FAILED');
});

test('witness: per-category counts are never witnessed; older copies of withheld v1 days still match', async () => {
  const { log } = await syntheticLog([3, 5, 9], [1, 1, 2]);
  const v1 = log.checkpoints[0]!;
  // An older copy of the same day, with fields the service no longer publishes.
  const { signature_withheld: _w, ...base } = v1 as PublicCheckpoint & { signature_withheld?: true };
  const older = { ...base, prev_hash: null, hash: 'ab'.repeat(32), signature: { kid: 'test-key', sig: 'x' } };
  const content = `${JSON.stringify(older, null, 2)}\n`;
  assert.equal(sameWitnessedDay(content, v1), true);
  assert.deepEqual(
    compareWitness('agent-count', new Map([['agent-count/2026/2026-09-20.json', content]]), log.checkpoints),
    [],
  );
  // Every field still published must match.
  assert.equal(sameWitnessedDay(content.replace('"tree_size": 3', '"tree_size": 4'), v1), false);
  assert.equal(sameWitnessedDay(content, { ...v1, root: 'ee'.repeat(32) }), false);
  // A v2 day matches byte for byte only.
  const v2 = log.checkpoints[2]!;
  assert.equal(sameWitnessedDay(witnessFile('agent-count', v2).content, v2), true);
  assert.equal(sameWitnessedDay(witnessFile('agent-count', v2).content.replace(/\n$/, ''), v2), false);
  // The witness job refuses to write a checkpoint with per-category counts (and writes nothing).
  const full = { ...v1, subcounts: { in_person_accounts: 1, in_ai_workspaces: 1, unclaimed: 1, revoked: 0 } };
  const plan = witnessPlan('agent-count', [full as unknown as Checkpoint, v2], () => undefined);
  assert.deepEqual(plan.refused, ['2026-09-20']);
  assert.deepEqual(plan.add, []);
  const clean = witnessPlan('agent-count', log.checkpoints, () => undefined);
  assert.deepEqual([clean.refused, clean.add.length], [[], 3]);
});

test('a full legacy v1 log (served before the withheld form) is checked as before and does not crash', async () => {
  const { log } = await syntheticLog([3, 5], [1, 1], { full: true });
  for (const cp of log.checkpoints) assert.ok('subcounts' in cp && 'hash' in cp);
  const report = await verifyLog(log);
  assert.deepEqual([report.problems, report.unchecked], [[], []]);
  assert.equal(resultLine(report), 'RESULT: VERIFIED');
  // Its hash and signature are checked.
  const badSig = clone(log);
  v2(badSig.checkpoints[0]).signature!.sig = v2(badSig.checkpoints[1]).signature!.sig;
  assert.ok((await verifyLog(badSig)).problems.some((p) => /bad signature/.test(p)));
  const badCount = clone(log);
  badCount.checkpoints[1]!.tree_size = 6;
  assert.ok((await verifyLog(badCount)).problems.some((p) => /hash does not match/.test(p)));
  // Comparing witness files against it does not throw. Files witnessed in the withheld form
  // (older, with hash and signature, or current, without) are the same day; a different hash is not.
  const current = new Map<string, string>();
  const older = new Map<string, string>();
  for (const cp of log.checkpoints) {
    const path = witnessFile('agent-count', cp).path;
    const { subcounts: _s, ...rest } = cp as Checkpoint & { subcounts: unknown };
    current.set(path, witnessFile('agent-count', { ...toPublicCheckpoint(cp as Checkpoint) }).content);
    older.set(path, `${JSON.stringify({ ...rest, subcounts_withheld: true }, null, 2)}\n`);
  }
  assert.deepEqual(compareWitness('agent-count', current, log.checkpoints), []);
  assert.deepEqual(compareWitness('agent-count', older, log.checkpoints), []);
  const [firstPath, firstContent] = [...older][0]!;
  const tampered = new Map([[firstPath, firstContent.replace(/"hash": "[0-9a-f]+"/, `"hash": "${'ab'.repeat(32)}"`)]]);
  assert.equal(compareWitness('agent-count', tampered, log.checkpoints).length, 1);
  // A witnessed file that carries the counts still matches the same full day (it is not rewritten).
  const fullFile = witnessFile('agent-count', log.checkpoints[0]!).content;
  assert.equal(sameWitnessedDay(fullFile, log.checkpoints[0]!), true);
  assert.equal(sameWitnessedDay(fullFile, toPublicCheckpoint(log.checkpoints[0] as Checkpoint)), true);
  // The witness job refuses to write any of it.
  assert.deepEqual(witnessPlan('agent-count', log.checkpoints, () => undefined).refused, ['2026-09-20', '2026-09-21']);
});

test('the witnessed agent-count files form a valid withheld v1 chain', async () => {
  const folder = new URL('../agent-count/2026/', import.meta.url);
  const files = readdirSync(folder)
    .filter((name) => name.endsWith('.json'))
    .sort();
  assert.ok(files.length > 0);
  const published: PublicCheckpoint[] = [];
  for (const name of files) {
    const content = readFileSync(new URL(name, folder), 'utf8');
    const witnessed = JSON.parse(content) as Record<string, unknown>;
    assert.ok(!('subcounts' in witnessed), name);
    // The form the service publishes for that day now.
    const live = {
      v: 1,
      date: witnessed.date,
      tree_size: witnessed.tree_size,
      withdrawn: witnessed.withdrawn,
      root: witnessed.root,
      subcounts_withheld: true,
      signature_withheld: true,
      consistency: witnessed.consistency,
    } as PublicCheckpoint;
    assert.equal(sameWitnessedDay(content, live), true, name);
    assert.ok(live.date <= V1_LAST_DATE, name);
    published.push(live);
  }
  assert.deepEqual(await verifyChain(published), []);
});
