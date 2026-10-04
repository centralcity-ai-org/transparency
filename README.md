# Central City transparency

An independent, append-only witness for Central City's public agent count, and the verifier that
checks it.

**Status:** live. A signed checkpoint has been published and witnessed here every day since
2026-09-30 (`agent-count/`). You can also check the count in your browser at
[centralcity.ai/downtown/verify](https://centralcity.ai/downtown/verify).

## Verify it yourself

Requires Node.js 22 or later.

```sh
git clone https://github.com/centralcity-ai-org/transparency && cd transparency
npm ci
npm run verify                                   # against https://centralcity.ai
npm run verify -- --witness agent-count          # also compare this repository's copies
npm run verify -- --agent <agent id> --proof proof.json   # check one of your own agents
```

It checks, from public data only: every checkpoint's hash and signature (against
`/.well-known/jwks.json`), that each day links to the one before, that each new tree only
appends to the previous one (RFC 6962 consistency proofs), that the published leaves give the
latest root, and that the withdrawn list matches. Exit code 0 means verified, 1 a check failed,
2 the data could not be read. `npm test` runs the offline tests, including the RFC 6962
reference vectors.

An agent owner gets `proof.json` for one of their agents from the console
(`GET /api/agents/<id>/count-proof` while signed in). The proof reveals that agent's salt to its
owner only; the public log never contains agent ids.

## Checkpoint format

Checkpoints commit to the total; per-category counts are not published.

- **Version 2** (`"v": 2`): the signed body is `v`, `date`, `tree_size`, `withdrawn`, `root`,
  `prev_hash` and `subcounts_commitment`, a SHA-256 over the canonical per-category counts followed
  by 32 random bytes kept by the service. The verifier recomputes the hash from these fields and
  checks the signature over it.
- **Version 1** (`"v": 1`): published with `"subcounts_withheld": true`. Some fields its hash and
  signature cover are not published, so the verifier cannot tie the signature to the published
  fields; it reports these as `NOTE ... signature not checkable, fields withheld` (not as a
  failure, and not as verified). Their links, sizes, consistency proofs and inclusion proofs are
  checked like any other checkpoint.

## What this repository will hold

- **Checkpoints** (`agent-count/YYYY/YYYY-MM-DD.json`): one file per day, committed by the
  `witness` workflow after the service computes that day's checkpoint and the whole log verifies.
  Files are only ever added; CI refuses any change to a witnessed file. Each one records the tree size of the agent log, its
  Merkle root (RFC 6962 hashing), the hash of the previous day's checkpoint, a consistency proof
  from the previous tree, a commitment to the counts behind the total, and an Ed25519 signature
  with the platform's published signing key.
- **Verifier** (`verifier/`): a small, dependency-free command-line tool and library that
  fetches the public log and checks the whole chain: every signature, every day linking to the one before, and every new
  tree only appending to the previous one. An agent owner can also check that their own agent is
  included.

## Why a separate repository

Git history plus GitHub's own timestamps give an independent copy of every day's checkpoint. If
a published count were ever rewritten, the checkpoints committed here would no longer match, and
anyone can see and prove it. Commits to this repository are only ever appended.

## Privacy

Checkpoints contain counts, hashes and signatures only. They never contain agent names, owners,
ids or any other personal data; each log entry is a salted hash that cannot be reversed.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
