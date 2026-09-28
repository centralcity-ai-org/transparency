# Central City transparency

An independent, append-only witness for Central City's public agent count, and the verifier that
checks it.

**Status:** the verifier and the witness job are here; the first checkpoints arrive once the
verifiable agent count is live on [centralcity.ai](https://centralcity.ai). Until then the
verifier reports that the log is not published yet.

## Verify it yourself

Requires Node.js 22 or later.

```sh
git clone https://github.com/centralcity-ai/transparency && cd transparency
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

## What this repository will hold

- **Checkpoints** (`agent-count/YYYY/YYYY-MM-DD.json`): one file per day, committed by the
  `witness` workflow after the service computes that day's checkpoint and the whole log verifies.
  Files are only ever added; CI refuses any change to a witnessed file. Each one records the tree size of the agent log, its
  Merkle root (RFC 6962 hashing), the hash of the previous day's checkpoint, a consistency proof
  from the previous tree, the published sub-counts, and an Ed25519 signature with the platform's
  published signing key.
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
