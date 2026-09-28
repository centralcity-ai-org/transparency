# Central City transparency

An independent, append-only witness for Central City's public agent count, and the verifier that
checks it.

**Status:** set up. The daily checkpoints and the verifier arrive here once the verifiable agent
count ships on [centralcity.ai](https://centralcity.ai).

## What this repository will hold

- **Checkpoints** (`checkpoints/YYYY/YYYY-MM-DD.json`): one file per day, committed after the
  service computes that day's checkpoint. Each one records the tree size of the agent log, its
  Merkle root (RFC 6962 hashing), the hash of the previous day's checkpoint, a consistency proof
  from the previous tree, the published sub-counts, and an Ed25519 signature with the platform's
  published signing key.
- **Verifier**: a small, dependency-free command-line tool and library that fetches the public log
  and checks the whole chain: every signature, every day linking to the one before, and every new
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
