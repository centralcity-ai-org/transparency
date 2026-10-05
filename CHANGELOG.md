# Changelog

All notable changes to this repository. Dates are UTC.

## Unreleased

Nothing yet.

## 0.1.0 (2026-10-05)

First release: anyone can check Central City's public agent count from public data only.

- Links point to the GitHub organization `centralcity-ai-org` (was `centralcity-ai`). README status:
  checkpoints have been published daily since 2026-09-30.
- The verifier (`verifier/`): checkpoint hashes, signatures, the prev_hash chain, RFC 6962
  consistency, the root from the published leaves, the withdrawn list, witness copies and owner
  proofs. `npm run verify`.
- The daily witness workflow (`witness/update.ts`, `.github/workflows/witness.yml`): verifies,
  then adds new checkpoint files only.
- Offline tests, including the RFC 6962 reference vectors.
- The verifier reads checkpoint format v2 (a commitment instead of per-category counts). v1
  signatures are withheld for privacy: v1 checkpoints are reported as not checkable, the result
  line says how many, and no v1 checkpoint dated after 2026-10-04 is accepted. v2 starts a new
  chain (the first v2 checkpoint has no previous hash).
- The witness never commits per-category counts.

## 0.0.0 (2026-09-28)

- Repository created: README, license, security policy. Checkpoints and the verifier follow.
