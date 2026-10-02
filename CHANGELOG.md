# Changelog

All notable changes to this repository. Dates are UTC.

## Unreleased

- Links point to the GitHub organization `centralcity-ai-org` (was `centralcity-ai`). README status:
  checkpoints have been published daily since 2026-09-30.
- The verifier (`verifier/`): checkpoint hashes, signatures, the prev_hash chain, RFC 6962
  consistency, the root from the published leaves, the withdrawn list, witness copies and owner
  proofs. `npm run verify`.
- The daily witness workflow (`witness/update.ts`, `.github/workflows/witness.yml`): verifies,
  then adds new checkpoint files only.
- Offline tests, including the RFC 6962 reference vectors.

## 0.0.0 (2026-09-28)

- Repository created: README, license, security policy. Checkpoints and the verifier follow.
