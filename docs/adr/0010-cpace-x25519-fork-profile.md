---
status: proposed
date: 2026-07-03
source-review-runs:
  - 20260703T060754-abacf596cb5ecc28864da9d5 # ras review on PR #2 found the missing fork-profile ADR
  - 20260703T132521-d2e052b0dcd91af00847982e # ras consider — accepted shape requires ADR text revisions before acceptance
---

# CPACE-X25519-SHA512 fork profile

## Status

**Proposed (2026-07-03).** This ADR records the X25519 fork profile already implemented on PR #2 so it can receive the independent `ras consider` gate required by this repository's ADR policy before it is marked accepted. The profile touches wire bytes, package identity, generator mapping, crypto backend and dependency graph, scalar behavior, low-order peer-share handling, retained error sentinels, and release-evidence posture; until this ADR is accepted, treat it as the review target rather than a ratified policy exception.

**Maintainer direction recorded during PR #2 fix pass.** The fork-specific release helper and documentation now use the SBOM asset prefix `cpace-x25519-<tag>.cdx.json` rather than the inherited `cpace-<tag>.cdx.json`. This records the maintainer-directed fix for fork identity; broader ADR acceptance for the full X25519 profile still requires the independent `ras consider` gate.

## Context

This repository is a fork of `github.com/the-sarge/cpace` for a single CPACE-X25519-SHA512 package profile. The inherited ADRs, evidence, and release docs were written for the original Ristretto255 implementation and contain accepted decisions about the original module's pre-v1 API and release process. The fork has no cpace-x25519 release tags; inherited `v0.1.x` tags from the parent were removed from this repository and are historical source-control context only.

The public API and package-profile policy are otherwise frozen except accepted ADR exceptions. The X25519 fork changes observable protocol behavior relative to the parent, so the decision needs an ADR rather than relying on scattered implementation comments or inherited Ristretto ADRs.

## Decision

Implement exactly one suite: `CPACE-X25519-SHA512` from `draft-irtf-cfrg-cpace-21`, initiator-responder mode only.

Use `currentSuite = 0x02` as the package-owned wire suite byte for this fork. The inherited Ristretto package used `0x01`; this fork intentionally does not preserve wire compatibility with parent-module releases.

The suite-byte registry is fork-local from this ADR forward: `0x01` is retired here as the parent Ristretto assignment, `0x02` is `CPACE-X25519-SHA512`, and no coordination with future parent-module byte assignments is implied.

Use `suiteName = "CPACE-X25519-SHA512"` in package-owned CI construction, `G_X25519.DSI = "CPace255"` for generator derivation, and `DSI_ISK = "CPace255_ISK"` for ISK derivation.

Derive generators by hashing the draft generator string to SHA-512, taking the first 32 bytes, and applying the draft Curve25519 Elligator2 mapping using `filippo.io/edwards25519/field` field arithmetic.

Implement X25519 scalar multiplication with a package-local Montgomery ladder over `filippo.io/edwards25519/field`, not `crypto/ecdh` or `golang.org/x/crypto/curve25519`. The rationale is to keep the fork's dependency graph to one field-arithmetic dependency, retain arbitrary-base scalar-multiplication control for the CPace generator path, retain local zeroization control for clamped scalar bytes, and avoid adding the deprecated external Curve25519 dependency; this local ladder and generator mapping remain in the independent cryptographic review scope documented in `docs/security-assessment.md`.

Sample scalars as 32 random bytes and rely on X25519 clamping inside scalar multiplication. Do not reduce or reject scalar byte strings before the ladder.

Validate X25519 peer public shares by enforcing exact 32-byte share length and rejecting all-zero shared-secret output from the ladder. `Respond` prevalidates the initiator share with a fixed public validation scalar before responder generator derivation and scalar sampling; this preserves validate-before-randomness while avoiding a decoded-share reuse story from the parent Ristretto profile.

Surface X25519 low-order peer shares as `ErrAbort` plus `ErrPeerShareIdentity` with initiator/responder role context. Keep `ErrPeerShareEncoding` exported for API continuity with the parent-module surface ratified by ADR-0003, easing import-path migration and preserving freeze-era API stability; pre-tag removal was considered and rejected because exact-length X25519 public shares normally reach the ladder rather than a non-canonical point decoder, so this sentinel is not expected from the production X25519 public-share path. Malformed wire lengths remain `ErrMessage` from framing; internal wrong-length validation branches remain defensive `ErrAbort` errors without peer-share sentinels.

Treat inherited dependency-review, fuzz, Capslock, security/spec audit, OSS-Fuzz validation, and release-readiness evidence as stale for cpace-x25519 release claims. Any stronger release claim needs refreshed evidence against the exact cpace-x25519 candidate commit.

Keep the first cpace-x25519 releases in the `v0.x` range and do not claim production readiness until independent cryptographic review and the refreshed evidence lanes are complete.

## Consequences

The fork is protocol-incompatible with the parent Ristretto module by design. The module path, suite byte, suite name, DSI strings, dependency graph, generator mapping, scalar behavior, vectors, invalid-share behavior, release helper expectations, and evidence posture all need to be audited as cpace-x25519-specific.

ADR-0002 remains the accepted parent-profile decision to remove dead exported suite API before v1.0.0, but its literal `0x01` wire-suite acceptance criteria are superseded for this fork by this ADR's `0x02` X25519 profile.

ADR-0003 remains the accepted parent-profile decision to add peer-share sentinels and nil-on-failure helper behavior, but its Ristretto non-canonical decoding examples are refined for this fork: `ErrPeerShareIdentity` is the live X25519 low-order signal, while `ErrPeerShareEncoding` is retained exported API surface rather than a normal X25519 ladder outcome.

ADR-0007 remains the accepted release-artifact architecture, but the release-managed SBOM asset prefix for this fork is `cpace-x25519-<tag>.cdx.json` so release assets match the forked module and repository identity.

## Acceptance criteria

- An independent `ras consider` review concurs with this ADR, or maintainers resolve its findings and a follow-up verification is clean enough to flip `status: accepted`.
- `go.mod` module path is `github.com/the-sarge/cpace-x25519`.
- `api.go`, `framing.go`, and wire-format tests pin `currentSuite == wireSuite == 0x02`.
- `crypto.go`, `go.mod`, and `docs/security-assessment.md` agree that X25519 scalar multiplication uses a package-local Montgomery ladder over `filippo.io/edwards25519/field` and remains in independent cryptographic review scope.
- Draft X25519 generator, protocol, low-order, and confirmation-tag tests are backed by hash-pinned fixtures, with confirmation tags stored as literal goldens rather than computed from the implementation under test.
- Docs that discuss inherited dependency, fuzz, security/spec, Capslock, OSS-Fuzz, and release evidence clearly say the evidence is historical parent-module signal and stale for cpace-x25519 release claims.
- Release helper tests and release verification docs use `cpace-x25519-<tag>.cdx.json` and `the-sarge/cpace-x25519`.
