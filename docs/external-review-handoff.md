# External Review Handoff

Date: 2026-07-03

Target module: `github.com/the-sarge/cpace-x25519`

Last released tag: none for the cpace-x25519 module.

Inherited tags from `github.com/the-sarge/cpace` are historical source-control context only and are not cpace-x25519 releases.

Current evidence baseline: see `docs/evidence-baseline.md`. The inherited `github.com/the-sarge/cpace` evidence bundle under `docs/evidence/f7efa6a-20260619/` predates the X25519 port and is stale for cpace-x25519 release claims.

Evidence status: implementation tests pass locally, but dependency review, fuzz evidence, Capslock, and security/spec audit must be refreshed against an exact cpace-x25519 candidate before any stronger release-readiness claim.

Review the package code after the X25519 port branch lands on `main`; do not treat inherited Ristretto evidence as applying to the forked cryptographic code.

Status: auditable draft implementation. This package has not had independent
cryptographic review and is not production-ready.

## Review Goal

The immediate review goal is external review of the package-owned choices around
CPace draft-21 integration, wire framing, caller-facing profile policy, and
release evidence. This is separate from, and does not replace, independent
cryptographic review before any production-ready claim.

## Primary References

- `README.md` for the public API contract, integration warnings, and validation
  commands.
- `docs/security-assessment.md` for the current security self-assessment.
- `docs/spec-matrix.md` for the draft-21 requirement mapping.
- `docs/security-spec-audit.md` for the latest internal security/spec audit.
- `docs/threat-model.md` for assets, attackers, non-goals, and security
  boundaries.
- `docs/integration-guidance.md` for outer negotiation, downgrade protection, role-local identity input, and session-output guidance.
- `docs/dependency-review.md` for dependency and vulnerability scan evidence.
- `docs/fuzz-evidence.md` for local smoke and long-fuzz campaign evidence.
- `docs/capslock-report.md` for static capability-analysis evidence.
- `docs/evidence-baseline.md` for the current pinned evidence baseline and stale-trigger index.
- `docs/evidence/f7efa6a-20260619/` for the current exact-candidate raw evidence bundle and SHA-256 digests.
- `docs/evidence/v012-candidate-20260508/` for raw v0.1.2 candidate transcript
  files and SHA-256 digests.
- `docs/evidence/v012-soak-20260509/` for raw v0.1.2 supplemental fuzz soak
  transcripts and SHA-256 digests, including the iMacPro all-target non-pass
  and clean same-host targeted `FuzzProtocolConsistency` rerun.
- `docs/performance.md` for local benchmark and allocation-measurement guidance.
- `docs/ci-policy.md` for hosted-runner policy, advisory lanes, long-fuzz
  evidence, and signed release tags.
- `docs/release-checklist.md` for exact-candidate release evidence steps.
- `testdata/generate_sage_x25519_vectors.sage` and `testdata/sage-x25519-extended.json` for the reproducible SageMath-derived extended X25519 oracle fixture.

## Implemented Scope

The package implements only `CPACE-X25519-SHA512` from
`draft-irtf-cfrg-cpace-21`.

The public API exposes initiator-responder mode only. A session is returned
only after explicit key confirmation succeeds. `Respond` returning success is
not authentication.

The package is intentionally not a generic CPace framework. It does not expose other CPace suites, Ristretto255/X448/NIST curves, symmetric mode, a raw-CI API, or application negotiation. Applications must provide downgrade protection for any outer negotiation that happens before CPace inputs are fixed.

## Package-Owned Choices To Review

- `cpace-go` CI construction from draft version, suite, role labels, role-local party identities, and caller context.
- Binary wire framing with format byte `0xc1`, suite and role bytes, and
  draft LEB128 length-value fields.
- Non-configurable per-field size caps: passwords and party IDs at 4 KiB,
  context and session IDs at 1 KiB, associated data at 64 KiB, and exact-sized
  public shares and confirmation tags.
- Default rejection of empty `SessionID`, with `AllowEmptySessionID` kept only
  for draft-21 compatibility or deliberately compatible profiles.
- Draft-compatible confirmation tag inputs, with no package-added role labels
  in the confirmation MACs.
- Scalar sampling profile: read 32 random bytes and clamp inside the X25519 ladder.
- X25519 low-order public-share handling: reject all-zero scalar-multiplication output with `ErrAbort` and `ErrPeerShareIdentity`, with responder-side fixed-scalar prevalidation before randomness.
- `Session.Export` as HKDF-SHA512 over the confirmed ISK, and
  `Session.TranscriptID` as the draft `CPaceSidOutput` rather than a complete
  channel binding for outer negotiation.
- Best-effort session key cleanup through `Session.Close`, with no claim of
  resistance to local memory disclosure under the Go runtime.

## Evidence Snapshot

The current inherited package-code evidence baseline and freshness caveats are indexed in `docs/evidence-baseline.md`. The `f7efa6a963a954952b1ecad3f46530f13799fe89` bundle refreshes dependency review, long fuzzing, Capslock, security/spec audit support, tag-ruleset capture, GitHub status, Scorecard, and vector stability for the original Ristretto implementation. The X25519 fork changes protocol behavior, dependency graph, and vectors, so repeat those lanes before any production-readiness or release-current claim.

Capslock capability-analysis evidence is recorded in `docs/capslock-report.md`; its pinned baseline and freshness caveat are indexed in `docs/evidence-baseline.md`.

OSS-Fuzz onboarding needs a fresh cpace-x25519 submission. The inherited `google/oss-fuzz#15480` context was for the original `cpace` project and does not establish fork readiness.

The SageMath-derived extended vector fixture under `testdata/sage-x25519-extended.json` adds a code-lineage-independent oracle for generator derivation, random/twist/low-order/non-canonical X25519 scalar multiplication, and full package-profile exchange ISK/tag/message outputs. It is reproducible with the pinned Docker/Sage command recorded in the fixture metadata and generator script. This strengthens test coverage and reviewer inspection material, but it is not a substitute for independent cryptographic review or exact-candidate dependency/fuzz/security evidence refresh.

## Review Questions

- Is the package-owned CI construction appropriate for a Go package profile over draft-21, and are the role-local identity-input requirements clear enough for real integrations?
- Is the binary wire framing unambiguous, injective for the represented fields,
  and sufficiently future-versioned?
- Are the per-field size caps reasonable for a library API, and are the
  associated-data warnings sufficient to keep callers from treating AD as a
  large payload channel?
- Is default rejection of empty session IDs the right package posture while
  preserving explicit draft compatibility?
- Are the scalar sampling, invalid-point handling, confirmation, exporter, and
  session lifecycle claims in the docs accurate and complete?
- Are the CI, dependency, fuzz, and release-tag controls sufficient evidence for
  an auditable prerelease, assuming independent cryptographic review remains
  required?

## Remaining Release Blockers

- Complete external review of package-owned framing, CI construction, and
  profile choices.
- Obtain independent cryptographic review before any production-ready claim.
- Refresh exact-release dependency review, long fuzz evidence, Capslock
  capability evidence, and security/spec audit after review-driven or
  security-relevant changes before any production-readiness claim.
- Resolve any critical or high review findings before moving beyond the `v0.x`
  prerelease line.
