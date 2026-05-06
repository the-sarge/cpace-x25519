# Project Plan

Status: living plan after the decision-free hardening workstreams landed in
PRs #2-#8.

This document tracks current work. Historical review triage remains in
`docs/interview-results-triage.md`.

## Current Phase

The next phase is policy and API decisions. Do not implement these as incidental
cleanup: each item changes package semantics, compatibility, or caller
responsibility.

## Policy Decisions

| Area | Current behavior | Decision needed |
| --- | --- | --- |
| `Config.Rand` | Public `io.Reader` hook accepted for scalar randomness; nil uses `crypto/rand.Reader`. | Keep public with stronger docs, remove from public API, or require an explicit unsafe/test opt-in for custom readers. |
| Empty `SessionID` | Accepted for draft-21 compatibility and documented as weaker. | Keep draft-permissive behavior, or reject empty values by default with an explicit compatibility escape hatch. |
| `Session.Discard()` | No public session-destruction method; internal consumed state is cleared best-effort. | Add a public lifecycle method that clears `Session.isk` and makes future `Export` fail, or keep the session API minimal. |
| Peer associated data | Peer AD is bound into transcripts but not exposed through accessors. | Add accessors to reduce application-layer mistakes, or keep messages opaque. |
| Confirmation tag role separation | Draft-compatible tag input is unchanged. | Keep draft-compatible tags, or add role labels as a package-profile hardening break. |
| `maxFieldLength` | Parser cap is 1 MiB. | Keep, lower, or make configurable. |
| Scalar sampling | Masked canonical 32-byte sampling with zero retry. | Keep for draft conformance, or investigate a `SetUniformBytes`-based approach and prove compatibility/distribution properties. |

## Recommended PR Order

1. `Config.Rand` policy.
   This has the largest impact on timing analysis, test hooks, and caller
   footguns.

2. Empty `SessionID` policy.
   Decide whether draft compatibility remains the default or moves behind an
   explicit compatibility option.

3. Session lifecycle and peer-data API.
   Consider `Session.Discard()` and peer associated-data accessors together
   because both are public API surface changes.

4. Framing and confirmation profile choices.
   Decide `maxFieldLength` and confirmation tag role separation after the
   compatibility posture is explicit.

5. Scalar sampling investigation.
   Treat any change as a protocol-conformance project, not a mechanical
   refactor. Keep this separate from API policy changes.

## Release Readiness

Before any production-readiness claim:

- run every fuzz target for more than five minutes on release hardware or in
  the long-fuzz workflow;
- repeat dependency review with `govulncheck -test -show verbose ./...`;
- review `docs/security-assessment.md` and `docs/spec-matrix.md` against the
  exact release commit;
- complete external review of package-owned framing and profile choices;
- obtain independent cryptographic review.

## Later Investigation

- OpenSSF Scorecard.
- CodeQL.
- Capslock.
- OSS-Fuzz.
- Offline Sage-derived extended vector dataset.
- Allocation measurements on hot paths before adding permanent allocation
  tests.
