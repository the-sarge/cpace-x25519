---
status: proposed
---

# Disposition of the `Suite` type before v1.0.0 freeze

## Status

**Proposed — recorded, not yet enforced.** This ADR captures a v1.0.0 freeze decision surfaced by external code review (item B1) so the reasoning is preserved. It is deliberately *not* binding: it stays `proposed` until an independent multi-agent review (`ras consider`) of this ADR concurs. Only then does it move to `accepted`, at which point the v1.0.0 public surface is settled on this point and future reviews should not re-litigate it. If the review dissents, this ADR is revised or rejected instead.

## Context

`api.go:22-28` exports `Suite byte` together with the single constant `SuiteCPaceRistretto255SHA512 Suite = 0x01`. No exported function takes a `Suite` parameter, no exported method returns a `Suite`, and no `Config` field has type `Suite`. The constant is used internally only at `framing.go:7` as `wireSuite byte = byte(SuiteCPaceRistretto255SHA512)`, where the type is immediately discarded.

The shape was added in anticipation of a future multi-suite version of cpace. Today the package supports exactly one suite (CPACE-RISTR255-SHA512) and the threat model, docs, and tests all reflect that. The public API and profile policy are frozen for v1.0.0 unless this review reopens them, and any post-freeze change to this type is breaking.

The deferred problem: shipping `Suite` exported but unused commits the project to one of two long-term outcomes. Either a future multi-suite version threads `Suite` through `Config`/`Start`/`Respond` (which is non-breaking *only* if zero values are reserved for "current suite" *now*), or the type is eventually unexported (breaking). There is no third escape — the type's exported status is observable.

## Decision

Unexport `Suite` and `SuiteCPaceRistretto255SHA512` before v1.0.0. Rename `Suite → suite` and `SuiteCPaceRistretto255SHA512 → currentSuite` (or similar internal-only names). The single use site at `framing.go:7` simplifies to `wireSuite byte = currentSuite`.

When (if) a future version of cpace supports multiple suites, the project re-introduces an exported `Suite` enum at that time with a deliberately-chosen multi-suite negotiation surface (e.g., `Config.Suite Suite` with a documented zero-value that maps to the current suite, or a `StartSuite(suite, cfg)` constructor). Re-exporting a previously-unexported type is non-breaking; removing or repurposing a previously-exported type is breaking. Doing the cheap-now thing preserves both choices.

This ADR rejects the option of threading `Suite` through `Config`/`Start`/`Respond` *now* on the grounds that the multi-suite negotiation design (zero-value semantics, suite-mismatch error path, downgrade-attack story for outer negotiation) is not load-bearing for v1.0.0 and committing to it before there are multiple suites means committing without evidence.

## Acceptance criteria

The implementation must satisfy these before this ADR moves `proposed → accepted` *and* before v1.0.0 is tagged:

- **No exported symbol** named `Suite`, `SuiteCPaceRistretto255SHA512`, or any other Suite-typed identifier remains in `api.go`, `doc.go`, or any other file under the repo root.
- **`framing.go` still constructs the wire byte** from the internal constant; the wire format is unchanged (still `0xc1 || 0x01 || role || ...`).
- **`docs/spec-matrix.md`, `docs/security-assessment.md`, and `README.md`** are updated to describe the single-suite scope without using exported-`Suite` terminology.
- **`CHANGELOG.md` Unreleased** records the unexport as a breaking change relative to the unreleased state (no released `v0.x` exposed `Suite` differently, so this is a pre-v1 cleanup, not a `v1.x.x` break).

## Considered options

- **A — Unexport now (recommended).** Removes the API surface tax, preserves both futures (re-export later or stay single-suite). Cost: ~5 LoC, one CHANGELOG entry.

- **B — Thread `Suite` through `Config` now.** Adds `Config.Suite Suite` defaulting to `SuiteCPaceRistretto255SHA512` (requires either remapping the constant to `0x00` so zero-value works, or treating `0x00` as "current" and leaving `0x01` as the explicit current-suite identifier). Locks in multi-suite negotiation semantics — zero-value default, suite-mismatch error code, outer-negotiation downgrade story — without a second suite to validate the design against.

- **C — Status quo.** Leaves `Suite` exported and unused for v1.0.0. Future multi-suite work then has to either thread through `Suite` (which would have been Option B done late) or unexport (which would have been Option A done late, but now breaking).

## Consequences

- **Option A (recommended):**
  - One-time breaking change relative to the *unreleased* tree. `v0.x` consumers are not affected (the `Suite` type is reachable from `v0.x` releases but the constant has not migrated through any API).
  - Re-exporting the type later costs only a doc note and a `CHANGELOG` entry.
  - `framing.go` and tests already do not depend on the exported shape.

- **Option B:**
  - Locks `Config.Suite` semantics for v1.0.0 with no second suite to validate against.
  - Forces a decision on zero-value defaulting *now* (rename `SuiteCPaceRistretto255SHA512` to `0x00`, or accept that zero is invalid and require callers to set it explicitly).
  - Adds a documented suite-mismatch error path that has no testable wire-format outcome until a second suite exists.

- **Option C:**
  - Defers cost to v2.x or later, but the deferred cost is strictly worse: a v2.0.0 unexport is a breaking change that *did* propagate through a stable release.
  - Carries permanent doc footnote ("`Suite` is reserved for future use") for the lifetime of v1.x.

## Implementation outline (Option A)

1. Rename `Suite` → `suite` and `SuiteCPaceRistretto255SHA512` → `currentSuite` in `api.go`.
2. Update `framing.go:7` to `wireSuite byte = currentSuite`.
3. Remove the public-doc reference in `doc.go` if any (none currently).
4. Update `docs/spec-matrix.md` package-profile row to refer to "single-suite CPACE-RISTR255-SHA512" without invoking `Suite`.
5. Add a `CHANGELOG.md` Unreleased entry under "Pre-v1 API cleanup".
6. Run `go test ./...`, `go test -race ./...`, `task check`. No protocol-visible or wire-format change is expected.
