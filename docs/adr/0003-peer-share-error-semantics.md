---
status: proposed
---

# Peer-share error semantics for `scalarMultVFY`

## Status

**Proposed — recorded, not yet enforced.** This ADR captures a v1.0.0 error-API decision surfaced by external code review (item H2). It stays `proposed` until an independent multi-agent review (`ras consider`) concurs that the chosen direction is correct. Once accepted, the error-sentinel surface and the internal return shape of `scalarMultVFY` are settled and future reviews should not re-litigate them.

## Context

`crypto.go:99-109` defines:

```go
func scalarMultVFY(s *ristretto255.Scalar, encoded []byte) ([]byte, bool) {
    p, ok := decodePublicShare(encoded)
    if !ok {
        return clone(identityEncoding), false
    }
    out := ristretto255.NewIdentityElement().ScalarMult(s, p).Bytes()
    if hmac.Equal(out, identityEncoding) {
        return clone(identityEncoding), false
    }
    return out, true
}
```

with `decodePublicShare(encoded)` at `crypto.go:111-124` returning `(*ristretto255.Element, bool)` and rejecting for any of three reasons: wrong length, non-canonical Ristretto255 encoding, or identity-element encoding.

The function collapses **three distinct attacker-relevant signals** into a single boolean:

1. **Wrong length** — `len(encoded) != pointSize`. The wire decoder already enforces 32 bytes (`framing.go` `readExactField(pointSize, ...)`), so this branch only fires for an internal-caller bug — a programmer error in framing, not an active attacker. Today it is dead but defensive.
2. **Non-canonical encoding** — `SetCanonicalBytes` rejection. The peer sent 32 bytes that do not decode as a valid Ristretto255 point. This is either a buggy or malicious peer.
3. **Identity element on input** — `p.Bytes() == identityEncoding`. The peer sent the encoded identity. This is almost certainly an active attacker trying to force `K = identity`.

A fourth branch — the post-multiply identity check at `crypto.go:104-107` — is dead in prime-order Ristretto255 (for any non-identity `p` and non-zero scalar `s`, `s·p` is non-identity) but kept as defense-in-depth.

All three callers (`api.go:166-168`, `api.go:180-184`, `api.go:222-226`) wrap the bool as a single `fmt.Errorf("%w: invalid initiator/responder share", ErrAbort)`. An operator seeing `cpace: protocol abort: invalid responder share` in production cannot distinguish "we shipped a framing bug to our peers" from "an attacker is on the wire feeding identity points." Both are concerning, but the responses differ.

There is also a separate concern at the function's return value: on every failure path `scalarMultVFY` returns `clone(identityEncoding)` (32 zero bytes) as the first return value, with `ok=false`. Every current caller checks `ok` before using the first return, but the silent-fallback shape is the canonical "safe default that masks failure" anti-pattern — a future `k, _ := scalarMultVFY(...)` would key with an all-zeros shared secret.

The error sentinel set in `errors.go:5-34` already exposes `ErrAbort` ("draft abort condition such as an invalid point or neutral-element Diffie-Hellman result"). The proposal does not remove or repurpose `ErrAbort`; it adds finer-grained sentinels that *wrap* `ErrAbort` so existing `errors.Is(err, ErrAbort)` checks remain correct.

The public API is frozen for v1.0.0 unless this review reopens it. Adding new exported error sentinels is API surface expansion and must be done before the freeze.

## Decision

Make two changes to `scalarMultVFY` and its callers, neither of which alters wire format or protocol semantics:

1. **Return `nil` on failure instead of `clone(identityEncoding)`.** No current caller reads the first return when `ok=false`, so this is internally non-breaking. The change removes the silent-fallback shape and ensures any future caller that ignores the bool will fail loudly (nil dereference) instead of silently keying with zeros.

2. **Add three exported sentinels in `errors.go`**, each wrapping `ErrAbort`:
   - `ErrPeerShareLength` — internal-caller bug; peer share length is not `pointSize`.
   - `ErrPeerShareEncoding` — wire decoded but `SetCanonicalBytes` rejected (non-canonical Ristretto255).
   - `ErrPeerShareIdentity` — peer share decoded to the identity element.

   And change the signature of `scalarMultVFY` (and `decodePublicShare`) to return `([]byte, error)` with the appropriate sentinel. The three call sites in `api.go` propagate the wrapped error directly.

`ErrAbort` is retained. Every new sentinel wraps it via `fmt.Errorf("%w: ...: %w", ErrAbort, ErrPeerShareIdentity)` so callers using `errors.Is(err, ErrAbort)` continue to see all three rejection causes; callers using `errors.Is(err, ErrPeerShareIdentity)` get the finer-grained signal.

The post-multiply identity check at `crypto.go:104-107` stays in place as defense-in-depth but gains a one-line comment explaining that it is unreachable for prime-order Ristretto255 and is kept against a future suite change.

## Acceptance criteria

The implementation must satisfy these before this ADR moves `proposed → accepted` *and* before v1.0.0 is tagged:

- **New sentinels exist** at `errors.go` with doc comments stating each wraps `ErrAbort`.
- **`scalarMultVFY` returns nil-on-failure** with a typed error; no caller path relies on the first return value when the error is non-nil.
- **`errors.Is(err, ErrAbort)` succeeds** for every error produced by the three reject branches (regression test: `TestPeerShareErrorsWrapErrAbort`).
- **Each sentinel is reachable from at least one test** — `TestPeerShareErrorEncodingRejection`, `TestPeerShareErrorIdentityRejection`, and one length-mismatch test that may have to use a constructed adversarial wire message that bypasses the wire decoder.
- **No protocol-visible change.** All existing protocol-level tests including the draft-21 invalid-vector JSON and `FuzzScalarMultVFY` continue to pass.
- **Wire format unchanged.** No new bytes on the wire, no new acceptance criteria for incoming messages.

## Considered options

- **A — Add sentinels, return nil on failure (recommended).** Resolves both the silent-fallback shape and the operator-triage information loss. Costs three new exported sentinels and a small refactor of `scalarMultVFY`'s return type. Backward-compatible at the `errors.Is(err, ErrAbort)` level.

- **B — Keep the `bool`, just change the first return to nil.** Removes the silent-fallback shape without expanding the error sentinel surface. Cheaper, but does not resolve the operator-triage problem and leaves identity-element submissions indistinguishable from peer encoding bugs in logs.

- **C — Add sentinels but keep the `bool` and the identity-encoding fallback.** The error sentinels exist for the call-site `fmt.Errorf` wrap, but the internal helper stays unchanged. Marginal improvement over status quo. Does not fix the silent-fallback risk for future callers.

- **D — Status quo.** Ship v1.0.0 with the current `(bytes, bool)` shape. `ErrAbort` continues to be the only signal callers get. Documented as a known limitation in `docs/integration-guidance.md`.

## Consequences

- **Option A (recommended):**
  - Three new exported error sentinels become part of the v1.0.0 surface.
  - Internal refactor of `scalarMultVFY` signature (unexported, no external impact).
  - Operators triaging production logs can distinguish "we have a framing bug" from "we have an attacker on the wire."
  - Future callers cannot silently key with all-zeros.
  - One new doc paragraph in `docs/integration-guidance.md` explaining the sentinel taxonomy.

- **Option B:**
  - One-line fix removes the silent-fallback footgun but does not improve operator-side triage.
  - No API surface expansion.
  - If operator-side triage becomes important later, the work is deferred.

- **Option C:**
  - Adds API surface without fixing the silent-fallback shape. Worst of both worlds.

- **Option D:**
  - Zero risk of getting the sentinel taxonomy wrong, but the silent-fallback shape and the triage gap persist for the lifetime of v1.x.

## Implementation outline (Option A)

1. Add `ErrPeerShareLength`, `ErrPeerShareEncoding`, `ErrPeerShareIdentity` to `errors.go` with doc comments.
2. Change `decodePublicShare` to return `(*ristretto255.Element, error)` using the new sentinels.
3. Change `scalarMultVFY` to return `([]byte, error)`, returning `nil` on every failure path; threading the sentinel through.
4. Update `api.go:166-168, 180-184, 222-226` to propagate the typed error directly (or wrap with a call-site message that still threads `ErrAbort` reachability).
5. Add tests:
   - `TestPeerShareErrorsWrapErrAbort` — table over each new sentinel asserting both `errors.Is(err, sentinel)` and `errors.Is(err, ErrAbort)`.
   - `TestPeerShareEncodingRejection` — feed a non-canonical Ristretto255 encoding via wire and assert `ErrPeerShareEncoding`.
   - `TestPeerShareIdentityRejection` — feed the identity encoding via wire and assert `ErrPeerShareIdentity`.
   - `TestPeerShareLengthRejection` — call the internal helper with a short slice (test-only escape) and assert `ErrPeerShareLength`.
6. Update `docs/integration-guidance.md` and `docs/security-assessment.md` to describe the sentinel taxonomy.
7. Add a `CHANGELOG.md` Unreleased entry under "Pre-v1 error surface".
