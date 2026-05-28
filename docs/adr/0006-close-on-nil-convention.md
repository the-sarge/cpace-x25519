---
status: proposed
---

# `Session.Close` on a nil receiver — `io.Closer` convention or strict error

## Status

**Proposed — recorded, not yet enforced.** This ADR captures a v1.0.0 public-API contract decision surfaced by external code review (item M2). It stays `proposed` until an independent multi-agent review (`ras consider`) concurs. Once accepted, the contract for nil-receiver methods on `Session` is settled for the v1.0.0 freeze.

## Context

`session.go:48-62` implements:

```go
func (s *Session) Close() error {
    if s == nil || s.state == nil {
        return fmt.Errorf("%w: nil session", ErrInvalidInput)
    }
    // ...
}
```

while the three accessor methods (`TranscriptID`, `PeerAssociatedData`, `PeerID`) at `session.go:15-41` return `nil` on a nil receiver. `Export` returns `ErrInvalidInput` on a nil receiver, matching `Close`.

The contract is asymmetric:

- `Close()` on nil → wrapped `ErrInvalidInput`.
- `TranscriptID()` / `PeerAssociatedData()` / `PeerID()` on nil → `nil`.
- `Export()` on nil → wrapped `ErrInvalidInput`.

Both halves of the asymmetry are tested at `api_test.go` `TestNilSessionClose` (close + the three accessors) and the test added on the safe-fixes branch covers the new `Export` and `TranscriptID` paths.

The Go convention for `io.Closer`-shaped methods is that `Close()` is idempotent and tolerant. For pointer receivers, this idiomatically extends to: `Close()` on a nil receiver is a no-op that returns `nil`. Concrete examples:

- `*sync.Pool` — has no Close.
- `*net.Conn` — `(net.Conn).Close()` on a nil interface panics, but on a typed nil `*net.TCPConn` it panics too. So Go stdlib is not uniformly nil-tolerant here.
- `*os.File` — `(*os.File).Close()` on nil panics. Stdlib precedent.
- `*sql.DB` — `(*sql.DB).Close()` on nil panics.
- `*bytes.Buffer` — doesn't implement Close.

Looking at the stdlib, the dominant convention is **panic on nil**, not "no-op return nil". The "return ErrInvalidInput" pattern in cpace is a *third* convention — strict error rather than panic.

There are three reasonable options for the v1.0.0 contract:

1. **Status quo**: `Close` returns `ErrInvalidInput` on nil; accessors return nil; `Export` returns `ErrInvalidInput`.
2. **Panic on nil** for every method (match `*os.File` / `*sql.DB`). Caller bug → loud failure.
3. **Tolerant**: `Close` returns `nil` on nil; accessors return nil; `Export` returns `nil, ErrInvalidInput`. Mostly-aligned with `io.Closer` convention.

The current contract trades on safety: a caller running `defer session.Close()` on a `nil *Session` (e.g., after a failed `Finish` that returned `(nil, nil, err)`) gets a clean error rather than a panic. The cost is non-conventional behaviour and the asymmetry with the accessors.

The most consequential downstream pattern is `defer session.Close()` after a `Finish` that may have failed. Today's behaviour means `defer (*Session)(nil).Close()` returns an error that the caller almost certainly is ignoring (it's `defer`d), which is a no-op in practice. Switching to `nil → nil` makes that explicit: `defer session.Close()` after a failed Finish is a no-op.

## Decision

Switch `Session.Close()` on a nil receiver to return `nil` (no-op). Keep `Export` on nil returning `ErrInvalidInput`. Keep accessors returning `nil`.

Rationale:

- **`defer session.Close()` after a failed `Finish` should be a no-op, not an error-emitter.** This is the dominant caller pattern; making it a no-op aligns with caller expectation and the way `defer` swallows error returns.
- **`Export` on nil should remain an error** because callers MUST receive a return value, and `nil, nil` would be a silent "no key, no error" signal that masks a programmer bug. `Export` is not idempotent or terminal in the way `Close` is.
- **Accessors returning `nil`** is correct: they are documented as returning a copy of stored metadata; on nil receiver there is no metadata, so returning `nil` is unambiguous.

This proposal does NOT match the strict `*os.File`-style panic convention. The cpace package consistently chooses "wrapped sentinel error" over panic for invalid input throughout, and the documented threat model treats panics as a denial-of-service surface. Continuing that policy means: `Close` becomes nil-tolerant; `Export` keeps the error; no panics anywhere.

## Acceptance criteria

The implementation must satisfy these before this ADR moves `proposed → accepted` *and* before v1.0.0 is tagged:

- **`Session.Close()` on a nil receiver returns `nil`.** No allocation, no error.
- **`Export` on a nil receiver continues to return** the current wrapped `ErrInvalidInput`.
- **`TranscriptID`, `PeerAssociatedData`, `PeerID` on a nil receiver continue to return `nil`.**
- **Updated test** `TestNilSessionClose` (or a renamed `TestNilReceiverMethods`) asserting the new contract.
- **Updated doc** on `Session.Close`: *"Close is idempotent and nil-safe; calling Close on a nil `*Session` returns nil."*
- **`CHANGELOG.md` Unreleased** records the contract change. Note: this is technically a breaking change for any caller that did `if err := s.Close(); errors.Is(err, ErrInvalidInput) { ... }` to detect a nil receiver. Such code is unusual but possible; the changelog should call this out explicitly.

## Considered options

- **A — Nil-tolerant Close, strict Export, nil accessors (recommended).** Documented, conventional for `Close`, error-loud for `Export`, no panics.

- **B — Status quo.** `Close` returns `ErrInvalidInput` on nil. Consistent within the package's existing strict-error policy. Mildly non-conventional for `Close`.

- **C — All methods panic on nil.** Matches `*os.File` / `*sql.DB`. Catches programmer bugs loudly. Diverges from the package's no-panic-on-input policy.

- **D — All methods nil-tolerant.** `Export` on nil returns `nil, nil`. Aligns with accessors, but `nil, nil` is the canonical silent-failure shape — rejected for the same reason `scalarMultVFY` returning `clone(identityEncoding)` on failure is being changed in [[0003-peer-share-error-semantics]].

## Consequences

- **Option A (recommended):**
  - `defer session.Close()` after a failed `Finish` becomes a true no-op.
  - `Export` continues to surface programmer bugs.
  - One CHANGELOG entry flagging the minor contract change.
  - Updated doc + test.

- **Option B (status quo):**
  - No change. Continues to require the doc + test to remain accurate.

- **Option C:**
  - All nil-receiver method calls panic, including in `defer` blocks. `defer session.Close()` after a failed `Finish` panics during cleanup — likely *during* another error path — which is exactly the situation panics are worst at handling.
  - Diverges from the package's no-panic-on-input policy.

- **Option D:**
  - Reintroduces silent-failure shape for `Export`. Rejected.

## Implementation outline (Option A)

1. Change `session.go:48-51` from `return fmt.Errorf("%w: nil session", ErrInvalidInput)` to `return nil`.
2. Update the `Session.Close` doc comment at `session.go:43-47` to state nil-tolerance explicitly.
3. Update the existing `TestNilSessionClose` test (or add a new test) to assert `err == nil` on nil receiver Close.
4. Add `CHANGELOG.md` Unreleased entry under "Pre-v1 contract change" calling out the behaviour change.
5. Confirm `Export` and accessors are unchanged.
