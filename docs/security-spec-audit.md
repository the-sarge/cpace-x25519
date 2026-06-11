# Security/Spec Audit

Date: 2026-06-11

Target module: `github.com/the-sarge/cpace`

Implementation baseline: `933ece246e6170b11e838395bf36f852cba0cd02`

Documentation/evidence baseline: the merge commit containing this file.

Toolchain: Go 1.26.4

Evidence transcript: `docs/evidence/go1264-20260611/local-analysis.log`

Draft source: `draft-irtf-cfrg-cpace-21`
(`https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21`)

## Scope

This audit checked `docs/security-assessment.md` and `docs/spec-matrix.md` (as
updated by PR #73, which shipped its own documentation updates alongside its
code changes) against the implementation baseline, tests, refreshed Go 1.26.4
release evidence, and the draft-21 text. It is a documentation and conformance
audit, not an independent cryptographic review. This is a project-side
self-audit, distinct from independent cryptographic review or external review.

The audit covered:

- implemented suite and protocol mode;
- CPace transcript, generator, ISK, scalar sampling, and confirmation behavior;
- package-owned CI construction, wire framing, and per-field caps;
- session lifecycle, export, peer metadata, and memory-handling claims;
- invalid-share handling and parser rejection behavior;
- test/vector/fuzz/dependency/Capslock evidence referenced by the
  release-readiness docs;
- the go1.26.4 toolchain security release (2026-06-02) impact;
- the PR #73 package-code changes (the safe fixes from the 2026-05-27
  multi-agent review: deferred wipe unification, `sampleScalar` retry,
  protocol-identity test pins, SAST gate workflow).

## Result

No security/spec drift was found at the implementation baseline.

`task check` passes under Go 1.26.4 at the implementation baseline (transcript
records exit 0 with both test lanes green). The clean-worktree evidence
transcript records dependency, gosec, and Capslock commands at the
implementation baseline.

The security assessment and spec matrix accurately describe the current
implementation:

- only `CPACE-RISTR255-SHA512` from draft-21 is implemented;
- only initiator-responder mode is exposed;
- `Respond` success is not authentication; sessions are returned only after
  explicit key confirmation;
- `transcript_ir`, generator derivation, ISK derivation, confirmation tags,
  scalar sampling, and `scalar_mult_vfy` handling match the documented
  draft-21 profile;
- package-owned CI construction, binary framing, non-configurable field caps,
  `Session.Export`, `Session.Close`, `PeerAssociatedData`, and `PeerID` are
  correctly documented as package-profile behavior;
- dependency and Capslock evidence references point to the refreshed Go 1.26.4
  evidence documents; the long-fuzz evidence refresh under 1.26.4 is pending
  the paired maintainer-machine campaigns and is tracked separately.

The go1.26.4 release (2026-06-02) is a security release: fixes to
`crypto/x509`, `mime`, and `net/textproto`, plus bug fixes to
`crypto/fips140`, the compiler, and the runtime. CPace does not import the
three patched packages; it does transitively use Go crypto internals including
`crypto/fips140`, so evidence is re-recorded under Go 1.26.4. Separately,
PR #73 merged the safe fixes from the 2026-05-27 multi-agent review into
`api.go`, `crypto.go`, and `session.go` (deferred wipe unification,
`sampleScalar` retry, protocol-identity test pins); those changes were
multi-agent-reviewed, shipped with their own security-assessment and
spec-matrix updates, and pin protocol identity with dedicated tests. At this
baseline `task check` reran the draft/RFC vector assertions. No Go API,
wire/protocol, dependency, or vector behavior change was found.

### Toolchain Vector Stability

For this refresh, the draft/RFC vector assertions were run under **both**
toolchains and recorded in the evidence transcript: `go test -count=1 -run
'Vector' -v ./...` under go1.26.4, and the same command under
`GOTOOLCHAIN=go1.26.3`. All vector tests pass identically under both
(`TestStringUtilitiesDraftVectors`, `TestEmbeddedDraftVectorJSON`,
`TestEmbeddedDraftInvalidVectorJSON`, `TestRistrettoDraft21Vectors`,
`TestScalarMultVFYDraftInvalidVectors`, and the vector-loader fuzz seeds).
This is the first refresh to record the old/new pair the evidence policy asks
for; future toolchain-triggered refreshes should continue the practice.

## Post-Baseline Changes

ADR-0003 (peer-share error semantics) was implemented after this audit's implementation baseline. It adds the exported `ErrPeerShareEncoding`/`ErrPeerShareIdentity` sentinels and changes the internal `scalarMultVFY` failure convention to nil plus an `ErrAbort`-wrapped error — an intentional internal-only divergence from draft-21's function-level neutral-element return with no protocol-visible change; the `scalar_mult_vfy` abort behavior audited above is unchanged. Read the "match the documented draft-21 profile" claim with that divergence in mind; the consolidated post-implementation evidence refresh will re-audit at the new baseline.

## Residual Risk

External review of package-owned CI/framing/profile choices remains open.
Independent cryptographic review remains required before any production-ready
claim.

Repeat this audit if protocol code, parser/framing code, package-profile docs,
dependencies, toolchain, or the targeted CPace draft revision changes before a
release tag.
