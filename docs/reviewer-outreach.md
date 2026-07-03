# Reviewer Outreach Note

Use this note as a starting point when asking for external review. Adjust the
recipient, scope, and time expectations before sending.

## Short Note

Hello,

I am looking for external review of a Go CPace draft implementation:

`https://github.com/the-sarge/cpace-x25519`

The package implements only `CPACE-X25519-SHA512` from `draft-irtf-cfrg-cpace-21`, in initiator-responder mode with mandatory explicit key confirmation. It is explicitly marked as an auditable draft implementation, not production-ready cryptographic software.

The review handoff is here:

`https://github.com/the-sarge/cpace-x25519/blob/main/docs/external-review-handoff.md`

The threat model is here:

`https://github.com/the-sarge/cpace-x25519/blob/main/docs/threat-model.md`

The most useful review focus would be:

- package-owned context-info construction and role-local identity input;
- binary wire framing and field-size limits;
- empty-session-ID policy and integration guidance;
- scalar sampling, X25519 low-order public-share handling, confirmation, exporter, and session lifecycle claims;
- whether the CI, dependency, fuzz, and signed-release evidence is sufficient
  for an auditable prerelease while independent cryptographic review remains a
  blocker.

Open public review findings on `https://github.com/the-sarge/cpace-x25519/issues` unless the finding is sensitive enough for private reporting.

The inherited `github.com/the-sarge/cpace` evidence bundle is indexed in `docs/evidence-baseline.md` but is stale for cpace-x25519 release claims. Refresh dependency, fuzz, Capslock, and security/spec evidence against an exact cpace-x25519 candidate before making stronger release-readiness claims.

This is still unaudited prerelease evidence, not a production-readiness claim.

Please report private vulnerabilities through the channels in `SECURITY.md`.
Public review notes that are not sensitive can be opened as GitHub issues.

Thank you.

## Reviewer Packet

Primary files for review:

- `README.md`
- `SECURITY.md`
- `docs/external-review-handoff.md`
- `docs/security-assessment.md`
- `docs/spec-matrix.md`
- `docs/integration-guidance.md`
- `docs/ci-policy.md`
- `docs/dependency-review.md`
- `docs/fuzz-evidence.md`
- `docs/security-spec-audit.md`
- `docs/capslock-report.md`
- `docs/evidence-baseline.md`
- `docs/evidence/f7efa6a-20260619/README.md`
- `docs/performance.md`

Open release blockers:

- external review of package-owned framing, context-info construction, and
  profile choices;
- independent cryptographic review;
- exact-candidate dependency review, long fuzzing, and security/spec audit after
  review-driven changes.
