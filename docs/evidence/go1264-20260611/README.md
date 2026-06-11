# Go 1.26.4 / Post-PR-#73 Evidence Transcripts

Date: 2026-06-11

Package-code baseline: `933ece246e6170b11e838395bf36f852cba0cd02`

These files preserve the raw local evidence for the combined refresh triggered
by the go1.26.4 toolchain security release (2026-06-02) and the
security-relevant package-code changes merged in PR #73. They back the
refreshed summaries in [`../../dependency-review.md`](../../dependency-review.md),
[`../../capslock-report.md`](../../capslock-report.md), and
[`../../security-spec-audit.md`](../../security-spec-audit.md).

**Pending:** the paired ARM/Intel long-fuzz campaign logs under go1.26.4
(maintainer machines, one hour per target). `docs/fuzz-evidence.md` is not
refreshed by this bundle; its pinned campaigns remain the recorded fuzz
evidence until those runs land and are added here (regenerating `SHA256SUMS`).

## Files

| File | Contents |
| --- | --- |
| `local-analysis.log` | Clean-worktree transcript at the baseline: commit, status, Go/Task versions, `go mod verify`, module list, `govulncheck -test -show verbose`, pinned `gosec@v2.26.1`, Capslock `v0.3.2` (default and verbose), `task check` summary, and draft/RFC vector-stability runs under both go1.26.4 and `GOTOOLCHAIN=go1.26.3`. |
| `SHA256SUMS` | SHA-256 digests for the transcript files above. |

## Verification

On macOS:

```sh
cd docs/evidence/go1264-20260611
shasum -a 256 -c SHA256SUMS
```
