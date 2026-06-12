# Go 1.26.4 / Post-PR-#73 Evidence Transcripts

Date: 2026-06-11

Package-code baseline: `933ece246e6170b11e838395bf36f852cba0cd02`

These files preserve the raw local evidence for the combined refresh triggered
by the go1.26.4 toolchain security release (2026-06-02) and the
security-relevant package-code changes merged in PR #73. They back the
refreshed summaries in [`../../dependency-review.md`](../../dependency-review.md),
[`../../capslock-report.md`](../../capslock-report.md),
[`../../security-spec-audit.md`](../../security-spec-audit.md), and
[`../../fuzz-evidence.md`](../../fuzz-evidence.md).

The paired ARM/Intel long-fuzz campaign logs (maintainer machines, one hour per target, 2026-06-11) completed this bundle; `docs/fuzz-evidence.md` is refreshed by them. The campaigns ran at the package-code baseline above, which predates the ADR-0003 implementation (PR #78); these runs double as the pre-refactor fuzz baseline for the ADR-0001 build sequence.

## Files

| File | Contents |
| --- | --- |
| `local-analysis.log` | Clean-worktree transcript at the baseline: commit, status, Go/Task versions, `go mod verify`, module list, `govulncheck -test -show verbose`, pinned `gosec@v2.26.1`, Capslock `v0.3.2` (default and verbose), `task check` summary, and draft/RFC vector-stability runs under both go1.26.4 and `GOTOOLCHAIN=go1.26.3`. |
| `fuzz-mbp128.log` | ARM leg (`mbp128.local`, `darwin/arm64`) raw `task fuzz` transcript: the executed task script, the `Running 14 fuzz targets (PARALLEL=1, FUZZTIME=1h, FUZZ_RACE=0)` banner, the full 14-target PASS set, and the `All 14 fuzz targets passed` success line. |
| `fuzz-imacpro.log` | Intel leg (`iMacPro.local`, `darwin/amd64`) raw `task fuzz` transcript, same shape as the ARM leg. |
| `fuzz-worktree-status-mbp128.log` | ARM campaign start context captured 2026-06-11T07:13:34Z: detached worktree at the baseline commit, clean status, go1.26.4, Task 3.51.1, `darwin/arm64`. |
| `fuzz-worktree-status-imacpro.log` | Intel campaign start context captured 2026-06-11T07:15:10Z: detached worktree at the baseline commit, clean status, go1.26.4, Task 3.51.1, `darwin/amd64`. |
| `SHA256SUMS` | SHA-256 digests for the transcript files above. |

Unlike the earlier `v012-candidate` wrapper logs, these `task fuzz` transcripts do not embed timestamps or the return code. Start times come from the worktree-status captures; completion is bounded by the final log writes, observed at copy time as 2026-06-11T21:13:55Z (ARM) and 2026-06-11T21:15:33Z (Intel) — ~14h00m per host, matching 14 sequential one-hour targets. The `All 14 fuzz targets passed` line is the success marker: the task script prints it only after checking that no per-target `.fail` files exist.

## Verification

On macOS:

```sh
cd docs/evidence/go1264-20260611
shasum -a 256 -c SHA256SUMS
```
