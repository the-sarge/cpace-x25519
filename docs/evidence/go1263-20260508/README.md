# Go 1.26.3 Evidence Transcripts

Date: 2026-05-08

Package-code baseline: `737bc56ffba81e2df5e9caa0df1ff180bfdb594b`

These files preserve the raw local evidence used by the Go 1.26.3 refresh
summaries in `docs/dependency-review.md`, `docs/fuzz-evidence.md`, and
`docs/capslock-report.md`.

## Files

| File | Contents |
| --- | --- |
| `fuzz-m4mini.log` | Raw `task fuzz` wrapper log from `m4mini.local` for the paired one-hour ARM run. |
| `fuzz-imacpro.log` | Raw `task fuzz` wrapper log from `iMacPro.local` for the paired one-hour Intel run. |
| `local-analysis.log` | Local clean-worktree transcript for Go version, clean status, module list, `govulncheck`, pinned `gosec`, and Capslock commands. |
| `SHA256SUMS` | SHA-256 digests for the transcript files above. |

## Notes

The fuzz logs are maintainer-machine transcripts. They are committed for review
traceability and protected by repository history once merged, but they are not
an independent third-party attestation. Future exact-candidate refreshes should
prefer immutable CI artifacts, signed transcripts, or both.

The `task fuzz` command records synthesized per-target PASS lines. It does not
preserve Go's per-target fuzz counter output. The documented seven-hour
wall-clock duration is therefore treated as consistent with each target running
the configured `FUZZTIME=1h`, not as independent proof of per-target iteration
counts.
