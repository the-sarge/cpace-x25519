# OSS-Fuzz cpace-x25519 Validation

This bundle records local OSS-Fuzz validation for `github.com/the-sarge/cpace-x25519` at commit `a2f892f785991b8ac20d60979c1f32639287f0d4` and the fresh upstream `google/oss-fuzz` submission opened as `google/oss-fuzz#15838`.

Validation ran on `mbp128.local` (`darwin/arm64`) using Docker Desktop with `DOCKER_DEFAULT_PLATFORM=linux/amd64` and OSS-Fuzz's explicit `--architecture x86_64` path. The upstream `oss-fuzz` submission branch was based on `google/oss-fuzz` commit `5c437ffb9e5945151b70cdd31ae7feeeeb43afd0`; after the project files were committed and the PR opened, the local submission branch head was `2cc262938096d54fd5d6d658018058403cdbd611`.

## Commands

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py build_image --architecture x86_64 --pull cpace-x25519
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py build_fuzzers --architecture x86_64 --sanitizer address --clean cpace-x25519 /Users/josh/code/github.com/the-sarge/cpace-x25519
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py check_build --architecture x86_64 --sanitizer address cpace-x25519
```

All three commands passed. `built-binaries.txt` contains the 15 produced cpace-x25519 fuzzer binaries plus `llvm-symbolizer`; `registered-binaries.txt` contains the 15 binaries from `.github/fuzz-targets.json`; `binary-diff.txt` is empty after excluding `llvm-symbolizer`.

The committed `build-fuzzers-address-x86_64.log` is a recapture of the same `build_fuzzers` command against a detached worktree at `a2f892f785991b8ac20d60979c1f32639287f0d4`; it includes the capture wrapper's `helper exit status: 0` marker because the helper does not print a success banner after the final Go dependency-download line.

## Files

- `build-image-x86_64.log`: OSS-Fuzz image build transcript with pulled base image digests.
- `build-fuzzers-address-x86_64.log`: clean address-sanitizer fuzzer build transcript recaptured against the detached `a2f892f785991b8ac20d60979c1f32639287f0d4` worktree, including the capture wrapper exit-status marker.
- `check-build-address-x86_64.log`: OSS-Fuzz `check_build` transcript, line-ending normalized from mixed CRLF/LF to LF after capture without changing log messages.
- `built-binaries.txt`, `registered-binaries.txt`, `binary-diff.txt`: binary registry comparison.
- `google-oss-fuzz-pr-15838.json`: upstream PR metadata captured with `gh pr view`.
- `cpace-*.txt`, `oss-fuzz-*.txt`, `docker-version.txt`, `python-version.txt`, `go-version.txt`, `uname.txt`, `validation-*-utc.txt`: commit, status, host, and tool metadata.
- `SHA256SUMS`: SHA-256 digests for every raw artifact in this bundle.

## Residual Limitations

This bundle proves local OSS-Fuzz project validation and records a fresh upstream submission. It does not prove that Google accepted or merged the project into OSS-Fuzz, that ClusterFuzz has started scheduled builds, or that OSS-Fuzz has produced coverage/crash signal. Treat upstream review/merge monitoring as the remaining OSS-Fuzz onboarding work.
