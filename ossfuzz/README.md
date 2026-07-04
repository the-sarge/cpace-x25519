# OSS-Fuzz Staging

This directory stages the files used by the `google/oss-fuzz/projects/cpace-x25519` upstream pull request. The active fuzz targets remain in this repository in `fuzz_test.go` and are registered locally in `.github/fuzz-targets.json`, where each entry names the target function, package, and OSS-Fuzz binary name; `go test ./...` checks those entries against this build script.

Self-containment requirement: OSS-Fuzz native Go rewriting compiles each registered fuzz target file independently with the package's production `.go` files, so registered target files must not depend on declarations that exist only in other `_test.go` files; `TestFuzzTargetRegistrySelfContainedFiles` enforces this locally.

For the upstream OSS-Fuzz PR, use a small delegate `build.sh` in `google/oss-fuzz/projects/cpace-x25519` that executes this repository's `ossfuzz/build.sh` instead of duplicating the target list there.

Before opening or updating the upstream OSS-Fuzz PR:

1. Copy these files into a fork of `google/oss-fuzz` under `projects/cpace-x25519`.
2. Confirm `primary_contact` in `project.yaml` is the maintainer
   Google-account-associated email that should receive ClusterFuzz access and
   private bug notifications.
3. Build and check locally from the OSS-Fuzz checkout:

```sh
python3 infra/helper.py build_image cpace-x25519
python3 infra/helper.py build_fuzzers --sanitizer address cpace-x25519 /path/to/cpace-x25519
python3 infra/helper.py check_build cpace-x25519
```

On Apple Silicon hosts, use the production `x86_64` path explicitly:

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py build_fuzzers --architecture x86_64 --sanitizer address cpace-x25519 /path/to/cpace-x25519
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py check_build cpace-x25519
```

OSS-Fuzz native Go fuzzing builds `testing.F` fuzzers as libFuzzer binaries.
The Go integration currently supports `libfuzzer` with the `address` sanitizer.
For native Go fuzzers, `F.Add` seeds are not imported automatically by
OSS-Fuzz; add explicit seed corpora later if the first coverage reports show a
need for them.

Historical local validation on 2026-05-07 used a temporary `google/oss-fuzz` checkout for the original `github.com/the-sarge/cpace` project, not this cpace-x25519 fork, and passed:

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py build_fuzzers --architecture x86_64 --sanitizer address cpace /Users/josh/code/github.com/the-sarge/cpace
DOCKER_DEFAULT_PLATFORM=linux/amd64 python3 infra/helper.py check_build cpace
```

Fresh cpace-x25519 local validation passed on 2026-07-04 against commit `a2f892f785991b8ac20d60979c1f32639287f0d4`, and a new upstream submission is open as `google/oss-fuzz#15838`. Raw logs, binary registry comparison, host/tool metadata, and upstream PR metadata are committed under `docs/evidence/ossfuzz-a2f892f-20260704/`.

OSS-Fuzz onboarding is not complete until the upstream project is accepted and merged by `google/oss-fuzz`, and later ClusterFuzz signal should be monitored separately.
