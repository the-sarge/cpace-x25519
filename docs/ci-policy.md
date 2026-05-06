# CI Policy

This repository treats CI as release evidence for an unaudited crypto package.
Required pull-request CI stays narrow because fork PRs run untrusted code on
hosted runners.

## Required PR Gate

The required PR gate is the `Check` job in `.github/workflows/ci.yml`. It runs
on GitHub-hosted Ubuntu runners with read-only repository permissions. Code
changes run `go test ./...`; docs-only PRs run whitespace and Markdown
validation without setting up Go.

Keep this lane short, deterministic, and least-privilege. New security or
analysis tools should start as background signal before being considered for
the required gate.

## Background Signal

`Vulnerability Scan`, `Gosec Advisory`, and `Nightly Fuzz` run on
GitHub-hosted runners through both `workflow_dispatch` and scheduled triggers.
These lanes are advisory unless a later policy change promotes them.

The scheduled fuzz lane is a short 5-minute-per-target regression run. It can
catch crashes and upload new failure corpus files, but it is not long-fuzz
release evidence by itself.

## Long Fuzzing And Release Evidence

Release-oriented changes should still run the full local gate, dependency
review, advisory security scan, and maintainer-controlled long fuzzing before a
release tag. Record exact evidence in the project evidence docs: commit SHA,
command or workflow, fuzz duration, target count, and residual risk.

Release tags should remain signed annotated tags. Downstream consumers should
be able to verify each release tag with `git verify-tag`.

## Self-Hosted Runners

GitHub-hosted runners handle untrusted PR validation. Self-hosted runners must
not run code from untrusted fork PRs.

If self-hosted capacity is added later, it must either be ephemeral with one
job per runner instance, or restricted to trusted `main`-only scheduled and
manual workflows. Long fuzzing may run on maintainer-controlled machines only
through manual, scheduled-main, or ephemeral-runner workflows.
