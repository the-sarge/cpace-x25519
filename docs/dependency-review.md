# Dependency Review

Date: 2026-06-11

Target module: `github.com/the-sarge/cpace`

Review commit: `933ece246e6170b11e838395bf36f852cba0cd02`

Review worktree: clean worktree at the review commit.

Toolchain: Go 1.26.4 (`darwin/arm64`)

Transcript: `docs/evidence/go1264-20260611/local-analysis.log`

Dependencies:

| Module | Version | Role | Notes |
| --- | --- | --- | --- |
| `github.com/gtank/ristretto255` | `v0.2.0` | Direct | Ristretto255 group and scalar operations. The package documents constant-time operations except variable-time APIs; this module does not call the variable-time APIs. |
| `filippo.io/edwards25519` | `v1.2.0` | Indirect | Pulled by `github.com/gtank/ristretto255`; pinned above the `v1.1.0` release noted by some SCA tools. |

## Commands

- `go version`
- `go list -m all`
- `govulncheck -version`
- `govulncheck -test -show verbose ./...`
- `go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...`

## Results

`go version` reported:

```text
go version go1.26.4 darwin/arm64
```

`go list -m all` reported only the main module plus:

- `filippo.io/edwards25519 v1.2.0`
- `github.com/gtank/ristretto255 v0.2.0`

`govulncheck -version` reported:

```text
Go: go1.26.4
Scanner: govulncheck@v1.3.0
DB: https://vuln.go.dev
DB updated: 2026-06-02 21:39:47 +0000 UTC
```

`govulncheck -test -show verbose ./...` scanned the module, the two dependency
modules, and the Go 1.26.4 standard library. Result: no vulnerabilities found.

The pinned gosec command reported zero issues:

```text
Summary:
  Gosec  : dev
  Files  : 7
  Lines  : 968
  Nosec  : 0
  Issues : 0
```

The `Gosec : dev` summary value is the string emitted by the upstream gosec
binary for this pinned `go run …gosec@v2.26.1` invocation. The line count
increased from 938 to 968 with the PR #73 package-code changes.

This refresh follows the go1.26.4 toolchain security release (2026-06-02;
`crypto/x509`, `mime`, `net/textproto` fixes plus `crypto/fips140`, compiler,
and runtime bug fixes) and the security-relevant package-code changes merged
in PR #73 (the safe fixes from the 2026-05-27 review: deferred wipe
unification, `sampleScalar` retry, protocol-identity test pins). No dependency
versions changed from the previous review.

## Residual Risk

Repeat this review against the exact release tag if any dependency, toolchain,
or parser/security-relevant code changes before release.
