#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

(
  cd "$repo_root/tools/releasepolicy"
  go test ./...
  go run . --repo-root "$repo_root"
)
