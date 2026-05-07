# Release Verification

Official releases are published as signed annotated Git tags. This project does
not currently attach binary release assets to GitHub releases. The canonical
release artifact is the repository content reachable from the signed tag.

## Verify A Release Tag

Fetch tags and verify the tag signature:

```sh
git fetch --tags https://github.com/the-sarge/cpace.git
git verify-tag vX.Y.Z
```

Expected output includes a good SSH signature for
`the-sarge@the-sarge.com`.

To inspect the signed tag and the commit it names:

```sh
git show --no-patch --format=fuller vX.Y.Z
git rev-list -n 1 vX.Y.Z
```

The tag must be an annotated tag, not a lightweight tag:

```sh
git cat-file -t vX.Y.Z
```

Expected output:

```text
tag
```

## Verify Source Content

To inspect the exact source tree for a release:

```sh
git checkout --detach vX.Y.Z
git status --short
```

The worktree should be clean after checkout. Compare the commit SHA with the
release notes or evidence docs for that release.

## Release Assets

Current GitHub releases have no attached binary assets. If future releases add
assets, each asset must be signed directly or included in a signed manifest that
lists cryptographic hashes for every asset. Verify those signatures or manifest
hashes before using the assets.

GitHub may display auto-generated source archives for tags. Treat the signed Git
tag as the canonical authenticity mechanism for source releases.
