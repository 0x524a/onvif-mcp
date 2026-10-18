# Releasing

Releases are cut by pushing an annotated `vX.Y.Z` tag from `main`. The workflow in
`.github/workflows/release.yml` does the rest. Pre-releases use a hyphen (`v0.2.0-rc.1`) and are
marked as pre-releases on GitHub.

## Steps

1. Be on an up-to-date `main` with a clean tree and a green CI run.
2. Edit `CHANGELOG.md`: move entries from `[Unreleased]` into a new `## [X.Y.Z]` section (no `v`
   in the heading) and update the compare links at the bottom. The section becomes the release
   notes verbatim; the release fails if it is missing or empty.
3. If the default `version` in `internal/mcpserver/server.go` should track the release, update it.
   Release binaries override it with the tag via `-ldflags`, so this only affects plain
   `go build`.
4. Run the gate and a local build of everything the workflow will publish:

   ```sh
   make release-check VERSION=vX.Y.Z      # gate, notes extraction, dist/ archives + SHA256SUMS
   make release-dry-run VERSION=vX.Y.Z    # the above, plus a preview of notes and assets
   ```

   `dist/` is build output. Do not commit it.
5. Commit the changelog, then tag and push. Use an annotated tag (`-a`) or a signed one (`-s`);
   the workflow rejects lightweight tags.

   ```sh
   git commit -am "chore(release): vX.Y.Z"
   git push origin main            # wait for CI to go green
   git tag -s vX.Y.Z -m "onvif-mcp vX.Y.Z"     # or: git tag -a vX.Y.Z -m "..."
   git push origin vX.Y.Z
   ```

## What the workflow does

1. **verify**: the tag is semver and annotated, the tagged commit is on `main`, the changelog has
   notes for it, and the full gate (build, vet, gofmt, `go test -race`, golangci-lint v2.13.2)
   passes on that commit.
2. **build**: `scripts/build-release.sh` cross-builds `cmd/onvif-mcp` (static, `CGO_ENABLED=0`,
   `-trimpath`, version injected with `-ldflags -X`) for linux, darwin and windows on amd64 and
   arm64. Each archive (`.tar.gz`, `.zip` on windows) holds the binary, `LICENSE`, `NOTICE` and
   `README.md`. It writes `SHA256SUMS`, then checks the linux binary prints the tag from `-version`
   and that every checksum matches. Only `onvif-mcp` ships; `demo-camera` is a development aid.
3. **attest**: build provenance attestations for every archive and `SHA256SUMS` (the only job with
   `id-token` and `attestations` write).
4. **release**: `gh release create` with the changelog section as notes (the only job with
   `contents: write`).

## Verifying a download

```sh
sha256sum -c SHA256SUMS --ignore-missing          # shasum -a 256 -c on macOS
gh attestation verify onvif-mcp_vX.Y.Z_linux_amd64.tar.gz --repo 0x524a/onvif-mcp
./onvif-mcp -version                              # prints vX.Y.Z
```

## Yanking a bad release

Published tags should be treated as immutable, so fix forward when you can.

1. Mark the release as a pre-release or edit its notes with a warning:
   `gh release edit vX.Y.Z --prerelease --notes "Withdrawn: <reason>; use vX.Y.Z+1"`.
2. If it must disappear, `gh release delete vX.Y.Z --cleanup-tag` (removes the tag too), and say so
   in the next changelog entry. Anyone who already fetched the tag keeps it.
3. Ship a corrected `vX.Y.(Z+1)` through the steps above. Never move or reuse a tag.

If the workflow fails before the release job, nothing was published: fix the cause, delete the tag
(`git push --delete origin vX.Y.Z; git tag -d vX.Y.Z`), and tag again.
