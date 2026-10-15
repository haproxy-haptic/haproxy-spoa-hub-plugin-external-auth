# Releasing

## Prerequisites

- Write access to the repository
- Ability to push tags to `https://github.com/haproxy-haptic/haproxy-spoa-hub-plugin-external-auth`

## Steps

1. **Update the changelog**: Move items from `## [Unreleased]` to a new version section:

   ```markdown
   ## [Unreleased]

   ## [0.2.0] - 2026-05-01

   ### Added
   - ...
   ```

   Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. Use categories: Added, Changed, Deprecated, Removed, Fixed, Security.

2. **Commit and merge**: Create a branch, commit the changelog update, merge to main via pull request.

3. **Tag the release**: From the merged main:

   ```bash
   git checkout main && git pull
   git tag v0.2.0
   git push origin v0.2.0
   ```

   Tags must match the pattern `v*` (e.g., `v0.1.0`, `v1.0.0-beta.1`).

4. **CI handles the rest**: The `Release` workflow (`.github/workflows/release.yml`) automatically:
   - Runs the full CI workflow, including the kind end-to-end test
   - Cross-compiles the `.so` for amd64, arm64, and armv7 with
     `cargo auditable` (binaries embed a compressed `Cargo.lock`-equivalent
     so SBOM tools can enumerate Rust deps without source access)
   - Generates per-file `.sha256` sidecars and a combined `SHA256SUMS`
   - Cosign keyless-signs every `.so` with the GitHub Actions OIDC identity,
     producing `.cosign.bundle` files, and verifies each signature
   - Extracts the matching changelog section as release notes
   - Creates a GitHub Release for the tag with all artifacts attached

   To rehearse signing without publishing, run the workflow manually
   (`gh workflow run release.yml -f dry_run=true`).

## Verifying a release

After CI finishes, verify the release end-to-end from a clean machine:

```sh
make verify-release VERSION=v0.2.0
```

This downloads `SHA256SUMS`, every artifact named in it, and every artifact's
cosign bundle from the GitHub Release, then runs `sha256sum -c` and
`cosign verify-blob` against the release workflow's identity for the tag.
Releases cut before the move to GitHub verify against the GitLab CI identity.

## Versioning

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **MAJOR**: Breaking changes to the plugin API, output variable names, or config parameters
- **MINOR**: New features (e.g., new config options, new output variables, new auth decision logic)
- **PATCH**: Bug fixes, performance improvements, documentation updates

Pre-release versions use suffixes: `v0.2.0-alpha.1`, `v0.2.0-beta.1`, `v0.2.0-rc.1`.
