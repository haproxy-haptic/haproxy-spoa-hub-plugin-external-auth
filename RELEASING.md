# Releasing

## Prerequisites

- Write access to the repository
- `glab` CLI authenticated, or ability to push tags

## Steps

1. **Update the changelog**: Move items from `## [Unreleased]` to a new version section:

   ```markdown
   ## [Unreleased]

   ## [0.2.0] - 2026-05-01

   ### Added
   - ...
   ```

   Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. Use categories: Added, Changed, Deprecated, Removed, Fixed, Security.

2. **Commit and merge**: Create a branch, commit the changelog update, merge to main via MR.

3. **Tag the release**: From the merged main:

   ```bash
   git checkout main && git pull
   git tag v0.2.0
   git push origin v0.2.0
   ```

   Tags must match the pattern `v*` (e.g., `v0.1.0`, `v1.0.0-beta.1`).

4. **CI handles the rest**: The `release` job in `.gitlab-ci.yml` automatically:
   - Builds the release `.so` artifact
   - Extracts the matching changelog section as release notes
   - Creates a GitLab release with the artifact and notes

## Versioning

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **MAJOR**: Breaking changes to the plugin API, output variable names, or config parameters
- **MINOR**: New features (e.g., new config options, new output variables, new auth decision logic)
- **PATCH**: Bug fixes, performance improvements, documentation updates

Pre-release versions use suffixes: `v0.2.0-alpha.1`, `v0.2.0-beta.1`, `v0.2.0-rc.1`.
