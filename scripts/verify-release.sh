#!/usr/bin/env bash
# Verify a published release end-to-end: download SHA256SUMS, every artifact
# named in it, and every artifact's cosign bundle; check sha256 sums; verify
# cosign signatures against this project's release workflow identity for the tag.
#
# Usage: scripts/verify-release.sh <vX.Y.Z>
#
# Requires: curl, sha256sum, cosign.

set -euo pipefail

VERSION="${1:?usage: $0 <vX.Y.Z>}"

PROJECT_PATH="haproxy-haptic/haproxy-spoa-hub-plugin-external-auth"
RELEASE_BASE="https://github.com/${PROJECT_PATH}/releases/download/${VERSION}"

GITHUB_IDENTITY="https://github.com/${PROJECT_PATH}/.github/workflows/release.yml@refs/tags/${VERSION}"
GITHUB_ISSUER="https://token.actions.githubusercontent.com"
# Releases cut before the move to GitHub were signed by GitLab CI.
GITLAB_IDENTITY="https://gitlab.com/${PROJECT_PATH}//.gitlab-ci.yml@refs/tags/${VERSION}"
GITLAB_ISSUER="https://gitlab.com"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
cd "${WORKDIR}"

echo "Downloading SHA256SUMS for ${VERSION}..."
curl --fail --silent --location --output SHA256SUMS "${RELEASE_BASE}/SHA256SUMS"

# Each line of SHA256SUMS is "<hash>  <filename>"
mapfile -t names < <(awk '{print $2}' SHA256SUMS)

echo "Downloading ${#names[@]} artifacts and signature bundles..."
for name in "${names[@]}"; do
    curl --fail --silent --location --output "${name}" "${RELEASE_BASE}/${name}"
    curl --fail --silent --location --output "${name}.cosign.bundle" \
        "${RELEASE_BASE}/${name}.cosign.bundle"
done

echo "Checking SHA256 sums..."
sha256sum --check --quiet SHA256SUMS

verify() {
    cosign verify-blob "$1" \
        --bundle "$1.cosign.bundle" \
        --certificate-identity "$2" \
        --certificate-oidc-issuer "$3" \
        > /dev/null 2>&1
}

echo "Verifying cosign signatures..."
for name in "${names[@]}"; do
    if verify "${name}" "${GITHUB_IDENTITY}" "${GITHUB_ISSUER}"; then
        continue
    fi
    if verify "${name}" "${GITLAB_IDENTITY}" "${GITLAB_ISSUER}"; then
        continue
    fi
    echo "FAIL: ${name} is not signed by ${GITHUB_IDENTITY} or ${GITLAB_IDENTITY}" >&2
    exit 1
done

echo "OK - ${#names[@]} artifacts verified for ${VERSION}"
