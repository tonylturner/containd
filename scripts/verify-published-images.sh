#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: bash scripts/verify-published-images.sh signature|sbom|vulnerabilities

Checks the published :latest management and engine images on GHCR:
  signature        Cosign keyless signature from the release workflow at the
                   image's stable release tag and that tag's commit.
  sbom             Signed CycloneDX SBOM attestation under the same identity.
  vulnerabilities  Trivy scan of every platform image, failing on HIGH or
                   CRITICAL findings not listed in .trivyignore.

The signature and sbom checks also require both images to come from the same
release, whose version tag resolves to the :latest digest.

Requires docker (with buildx), git and jq. Cosign and Trivy run from their
published container images. GITHUB_REPOSITORY selects the repository
(default tonylturner/containd).
EOF
}

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi
check="$1"
case "$check" in
    signature|sbom|vulnerabilities) ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        echo "unknown check: $check" >&2
        usage >&2
        exit 2
        ;;
esac

repository="${GITHUB_REPOSITORY:-tonylturner/containd}"
images=("ghcr.io/$repository" "ghcr.io/$repository-engine")
cosign_image="ghcr.io/sigstore/cosign/cosign:v2.6.1"
trivy_image="ghcr.io/aquasecurity/trivy:0.62.1"
issuer="https://token.actions.githubusercontent.com"
workflow="https://github.com/$repository/.github/workflows/release.yml"
stable_tag='v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'

run_cosign() {
    docker run --rm "$cosign_image" "$@"
}

manifest() {
    docker buildx imagetools inspect "$1" --format '{{json .Manifest}}'
}

resolve_digest() {
    local digest
    digest="$(manifest "$1" | jq -er '.digest')"
    if [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "invalid digest for $1: $digest" >&2
        return 1
    fi
    printf '%s\n' "$digest"
}

# Prints the commit a tag points at, peeling annotated tags.
tag_commit() {
    local refs commit
    refs="$(git ls-remote --tags "https://github.com/$repository" \
        "refs/tags/$1" "refs/tags/$1^{}")"
    commit="$(awk -v peeled="refs/tags/$1^{}" '$2 == peeled { print $1 }' <<<"$refs")"
    if [ -z "$commit" ]; then
        commit="$(awk -v ref="refs/tags/$1" '$2 == ref { print $1 }' <<<"$refs")"
    fi
    if [[ ! "$commit" =~ ^[a-f0-9]{40}$ ]]; then
        echo "cannot resolve tag $1 to a commit" >&2
        return 1
    fi
    printf '%s\n' "$commit"
}

# Prints the stable release tag whose release workflow signed image@digest.
signing_tag() {
    local image="$1" digest="$2" subjects count
    subjects="$(run_cosign verify \
        --certificate-identity-regexp "^${workflow//./\\.}@refs/tags/${stable_tag}\$" \
        --certificate-oidc-issuer "$issuer" \
        --output json "$image@$digest" | jq -r '.[].optional.Subject' | sort -u)"
    count="$(grep -c . <<<"$subjects" || true)"
    if [ "$count" -ne 1 ]; then
        printf 'expected one release identity for %s@%s, found %s:\n%s\n' \
            "$image" "$digest" "$count" "$subjects" >&2
        return 1
    fi
    printf '%s\n' "${subjects##*@refs/tags/}"
}

verify_release_images() {
    local image digest tag version_digest commit release=""
    for image in "${images[@]}"; do
        digest="$(resolve_digest "$image:latest")"
        tag="$(signing_tag "$image" "$digest")"
        if [ -n "$release" ] && [ "$tag" != "$release" ]; then
            echo "$image:latest comes from $tag, other images from $release" >&2
            return 1
        fi
        release="$tag"
        version_digest="$(resolve_digest "$image:${tag#v}")"
        if [ "$version_digest" != "$digest" ]; then
            echo "$image:latest is $digest but $image:${tag#v} is $version_digest" >&2
            return 1
        fi
        commit="$(tag_commit "$tag")"
        local trust=(
            --certificate-identity "$workflow@refs/tags/$tag"
            --certificate-oidc-issuer "$issuer"
            --certificate-github-workflow-sha "$commit"
        )
        case "$check" in
            signature)
                run_cosign verify "${trust[@]}" "$image@$digest" >/dev/null
                printf '%s:latest (%s) is signed by the %s release workflow at %s\n' \
                    "$image" "$digest" "$tag" "$commit"
                ;;
            sbom)
                run_cosign verify-attestation --type cyclonedx "${trust[@]}" "$image@$digest" |
                    jq -ser --arg ref "$image:latest" '
                        map(.payload | @base64d | fromjson | .predicate)
                        | if length > 0 and all(.bomFormat == "CycloneDX")
                          then map("\($ref): signed \(.bomFormat) \(.specVersion) SBOM, \(.components | length) components")[]
                          else error("\($ref): no signed CycloneDX SBOM") end'
                ;;
        esac
    done
}

scan_images() {
    local volume image digest platforms platform status=0
    volume="containd-trivy-cache-$$"
    docker volume create "$volume" >/dev/null
    # shellcheck disable=SC2064 # Expand the volume name now.
    trap "docker volume rm --force '$volume' >/dev/null" EXIT
    for image in "${images[@]}"; do
        digest="$(resolve_digest "$image:latest")"
        platforms="$(manifest "$image@$digest" | jq -er '
            [.manifests[]?.platform | select(.os != "unknown")
             | "\(.os)/\(.architecture)\(if .variant then "/\(.variant)" else "" end)"]
            | if length > 0 then .[] else error("not a multi-platform image index") end')"
        for platform in $platforms; do
            printf '\n==> %s:latest (%s) %s\n' "$image" "$digest" "$platform"
            docker run --rm \
                -v "$volume:/cache" \
                -v "$repo_root/.trivyignore:/trivyignore:ro" \
                "$trivy_image" \
                image --cache-dir /cache --image-src remote --platform "$platform" \
                --exit-code 1 --severity HIGH,CRITICAL --ignorefile /trivyignore \
                --format table --no-progress \
                "$image@$digest" || status=1
        done
    done
    return "$status"
}

case "$check" in
    signature|sbom) verify_release_images ;;
    vulnerabilities) scan_images ;;
esac
