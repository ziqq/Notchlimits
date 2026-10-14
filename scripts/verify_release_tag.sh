#!/bin/bash
# Refresh the remote tag; the local copy may have become stale during the build.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:?Release tag is required}"
EXPECTED_SHA="${2:-}"
if [[ "$TAG" != v* ]] || ! git check-ref-format "refs/tags/$TAG"; then
    echo "::error::Invalid release tag: $TAG" >&2
    exit 1
fi
git fetch --quiet --no-tags origin "refs/tags/$TAG"
TAG_SHA=$(git rev-parse 'FETCH_HEAD^{commit}')
if [ -n "$EXPECTED_SHA" ] && [ "$TAG_SHA" != "$EXPECTED_SHA" ]; then
    echo "::error::Remote tag $TAG does not reference build commit $EXPECTED_SHA." >&2
    exit 1
fi
printf '%s\n' "$TAG_SHA"
