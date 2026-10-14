#!/bin/bash
# Before accessing signing keys, require main ancestry and successful CI for the exact SHA.
set -euo pipefail
cd "$(dirname "$0")/.."

case "$GITHUB_EVENT_NAME" in
    workflow_dispatch)
        if [ "$GITHUB_REF" != refs/heads/main ]; then
            echo "::error::Manual releases must run from main."
            exit 1
        fi
        ;;
    push)
        if [ "$GITHUB_REF" != "refs/tags/$RELEASE_TAG" ]; then
            echo "::error::Release push events must reference the release tag."
            exit 1
        fi
        ;;
    *) echo "::error::Unsupported release event."; exit 1 ;;
esac

git fetch origin refs/heads/main:refs/remotes/origin/main
if [ "$GITHUB_EVENT_NAME" = push ]; then
    RELEASE_SHA=$(bash scripts/verify_release_tag.sh "$RELEASE_TAG" "$GITHUB_SHA")
else
    RELEASE_SHA=$(bash scripts/verify_release_tag.sh "$RELEASE_TAG")
fi
if ! git merge-base --is-ancestor "$RELEASE_SHA" origin/main; then
    echo "::error::Release commit is not an ancestor of main: $RELEASE_SHA"
    exit 1
fi

CI_RUN_ID=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs" \
    -f head_sha="$RELEASE_SHA" -f branch=main -f event=push -f per_page=100 \
    --jq '.workflow_runs | max_by(.id) | .id // empty')
if [ -z "$CI_RUN_ID" ]; then
    echo "::error::No main push CI run exists for $RELEASE_SHA."
    exit 1
fi

# A tag can be pushed immediately after merging, while main CI is still running.
gh run watch "$CI_RUN_ID" --repo "$GITHUB_REPOSITORY" --exit-status --interval 10
CONCLUSION=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$CI_RUN_ID" --jq '.conclusion')
if [ "$CONCLUSION" != success ]; then
    echo "::error::CI finished with conclusion $CONCLUSION."
    exit 1
fi
echo "sha=$RELEASE_SHA" >> "$GITHUB_OUTPUT"
