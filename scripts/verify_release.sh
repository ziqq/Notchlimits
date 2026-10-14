#!/bin/bash
# Перед доступом к ключам подписи: коммит из main и успешный CI на том же SHA.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$GITHUB_EVENT_NAME" = workflow_dispatch ] && [ "$GITHUB_REF" != refs/heads/main ]; then
    echo "::error::Ручной релиз разрешён только из main."
    exit 1
fi

git fetch origin refs/heads/main:refs/remotes/origin/main
RELEASE_SHA=$(git rev-parse HEAD)
if ! git merge-base --is-ancestor "$RELEASE_SHA" origin/main; then
    echo "::error::Коммит релиза не принадлежит main: $RELEASE_SHA"
    exit 1
fi

CI_RUN_ID=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs" \
    -f head_sha="$RELEASE_SHA" -f branch=main -f event=push -f per_page=100 \
    --jq '.workflow_runs | max_by(.id) | .id // empty')
if [ -z "$CI_RUN_ID" ]; then
    echo "::error::Для коммита $RELEASE_SHA нет push-CI из main."
    exit 1
fi

# На тег часто нажимают сразу после слияния, пока сборка main ещё идёт.
gh run watch "$CI_RUN_ID" --repo "$GITHUB_REPOSITORY" --exit-status --interval 10
CONCLUSION=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$CI_RUN_ID" --jq '.conclusion')
if [ "$CONCLUSION" != success ]; then
    echo "::error::CI завершился с результатом $CONCLUSION."
    exit 1
fi
