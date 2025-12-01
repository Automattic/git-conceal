#!/bin/bash

set -euo pipefail

echo "~~~ Creating GitHub Release..."
version="${BUILDKITE_TAG:-${BUILDKITE_COMMIT:0:7}}"

slug=$(basename "$(dirname "${BUILDKITE_REPO/:/\/}")")/$(basename "$BUILDKITE_REPO" .git)

echo "~~~ Creating release ${version}..."
create_release_json=$(cat <<EOF
{
  "tag_name":"${version}",
  "target_commitish":"$BUILDKITE_COMMIT",
  "name":"${version}",
  "body":"Release ${version}",
  "draft":false,
  "prerelease":false,
  "generate_release_notes":true
}
EOF
)
response="$(curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${slug}/releases" \
  -d "$create_release_json")"
release_id="$(echo "$response" | jq -r '.id')"

echo "~~~ Downloading Buildkite artifacts..."
mkdir -p artifacts
buildkite-agent artifact download "git-conceal-*" artifacts/

echo "~~~ Adding assets to release ${version}..."
find artifacts/ -name "git-conceal-*" | while read -r artifact; do
  echo "~~~ Adding artifact ${artifact} to release ${version}..."
  curl -L \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Content-Type: application/octet-stream" \
    "https://uploads.github.com/repos/${slug}/releases/${release_id}/assets?name=$(basename "${artifact}")" \
    --data-binary "@${artifact}"
done
