#!/bin/sh
set -eu

image_repository=${1:?image repository is required}
starting_sha=${2:?starting commit SHA is required}

case "${starting_sha}" in
  *[!0-9a-f]* | "")
    echo "starting commit SHA must be lowercase hexadecimal" >&2
    exit 2
    ;;
esac

# Incremental releases do not publish a new tag for an unchanged image. Walk
# the deployed commit's ancestry until the most recent immutable image tag for
# this component is found instead of assuming the immediately preceding
# release built every component.
for candidate_sha in $(git rev-list "${starting_sha}"); do
  manifest="$({
    docker buildx imagetools inspect \
      "${image_repository}:main-${candidate_sha}" \
      --format '{{json .Manifest}}'
  } 2>/dev/null)" || continue
  digest="$(printf '%s\n' "${manifest}" | jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))')" || continue
  printf '%s\n' "${digest}"
  exit 0
done

echo "no published immutable image found for ${image_repository} at or before ${starting_sha}" >&2
exit 1
