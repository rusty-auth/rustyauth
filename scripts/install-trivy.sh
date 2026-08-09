#!/bin/sh
set -eu

destination=${1:?usage: scripts/install-trivy.sh DESTINATION_DIRECTORY}
version=0.73.0

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    archive="trivy_${version}_macOS-ARM64.tar.gz"
    expected_sha256=80cc25faaf6378e37701202d0b4f9f43d9e413d198d594ba60fdf559fe44a683
    ;;
  Linux:x86_64)
    archive="trivy_${version}_Linux-64bit.tar.gz"
    expected_sha256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
    ;;
  *)
    echo "unsupported Trivy installer platform: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

temporary_directory=$(mktemp -d /tmp/rustyauth-trivy-install.XXXXXX)
case "$temporary_directory" in
  /tmp/rustyauth-trivy-install.*) ;;
  *) exit 1 ;;
esac
cleanup() {
  find "$temporary_directory" -type f -delete
  find "$temporary_directory" -depth -type d -empty -delete
}
trap cleanup EXIT HUP INT TERM

url="https://github.com/aquasecurity/trivy/releases/download/v${version}/${archive}"
curl --fail --location --silent --show-error --max-time 120 \
  --output "$temporary_directory/$archive" "$url"

case "$(uname -s)" in
  Darwin) actual_sha256=$(shasum -a 256 "$temporary_directory/$archive" | awk '{print $1}') ;;
  Linux) actual_sha256=$(sha256sum "$temporary_directory/$archive" | awk '{print $1}') ;;
esac
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "Trivy archive checksum mismatch" >&2
  exit 1
fi

tar -xzf "$temporary_directory/$archive" -C "$temporary_directory" trivy
install -d -m 0755 "$destination"
install -m 0755 "$temporary_directory/trivy" "$destination/trivy"
"$destination/trivy" --version
