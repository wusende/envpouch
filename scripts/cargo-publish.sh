#!/usr/bin/env bash
# Publish the crate to crates.io.
#
#   scripts/cargo-publish.sh            # publish (local: ~/.cargo/credentials.toml)
#   scripts/cargo-publish.sh --dry-run  # package + verify build, upload nothing
#
# Re-running is safe: if the version is already on the registry it is skipped,
# so a failed or repeated release does not turn into an error.
#
# In CI this runs with crates.io trusted publishing (OIDC): the job exchanges
# the workflow's OIDC token for a 30-minute token and puts it in
# CARGO_REGISTRY_TOKEN; see npm/README.md.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

dry_run=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# Version lives only in Cargo.toml; everything else (npm manifest, CI checks)
# is derived from it.
read -r name version < <(awk '
  /^\[package\]/ { p = 1; next }
  /^\[/         { p = 0 }
  p && /^name[[:space:]]*=/    { n = $0; sub(/.*=[[:space:]]*"/, "", n); sub(/".*/, "", n) }
  p && /^version[[:space:]]*=/ { v = $0; sub(/.*=[[:space:]]*"/, "", v); sub(/".*/, "", v) }
  END { print n, v }
' Cargo.toml)

if [ -z "${name:-}" ] || [ -z "${version:-}" ]; then
  echo "could not read name/version from Cargo.toml" >&2
  exit 1
fi

# On a tag build the tag is the release's name: v0.3.0 must publish 0.3.0.
# A mismatch would spend the crate version under a misleading git tag, and a
# published version can never be reused or removed.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
  if [ "v$version" != "$GITHUB_REF_NAME" ]; then
    echo "tag $GITHUB_REF_NAME does not match Cargo.toml version $version" >&2
    exit 1
  fi
fi

if [ "$dry_run" = true ]; then
  echo "dry-run: $name@$version"
  cargo publish --dry-run --locked
  exit 0
fi

# Skip when the version is already up. The check is best-effort: an unreachable
# registry (proxy, outage) must not block the publish attempt below.
status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "User-Agent: envpouch release script (https://github.com/wusende/envpouch)" \
  "https://crates.io/api/v1/crates/$name/$version" 2>/dev/null) || status=000

if [ "$status" = "200" ]; then
  echo "skip $name@$version (already published)"
  exit 0
fi

echo "publishing $name@$version (registry check: HTTP $status)"
set +e
output=$(cargo publish --locked 2>&1)
rc=$?
set -e
printf '%s\n' "$output"

# Race with a concurrent run, or a registry that answered 404 above but had the
# version after all: already-published is a success here, not a failure. cargo
# words this two ways ("already uploaded" from the upload endpoint, "already
# exists on crates.io index" from the index check).
if [ "$rc" -ne 0 ] && printf '%s' "$output" | grep -qiE 'already uploaded|already exists on crates\.io'; then
  echo "skip $name@$version (already published)"
  exit 0
fi

exit "$rc"
