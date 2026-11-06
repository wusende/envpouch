#!/usr/bin/env bash
# Stage the single npm package under npm/dist/envpouch.
#
# Every platform's binary is bundled in vendor/, so installing needs only the
# npm registry (and its mirrors) — no GitHub, no postinstall, no network at
# install time. The trade-off is a ~7 MB tarball, paid by everyone, to avoid a
# download step that is unreachable behind the GFW.
#
#   scripts/npm-pack.sh                        # fetch assets from GitHub Releases
#   scripts/npm-pack.sh --from-target          # use target/release (native only)
#   scripts/npm-pack.sh --from-artifacts DIR   # use the archives uploaded by CI
#   scripts/npm-pack.sh --check-version        # only assert the manifests agree (CI)
#
# Cargo.toml is the only place the version is written: staging stamps it into the
# built manifest and writes it back into the tracked one, and --check-version
# keeps that committed copy honest (CI's write-back never reaches the repo).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
  sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

mode=release
artifacts_dir=
check_version=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-version) check_version=true ;;
    --from-target) mode=target ;;
    --from-release) mode=release ;;
    --from-artifacts)
      mode=artifacts
      artifacts_dir=${2:-}
      [ -n "$artifacts_dir" ] || { echo "--from-artifacts needs a directory" >&2; exit 2; }
      shift
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
[ -n "$version" ] || { echo "cannot read the package version from Cargo.toml" >&2; exit 1; }

if [ "$check_version" = true ]; then
  NPM_MANIFEST=npm/envpouch/package.json NPM_VERSION=$version node -e '
    const fs = require("node:fs");
    const file = process.env.NPM_MANIFEST;
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    if (pkg.version !== process.env.NPM_VERSION) {
      console.error(`${file}: version ${pkg.version} != Cargo.toml ${process.env.NPM_VERSION}`);
      process.exit(1);
    }
  '
  echo "ok: npm/envpouch/package.json is $version, matching Cargo.toml"
  exit 0
fi

dist=npm/dist
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rm -rf "$dist"
mkdir -p "$dist/envpouch/vendor"

# The Linux builds are glibc (keyring's Secret Service backend links libdbus)
# and macOS ships one universal2 binary for both architectures.
# vendor dir | release asset | binary name | rust targets packed inside
platforms=(
  "linux-x64|envpouch-x86_64-unknown-linux-gnu.tar.gz|envpouch|x86_64-unknown-linux-gnu"
  "linux-arm64|envpouch-aarch64-unknown-linux-gnu.tar.gz|envpouch|aarch64-unknown-linux-gnu"
  "darwin-universal|envpouch-universal2-apple-darwin.tar.gz|envpouch|universal2-apple-darwin"
  "win32-x64|envpouch-x86_64-pc-windows-msvc.zip|envpouch.exe|x86_64-pc-windows-msvc"
)

extract() {
  local archive=$1 dest=$2
  mkdir -p "$dest"
  case "$archive" in
    *.zip)
      if command -v unzip >/dev/null; then unzip -q -o "$archive" -d "$dest"
      else tar -xf "$archive" -C "$dest"; fi
      ;;
    *.tar.gz) tar -xzf "$archive" -C "$dest" ;;
    *) echo "unsupported archive: $archive" >&2; return 1 ;;
  esac
}

checksum() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Local mode stages only what this machine has built, for testing the launcher;
# release and artifacts mode must cover every platform.
partial=false
host=
if [ "$mode" = target ]; then
  partial=true
  host=$(rustc -vV | sed -n 's/^host: //p')
  case "$host" in
    x86_64-unknown-linux-*) host_slug=linux-x64 ;;
    aarch64-unknown-linux-*) host_slug=linux-arm64 ;;
    *-apple-darwin) host_slug=darwin-universal ;;
    x86_64-pc-windows-*) host_slug=win32-x64 ;;
    *) echo "no prebuilt envpouch for host $host" >&2; exit 1 ;;
  esac
fi

echo "staging envpouch $version for npm (source: $mode)"

for entry in "${platforms[@]}"; do
  IFS='|' read -r slug asset bin _targets <<<"$entry"

  dest="$dist/envpouch/vendor/$slug"
  mkdir -p "$dest"

  case "$mode" in
    target)
      if [ "$slug" != "$host_slug" ]; then
        rmdir "$dest" 2>/dev/null || true
        continue
      fi
      src="target/release/$bin"
      if [ ! -f "$src" ]; then
        echo "missing $src — run cargo build --release first" >&2
        exit 1
      fi
      cp "$src" "$dest/$bin"
      ;;
    artifacts)
      archive="$artifacts_dir/$asset"
      [ -f "$archive" ] || { echo "missing $archive" >&2; exit 1; }
      extract "$archive" "$tmp/$slug"
      cp "$tmp/$slug/$bin" "$dest/$bin"
      ;;
    release)
      base="https://github.com/wusende/envpouch/releases/download/v$version"
      curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$asset" "$base/$asset"
      curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$asset.sha256" "$base/$asset.sha256"

      expected=$(cut -d' ' -f1 "$tmp/$asset.sha256" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
      actual=$(checksum "$tmp/$asset")
      if [ "$expected" != "$actual" ]; then
        echo "checksum mismatch for $asset: expected $expected, got $actual" >&2
        exit 1
      fi

      extract "$tmp/$asset" "$tmp/$slug"
      cp "$tmp/$slug/$bin" "$dest/$bin"
      ;;
  esac

  [ "$bin" = "envpouch.exe" ] || chmod 755 "$dest/$bin"
done

# The launcher package itself: manifest + bin from npm/envpouch, README/LICENSE
# for the registry page.
cp -R npm/envpouch/. "$dist/envpouch/"
cp README.md LICENSE "$dist/envpouch/"

sync_manifest() {
  NPM_MANIFEST=$1 NPM_VERSION=$version node -e '
    const fs = require("node:fs");
    const file = process.env.NPM_MANIFEST;
    const version = process.env.NPM_VERSION;
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    const before = pkg.version;
    pkg.version = version;
    fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
    if (before !== version) {
      console.error(`  ${file}: ${before} -> ${version}`);
    }
  '
}

sync_manifest "$dist/envpouch/package.json"
sync_manifest npm/envpouch/package.json

# Fail before publishing, not after.
NPM_DIST=$dist NPM_VERSION=$version NPM_ALLOW_PARTIAL=$([ "$partial" = true ] && echo 1 || echo 0) node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const dist = process.env.NPM_DIST;
  const version = process.env.NPM_VERSION;
  const allowPartial = process.env.NPM_ALLOW_PARTIAL === "1";
  const pkgDir = path.join(dist, "envpouch");
  const problems = [];

  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
  if (pkg.name !== "envpouch") problems.push(`package.json says ${pkg.name}`);
  if (pkg.version !== version) problems.push(`version ${pkg.version} != ${version}`);
  if (pkg.optionalDependencies) problems.push("optionalDependencies must be empty (binaries are bundled)");
  if (!fs.existsSync(path.join(pkgDir, "bin", "envpouch.js"))) problems.push("bin/envpouch.js is missing");

  const expected = [
    ["linux-x64", "envpouch"],
    ["linux-arm64", "envpouch"],
    ["darwin-universal", "envpouch"],
    ["win32-x64", "envpouch.exe"],
  ];
  const present = [];
  let total = 0;
  for (const [slug, bin] of expected) {
    const file = path.join(pkgDir, "vendor", slug, bin);
    if (!fs.existsSync(file)) {
      if (!allowPartial) problems.push(`vendor/${slug}/${bin} is missing`);
      continue;
    }
    const size = fs.statSync(file).size;
    if (size < 100_000) problems.push(`vendor/${slug}/${bin} is only ${size} bytes`);
    present.push(slug);
    total += size;
  }

  if (problems.length) {
    console.error(problems.map((p) => `  - ${p}`).join("\n"));
    process.exit(1);
  }
  const kind = allowPartial ? "partial: local platform only" : "all platforms";
  console.log(`ok: envpouch@${version}, ${present.length}/4 platforms, ${(total / 1048576).toFixed(1)} MB unpacked (${kind})`);
'
