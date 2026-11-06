#!/usr/bin/env bash
# CLI-level fuzz smoke for envpouch: feeds malformed inputs at the binary and
# asserts outcomes stay within the documented exit-code set (0/1/2/126/127)
# with no panics, stack overflows, or allocation aborts. Complements the
# in-process deterministic fuzz suite (src/fuzz_tests.rs), which covers the
# pure functions; this script covers process-level behavior.
#
# Usage: scripts/fuzz_cli.sh [path-to-envp-binary]
set -u
BIN="${1:-./target/release/envp}"
PASS="fuzzcli-pass-123"
WORK="$(mktemp -d)"
PROFILES="$HOME/.envpouch/profiles"
trap 'rm -rf "$WORK"' EXIT
FAIL=0
N=0

check() { # $1 = exit code, $2 = combined output
  N=$((N + 1))
  local rc="$1" out="$2"
  case "$rc" in
    0 | 1 | 2 | 126 | 127) ;;
    *) echo "[$N] BAD EXIT $rc"; FAIL=1; return ;;
  esac
  case "$out" in
    *"panicked at"* | *"stack overflow"* | *"memory allocation of"*)
      echo "[$N] PANIC/ABORT: ${out:0:200}"
      FAIL=1
      ;;
  esac
}

mkdir -p "$PROFILES"

# Interactive import helper (new-profile setup requires a TTY for the
# two-step password prompt); expect is preinstalled on macOS, script(1) is
# the fallback pty wrapper.
import_interactive() { # $1 = name, $2 = env file
  if command -v expect >/dev/null 2>&1; then
    expect -c "
      set timeout 60
      spawn $BIN import $1 --from $2
      expect \"Set a new password:\"
      send \"$PASS\r\"
      expect \"Confirm new password:\"
      send \"$PASS\r\"
      expect eof
    " >/dev/null 2>&1
  else
    printf '%s\n%s\n' "$PASS" "$PASS" |
      script -q /dev/null "$BIN" import "$1" --from "$2" >/dev/null 2>&1
  fi
}

echo "== 1) garbage files as --from input (80 random-byte files) =="
mkdir -p "$WORK/g"
for i in $(seq 1 80); do
  head -c $(((RANDOM % 2048) + 1)) /dev/urandom >"$WORK/g/f$i.bin" 2>/dev/null
done
for i in $(seq 1 80); do
  out="$("$BIN" import "fz$i" --from "$WORK/g/f$i.bin" 2>&1 <<<"$PASS")"
  check "$?" "$out"
done

echo "== 2) garbage profile names =="
for name in "" "../evil" "a/b" "a b" "ü" "a.b" "..." "-x" "$(printf 'x%.0s' $(seq 1 65))" "a
b"; do
  out="$("$BIN" show "$name" 2>&1 </dev/null)"
  check "$?" "$out"
done

echo "== 3) bit-flipped profile blobs → decrypt must degrade gracefully =="
import_interactive victim /dev/null
PROFILE="$PROFILES/victim.envpouch"
if [ ! -f "$PROFILE" ]; then
  echo "setup failed: victim profile missing"
  exit 1
fi
SZ=$(wc -c <"$PROFILE" | tr -d ' ')
for i in 0 1 2 3 4 5 6 7; do
  cp "$PROFILE" "$PROFILES/corrupt$i.envpouch"
  OFF=$(( (SZ * i) / 8 + 1 ))
  printf "\\x$(printf '%02x' $(((i * 37 + 1) % 256)))" |
    dd of="$PROFILES/corrupt$i.envpouch" bs=1 seek="$OFF" conv=notrunc 2>/dev/null
  out="$("$BIN" run "corrupt$i" --password-stdin -- true 2>&1 <<<"$PASS")"
  check "$?" "$out"
  out="$("$BIN" list 2>&1)"
  check "$?" "$out"
done

echo "== 4) garbage / directory files inside the profiles dir → list must survive =="
head -c 200 /dev/urandom >"$PROFILES/junk1.envpouch"
head -c 200 /dev/urandom >"$PROFILES/junk2.envpouch"
mkdir -p "$PROFILES/junkdir.envpouch"
out="$("$BIN" list 2>&1)"
check "$?" "$out"
out="$("$BIN" run junk1 --password-stdin -- true 2>&1 <<<"$PASS")"
check "$?" "$out"

echo "== 5) empty / oversized .env inputs =="
: >"$WORK/empty.env"
import_interactive emptyprof "$WORK/empty.env"
out="$("$BIN" show emptyprof 2>&1 </dev/null)"
check "$?" "$out"
head -c 1048576 /dev/urandom >"$WORK/big.env"
out="$("$BIN" import bigprof --from "$WORK/big.env" 2>&1 <<<"$PASS")"
check "$?" "$out"

echo "== cleanup =="
for p in victim emptyprof bigprof fz1 fz2 fz3 junk1 junk2; do
  printf 'y\n' | "$BIN" rm "$p" >/dev/null 2>&1
done
for i in 0 1 2 3 4 5 6 7; do
  printf 'y\n' | "$BIN" rm "corrupt$i" >/dev/null 2>&1
done
rm -rf "$PROFILES/junkdir.envpouch"

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "CLI FUZZ SMOKE PASSED ($N invocations, no panics/aborts, all exits documented)"
else
  echo "CLI FUZZ SMOKE FAILED ($N invocations)"
  exit 1
fi
