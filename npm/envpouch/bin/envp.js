#!/usr/bin/env node
// Launcher for the binary bundled under vendor/.
// Arguments, stdio, signals and the exit code pass straight through, so in a
// script `envp run prod ./x` behaves exactly like the native binary.
//
// Every platform ships inside the package (see scripts/npm-pack.sh): installing
// needs only the npm registry, never GitHub, and no network. The only install
// script is bin/postinstall.js, which prints the command name (`envp`).
//
// Dependency-free CommonJS on purpose: this runs before anything else is
// installed and must survive every npm/pnpm/yarn node version.

"use strict";

const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const HOMEPAGE = "https://github.com/wusende/envpouch";

// One universal2 binary covers both macOS architectures; Linux builds are
// per-architecture glibc binaries.
const VENDOR_DIR = {
  "linux-x64": "linux-x64",
  "linux-arm64": "linux-arm64",
  "darwin-x64": "darwin-universal",
  "darwin-arm64": "darwin-universal",
  "win32-x64": "win32-x64",
};

function bail(reason) {
  process.stderr.write(
    `envpouch: ${reason}\n` +
      `No prebuilt binary for this system. Install from source instead:\n` +
      `  cargo install envpouch\n` +
      `${HOMEPAGE}#install--build\n`,
  );
  process.exit(1);
}

// The Linux builds are glibc. A glibc binary started under musl fails with a
// bare "ENOENT" on exec, which reads like a broken install; name the real
// cause instead.
function isMusl() {
  if (process.platform !== "linux") return false;
  try {
    return !process.report.getReport().header.glibcVersionRuntime;
  } catch {
    return false;
  }
}

const key = `${process.platform}-${process.arch}`;
const dir = VENDOR_DIR[key];
if (!dir) {
  bail(`no prebuilt binary for ${key}`);
}

if (isMusl()) {
  bail(`${key} is a glibc build and this system uses musl (Alpine?)`);
}

const BIN = path.join(
  __dirname,
  "..",
  "vendor",
  dir,
  process.platform === "win32" ? "envp.exe" : "envp",
);

if (!fs.existsSync(BIN)) {
  bail(`${BIN} is missing (corrupt install? try: npm rebuild envpouch)`);
}

const child = spawn(BIN, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: false,
});

// The terminal already signals the whole process group on Ctrl-C, but npm's
// shim can run us detached; forwarding keeps one behaviour either way.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  try {
    process.on(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  } catch {
    // Windows has no SIGHUP; ignore.
  }
}

child.on("error", (error) => {
  bail(`failed to start ${BIN}: ${error.message}`);
});

child.on("exit", (code, signal) => {
  if (signal) {
    const number = os.constants.signals[signal];
    process.exit(number ? 128 + number : 1);
  }
  process.exit(code === null ? 1 : code);
});
