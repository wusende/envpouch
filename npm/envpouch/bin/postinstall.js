#!/usr/bin/env node
// Prints the one thing a fresh install needs to know: the package is
// `envpouch`, but the command is `envp`. Nothing else — no downloads, no
// configuration, no network.
//
// npm captures lifecycle-script output and, with its default
// `foreground-scripts=false`, throws it away on success. Writing to the
// terminal device instead of stdout is what makes this notice actually show
// up. Without a tty (CI, no controlling terminal) fall back to stdout.

"use strict";

const fs = require("node:fs");

const pkg = require("../package.json");

const message =
  `\nenvpouch ${pkg.version} installed — the command is \`envp\` (not \`envpouch\`).\n` +
  `\n  envp import prod --from .env.production   # store a .env file as an encrypted profile\n` +
  `  envp run prod -- ./start-server.sh        # run a command with those variables\n` +
  `  envp --help                               # all commands\n` +
  `\nDocs: ${pkg.homepage}\n\n`;

function writeToTerminal(text) {
  for (const device of process.platform === "win32" ? ["CONOUT$"] : ["/dev/tty"]) {
    let fd;
    try {
      fd = fs.openSync(device, "w");
      fs.writeSync(fd, text);
      return true;
    } catch {
      // No controlling terminal (CI, piped install): try the next option.
    } finally {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
          // Ignore: the message is already out.
        }
      }
    }
  }
  return false;
}

if (!writeToTerminal(message)) {
  process.stdout.write(message);
}
