//! Minimal signal plumbing for `run` (spec §4.2).
//!
//! Signal handlers must be async-signal-safe: the handler only stores the
//! signal number in a static AtomicI32; the main polling loop reads and
//! clears it, then forwards the signal to the child's process group.

use std::sync::atomic::{AtomicI32, Ordering};

static FORWARDED: AtomicI32 = AtomicI32::new(0);

/// Signals captured and forwarded to the child (spec §4.2). SIGSTOP/SIGKILL
/// cannot be caught and are intentionally absent.
const FORWARDED_SIGNALS: [libc::c_int; 8] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGWINCH,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

extern "C" fn handler(sig: libc::c_int) {
    FORWARDED.store(sig, Ordering::Relaxed);
}

/// Install the forwarding handlers. Call before spawning the child.
pub fn install() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in FORWARDED_SIGNALS {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Take the pending forwarded signal (0 if none), clearing the flag.
pub fn take() -> libc::c_int {
    FORWARDED.swap(0, Ordering::Relaxed)
}
