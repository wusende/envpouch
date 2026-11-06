//! Minimal signal plumbing for `run` (spec §4.2).
//!
//! Signal handlers must be async-signal-safe: the handler only sets one bit
//! per signal number in a static AtomicU32 (a pending bitmask, not a single
//! slot — two different signals arriving within one 10 ms poll interval must
//! both survive); the main polling loop pops the lowest pending signal and
//! forwards it to the child's process group.

use std::sync::atomic::{AtomicU32, Ordering};

static PENDING: AtomicU32 = AtomicU32::new(0);

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
    if (1..=31).contains(&sig) {
        PENDING.fetch_or(1 << sig, Ordering::Relaxed);
    }
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

/// Pop one pending signal, lowest number first (0 if none). The same signal
/// raised twice before it is forwarded collapses into one delivery —
/// acceptable, forwarding it once per poll tick has the same effect.
pub fn take() -> libc::c_int {
    let bits = PENDING.load(Ordering::Relaxed);
    if bits == 0 {
        return 0;
    }
    let sig = bits.trailing_zeros() as libc::c_int;
    // Clear only this bit: a different signal raised concurrently stays set
    PENDING.fetch_and(!(1 << sig), Ordering::Relaxed);
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the handler function directly (no real signals are raised).
    /// Distinct signals must not overwrite each other; duplicates collapse.
    #[test]
    fn pending_bitmask_preserves_distinct_signals() {
        assert_eq!(take(), 0);
        handler(libc::SIGTERM);
        handler(libc::SIGINT); // second signal within one poll window
        assert_eq!(take(), libc::SIGINT, "lowest signal pops first");
        assert_eq!(take(), libc::SIGTERM, "first signal survives the second");
        assert_eq!(take(), 0);

        handler(libc::SIGWINCH);
        handler(libc::SIGWINCH); // duplicate collapses
        assert_eq!(take(), libc::SIGWINCH);
        assert_eq!(take(), 0);
    }

    #[test]
    fn handler_ignores_out_of_range_signal_numbers() {
        handler(0);
        handler(32);
        handler(-1);
        assert_eq!(take(), 0);
    }
}
