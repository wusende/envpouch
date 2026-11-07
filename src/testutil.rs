//! Test-only helpers (compiled into the test binary only).
//!
//! Environment variables are process-global and `unsafe` to mutate since
//! edition 2024, so every test that touches `ENVPOUCH_HOME` serializes on
//! one mutex — parallel tests must not observe each other's variables.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Hold this for the whole body of any test that mutates ENVPOUCH_HOME.
pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn set_envpouch_home(dir: &Path) {
    unsafe { std::env::set_var("ENVPOUCH_HOME", dir) };
}

pub(crate) fn clear_envpouch_home() {
    unsafe { std::env::remove_var("ENVPOUCH_HOME") };
}
