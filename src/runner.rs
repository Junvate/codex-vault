use std::{
    env,
    ffi::{OsStr, OsString},
    process::{Command, Stdio},
};

use crate::{
    error::{Result, VaultError},
    store::VaultStore,
};

/// Unlocks a profile, runs the configured real Codex executable, and reseals the profile.
///
/// # Errors
///
/// Returns an error when authentication, process launch, process waiting, or resealing fails.
pub fn run_codex(
    store: &VaultStore,
    username: &str,
    password: &[u8],
    arguments: &[OsString],
) -> Result<i32> {
    let executable =
        env::var_os("CODEX_VAULT_REAL_CODEX").unwrap_or_else(|| OsString::from("codex"));
    run_program(store, username, password, executable, arguments)
}

/// Unlocks a profile, runs an explicit executable, and reseals the profile.
///
/// This is exposed for controlled integrations and testing. Normal callers should use
/// [`run_codex`].
///
/// # Errors
///
/// Returns an error when authentication, process launch, process waiting, or resealing fails.
pub fn run_program(
    store: &VaultStore,
    username: &str,
    password: &[u8],
    executable: impl AsRef<OsStr>,
    arguments: &[OsString],
) -> Result<i32> {
    let vault = store.unlock(username, password)?;
    let mut child = match Command::new(executable)
        .args(arguments)
        .env("CODEX_HOME", vault.codex_home())
        .env("CODEX_VAULT_ACTIVE_USER", vault.username())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            vault.close()?;
            return Err(VaultError::Launch(error.to_string()));
        }
    };

    #[cfg(unix)]
    let signal_forwarder = match SignalForwarder::start(child.id()) {
        Ok(forwarder) => forwarder,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            vault.close()?;
            return Err(error);
        }
    };
    let status_result = child.wait();
    #[cfg(unix)]
    signal_forwarder.stop();
    let close_result = vault.close();
    let status = status_result?;
    close_result?;

    if let Some(code) = status.code() {
        return Ok(code);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return Ok(128 + status.signal().unwrap_or(0));
    }

    #[allow(unreachable_code)]
    Ok(1)
}

#[cfg(unix)]
struct SignalForwarder {
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl SignalForwarder {
    fn start(child_pid: u32) -> Result<Self> {
        use signal_hook::{
            consts::signal::{SIGHUP, SIGINT, SIGTERM},
            iterator::Signals,
        };

        let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;
        let handle = signals.handle();
        let thread = std::thread::spawn(move || {
            for signal in signals.forever() {
                if let Ok(signal) = nix::sys::signal::Signal::try_from(signal) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child_pid.cast_signed()),
                        signal,
                    );
                }
            }
        });
        Ok(Self {
            handle,
            thread: Some(thread),
        })
    }

    fn stop(mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
