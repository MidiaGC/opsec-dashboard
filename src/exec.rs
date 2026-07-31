//! Subprocess execution for the checks.
//!
//! Every helper the dashboard shells out to (`ip`, `ss`, `nft`, `journalctl`, …)
//! goes through here so that three things are guaranteed:
//!
//! 1. **Timeouts.** A wedged helper stalls one check, never the whole app.
//! 2. **Distinguishable failures.** "ran fine, printed nothing" and "binary is
//!    not installed" are different facts and must not collapse into `None`.
//! 3. **Testability.** Checks are written against [`Outcome`], a plain data
//!    type, so their failure paths can be unit-tested without mocking `Command`.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Wall-clock budget for a single helper invocation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for helpers that legitimately take longer (`journalctl` scanning a
/// 24h window on a busy machine).
pub const SLOW_TIMEOUT: Duration = Duration::from_secs(15);

/// How often we re-check whether the child exited while waiting on the deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

static ALLOW_SUDO: AtomicBool = AtomicBool::new(true);

/// Enable/disable the `sudo -n` escalation attempts made by privileged checks.
pub fn set_allow_sudo(allow: bool) {
    ALLOW_SUDO.store(allow, Ordering::Relaxed);
}

/// Whether privileged checks may retry through `sudo -n`.
pub fn sudo_allowed() -> bool {
    ALLOW_SUDO.load(Ordering::Relaxed)
}

/// The result of trying to run a helper program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The process ran to completion. `success` is the exit status.
    Completed {
        stdout: String,
        stderr: String,
        success: bool,
    },
    /// The binary is not installed / not on `PATH`.
    NotFound,
    /// The process exceeded its deadline and was killed.
    TimedOut,
    /// Spawning or waiting failed for some other reason (permissions, fork
    /// limits, …).
    Failed(String),
}

impl Outcome {
    /// Convenience constructor for tests: a successful run with the given stdout.
    pub fn ok(stdout: &str) -> Self {
        Outcome::Completed {
            stdout: stdout.to_string(),
            stderr: String::new(),
            success: true,
        }
    }

    /// Convenience constructor for tests: a failed run (non-zero exit).
    pub fn failed_with(stdout: &str, stderr: &str) -> Self {
        Outcome::Completed {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            success: false,
        }
    }

    /// Standard output, or `""` if the process never produced any.
    pub fn stdout(&self) -> &str {
        match self {
            Outcome::Completed { stdout, .. } => stdout,
            _ => "",
        }
    }

    /// Standard error, or `""` if the process never produced any.
    pub fn stderr(&self) -> &str {
        match self {
            Outcome::Completed { stderr, .. } => stderr,
            _ => "",
        }
    }

    /// True only when the process ran *and* exited zero.
    pub fn succeeded(&self) -> bool {
        matches!(self, Outcome::Completed { success: true, .. })
    }

    /// Stdout, but only when the process exited zero. Use this when an empty
    /// stdout is a meaningful answer (e.g. "no matching journal entries") and
    /// must not be confused with a broken invocation.
    pub fn success_stdout(&self) -> Option<&str> {
        match self {
            Outcome::Completed {
                stdout,
                success: true,
                ..
            } => Some(stdout),
            _ => None,
        }
    }

    /// A short human-readable reason when the program could not be run at all.
    /// `None` means the program ran (whatever its exit status).
    pub fn unavailable_reason(&self) -> Option<String> {
        match self {
            Outcome::Completed { .. } => None,
            Outcome::NotFound => Some("command not installed".to_string()),
            Outcome::TimedOut => Some("command timed out".to_string()),
            Outcome::Failed(e) => Some(format!("command error: {e}")),
        }
    }
}

/// Run `prog` with `args` under the default timeout.
pub fn run(prog: &str, args: &[&str]) -> Outcome {
    run_timeout(prog, args, DEFAULT_TIMEOUT)
}

/// Run `prog` with `args`, killing it if it outlives `timeout`.
///
/// stdout/stderr are drained on dedicated threads so a chatty child can never
/// deadlock against a full pipe buffer while we are waiting on the deadline.
pub fn run_timeout(prog: &str, args: &[&str], timeout: Duration) -> Outcome {
    let mut child = match Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::NotFound,
        Err(e) => return Outcome::Failed(e.to_string()),
    };

    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_reader = std::thread::spawn(move || drain(out_pipe));
    let err_reader = std::thread::spawn(move || drain(err_pipe));

    let deadline = Instant::now() + timeout;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                return Outcome::Failed(e.to_string());
            }
        }
    };

    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();

    match exit {
        Some(status) => Outcome::Completed {
            stdout,
            stderr,
            success: status.success(),
        },
        None => Outcome::TimedOut,
    }
}

/// Run a command that may need root: try unprivileged first, then retry once
/// through `sudo -n` (never prompts) if that is permitted.
///
/// Returns the privileged retry only when it actually succeeded, so a failing
/// `sudo -n` does not mask the more informative unprivileged error.
pub fn run_privileged(prog: &str, args: &[&str]) -> Outcome {
    let direct = run(prog, args);
    if direct.succeeded() || !sudo_allowed() {
        return direct;
    }

    let mut sudo_args = vec!["-n", prog];
    sudo_args.extend_from_slice(args);
    let escalated = run("sudo", &sudo_args);
    if escalated.succeeded() {
        escalated
    } else {
        direct
    }
}

/// Read a pipe to EOF, losslessly converting invalid UTF-8 rather than failing.
fn drain<R: Read>(pipe: Option<R>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    match pipe.read_to_end(&mut buf) {
        Ok(_) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

/// Read a file under `/proc` or `/sys`, trimmed. `None` if it does not exist or
/// is not readable.
pub fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}
