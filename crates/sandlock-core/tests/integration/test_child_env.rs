//! The child's environment (`env_var`, `clean_env`) is built in the parent and
//! installed in the child without going through `std::env` (see
//! `context::ChildEnv`). These tests pin what the child sees, that `execvp`
//! still resolves commands against that environment, and that spawning stays
//! live while other threads of the parent read the environment.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandlock_core::{Sandbox, SandboxBuilder};

fn base() -> SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
}

/// A fresh directory holding one executable file `name` with `body`.
///
/// The file is written by a separate process, so no descriptor open for
/// writing on it ever exists in this test process. Otherwise a sandbox forked
/// concurrently by another test could inherit that descriptor and make the
/// `execve` fail with `ETXTBSY` (see `test_chroot.rs`, which hard-links for
/// the same reason).
fn dir_with_script(tag: &str, name: &str, body: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sandlock-test-childenv-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join(name);
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"", "sh", body])
        .arg(&script)
        .status()
        .unwrap();
    assert!(status.success(), "writing {} failed", script.display());
    dir
}

/// Sets the flag when dropped, so the reader thread stops even if the test
/// panics before reaching its end.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn test_env_var_and_inherited_vars_reach_child() {
    std::env::set_var("SANDLOCK_TEST_CHILDENV_INHERITED", "from-parent");
    std::env::set_var("SANDLOCK_TEST_CHILDENV_OVERRIDE", "from-parent");
    let mut policy = base()
        .env_var("SANDLOCK_TEST_CHILDENV_SET", "from-sandbox")
        .env_var("SANDLOCK_TEST_CHILDENV_OVERRIDE", "from-sandbox")
        .build()
        .unwrap();
    let result = policy.run(&["/usr/bin/env"]).await.unwrap();
    std::env::remove_var("SANDLOCK_TEST_CHILDENV_INHERITED");
    std::env::remove_var("SANDLOCK_TEST_CHILDENV_OVERRIDE");
    assert!(result.success(), "exit={:?}", result.code());
    let stdout = result.stdout_str().unwrap_or_default();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.contains(&"SANDLOCK_TEST_CHILDENV_INHERITED=from-parent"), "got: {stdout}");
    assert!(lines.contains(&"SANDLOCK_TEST_CHILDENV_SET=from-sandbox"), "got: {stdout}");
    let overrides: Vec<&&str> =
        lines.iter().filter(|l| l.starts_with("SANDLOCK_TEST_CHILDENV_OVERRIDE=")).collect();
    assert_eq!(overrides, [&"SANDLOCK_TEST_CHILDENV_OVERRIDE=from-sandbox"], "got: {stdout}");
}

#[tokio::test]
async fn test_clean_env_leaves_only_declared_vars() {
    let mut policy = base()
        .clean_env(true)
        .env_var("SANDLOCK_TEST_CHILDENV_ONLY", "1")
        .build()
        .unwrap();
    let result = policy.run(&["/usr/bin/env"]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    assert_eq!(result.stdout_str().unwrap_or_default().trim(), "SANDLOCK_TEST_CHILDENV_ONLY=1");
}

/// `execvp` must search the child's `PATH`, not the parent's: the environment
/// is installed before exec.
#[tokio::test]
async fn test_path_lookup_uses_the_child_path() {
    let dir = dir_with_script("path", "sandlock-childenv-hello", "#!/bin/sh\necho found-on-child-path\n");
    let mut policy = base()
        .fs_read(&dir)
        .env_var("PATH", dir.to_str().unwrap())
        .build()
        .unwrap();
    let result = policy.run(&["sandlock-childenv-hello"]).await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.success(), "exit={:?} stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    assert_eq!(result.stdout_str().unwrap_or_default().trim(), "found-on-child-path");
}

/// A script without a shebang fails `execve` with `ENOEXEC`; `execvp` then
/// runs it with `/bin/sh`.
#[tokio::test]
async fn test_script_without_shebang_runs_with_bin_sh() {
    let dir = dir_with_script("noshebang", "sandlock-childenv-noshebang", "echo ran-by-bin-sh\n");
    let mut policy = base()
        .fs_read(&dir)
        .env_var("SANDLOCK_TEST_CHILDENV_MARK", "1")
        .build()
        .unwrap();
    let script = dir.join("sandlock-childenv-noshebang");
    let result = policy.run(&[script.to_str().unwrap()]).await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.success(), "exit={:?} stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    assert_eq!(result.stdout_str().unwrap_or_default().trim(), "ran-by-bin-sh");
}

/// With `PATH` unset in the child, `execvp` falls back to the C library's
/// default search path, so a bare command name still runs. (`env` itself, not
/// a shell: `sh` would put a default `PATH` back into its own environment.)
#[tokio::test]
async fn test_unset_path_uses_the_default_search_path() {
    let mut policy = base().clean_env(true).build().unwrap();
    let result = policy.run(&["env"]).await.unwrap();
    assert!(result.success(), "exit={:?} stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    assert_eq!(result.stdout_str().unwrap_or_default().trim(), "", "PATH must be unset in the child");
}

/// A name `setenv` would reject used to panic inside the forked child; it is
/// now an error from `run`, before any fork.
#[tokio::test]
async fn test_invalid_env_name_is_an_error_not_a_broken_child() {
    let mut policy = base().env_var("SANDLOCK=BAD", "x").build().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), policy.run(&["/usr/bin/true"]))
        .await
        .expect("run must not hang");
    let err = result.expect_err("an invalid name must fail the run").to_string();
    assert!(err.contains("invalid environment variable name"), "got: {err}");
    assert!(!err.contains("BAD"), "the part after `=` must not be echoed: {err}");
}

/// Regression: the child used to rewrite its environment with
/// `std::env::set_var` after `fork()`. If another thread of the parent held
/// std's environment lock at that moment, the child blocked forever and never
/// exec'd. Concurrent spawns with an `env_var`, while a thread keeps reading
/// the environment, must all finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_spawns_stay_live_while_other_threads_read_the_env() {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_guard = StopOnDrop(Arc::clone(&stop));
    let reader = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::env::var_os("PATH");
                std::thread::yield_now();
            }
        })
    };
    let mut hung = 0;
    for _ in 0..4 {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            set.spawn(async {
                let mut sb = Sandbox::builder()
                    .fs_read("/usr")
                    .fs_read_if_exists("/lib")
                    .fs_read_if_exists("/lib64")
                    .env_var("SANDLOCK_TEST_CHILDENV_CONCURRENT", "1")
                    .build()
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(10), sb.run(&["/usr/bin/true"]))
                    .await
                    .is_err()
            });
        }
        while let Some(r) = set.join_next().await {
            hung += r.unwrap() as usize;
        }
    }
    drop(stop_guard);
    reader.join().unwrap();
    assert_eq!(hung, 0, "{hung} of 64 sandboxes never exec'd");
}
