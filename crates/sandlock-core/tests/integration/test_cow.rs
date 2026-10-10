use sandlock_core::{Sandbox, SandboxBuilder};
use sandlock_core::sandbox::BranchAction;
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-cow-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

// ============================================================
// Seccomp-based COW tests (workdir set)
// ============================================================

/// Test that seccomp COW creates files in upper, committed on exit.
#[tokio::test]
async fn test_seccomp_cow_create_file() {
    let workdir = temp_dir("seccomp-create");
    fs::write(workdir.join("existing.txt"), "hello").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)  // workdir set → seccomp COW
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let new_file = workdir.join("new.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "touch should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            // After commit, new file should exist in workdir
            assert!(new_file.exists(), "new.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that seccomp COW abort discards changes.
#[tokio::test]
async fn test_seccomp_cow_abort() {
    let workdir = temp_dir("seccomp-abort");
    fs::write(workdir.join("existing.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let new_file = workdir.join("aborted.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(_) => {
            // After abort, new file should NOT exist
            assert!(!new_file.exists(), "aborted.txt should not exist after abort");
            // Original file should be unchanged
            let content = fs::read_to_string(workdir.join("existing.txt")).unwrap();
            assert_eq!(content, "original");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW with relative paths (AT_FDCWD).
///
/// Regression test: resolve_at_path must truncate dirfd to i32 before
/// comparing with AT_FDCWD (-100). The kernel stores AT_FDCWD as
/// 0x00000000FFFFFF9C in the 64-bit seccomp_data.args field, not
/// 0xFFFFFFFFFFFFFF9C.
#[tokio::test]
async fn test_seccomp_cow_relative_path_abort() {
    let workdir = temp_dir("seccomp-relpath");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use relative paths (triggers AT_FDCWD in openat) — the child's cwd is set via .cwd().
    let result = policy.clone().run(&[
        "sh", "-c", "echo MUTATED >> orig.txt; echo leak > leaked.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With abort, original file must be unchanged
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert_eq!(content, "original\n", "orig.txt should be unchanged after abort");
            // New file must not exist
            assert!(!workdir.join("leaked.txt").exists(), "leaked.txt should not exist after abort");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW commit with relative paths (AT_FDCWD).
#[tokio::test]
async fn test_seccomp_cow_relative_path_commit() {
    let workdir = temp_dir("seccomp-relpath-commit");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let result = policy.clone().run(&[
        "sh", "-c", "echo APPENDED >> orig.txt; echo new > created.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With commit, changes should be merged back
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert!(content.contains("APPENDED"), "orig.txt should have appended content after commit");
            assert!(content.starts_with("original\n"), "orig.txt should preserve original content");
            // New file should exist
            let new_content = fs::read_to_string(workdir.join("created.txt")).unwrap();
            assert_eq!(new_content.trim(), "new", "created.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that openat with O_DIRECTORY works for COW-created directories.
///
/// When a directory is created via COW (only in upper layer), openat with
/// O_DIRECTORY must resolve to the upper path.  Without this fix,
/// prepare_open skipped O_DIRECTORY opens and the kernel returned ENOENT.
#[tokio::test]
async fn test_seccomp_cow_open_directory() {
    let workdir = temp_dir("seccomp-opendir");
    let out_file = workdir.join("opendir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // mkdir creates the dir in COW upper; python opens it with O_DIRECTORY.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.close(fd); ",
            "open('{}', 'w').write('ok')\"",
        ),
        out_file.display()
    );
    let result = policy.clone().run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert_eq!(content, "ok");
        }
        Err(e) => eprintln!("Seccomp COW opendir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}


/// Test that chdir works for directories created inside COW.
///
/// When a directory is created via COW (only exists in the upper layer),
/// chdir must be intercepted and redirected to the upper path.  Without
/// this, the kernel returns ENOENT because it doesn't see the COW directory.
#[tokio::test]
async fn test_seccomp_cow_chdir_to_created_dir() {
    let workdir = temp_dir("seccomp-chdir");
    let out_file = workdir.join("chdir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Create a nested directory through a dirfd so the COW handler must map the
    // upper-layer fd target back to the logical workdir before mkdirat.
    // Use physical pwd so the assertion covers getcwd virtualization.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.mkdir('deep', dir_fd=fd); ",
            "os.close(fd)\" && ",
            "cd subdir/deep && pwd -P > {}"
        ),
        out_file.display()
    );
    let result = policy.clone().run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert!(
                content.trim().ends_with("subdir/deep"),
                "pwd should end with subdir/deep, got: {}",
                content.trim()
            );
        }
        Err(e) => eprintln!("Seccomp COW chdir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that the raw open syscall ABI works correctly with COW.
///
/// Regression test: handle_cow_open always read args in openat() layout
/// (dirfd=args[0], path=args[1], flags=args[2]), but open() uses
/// (path=args[0], flags=args[1], mode=args[2]). This caused COW to miss
/// all legacy open() calls on x86_64, falling through to the kernel. ARM64
/// and riscv64 do not provide SYS_open, so they use the equivalent raw
/// openat ABI.
#[tokio::test]
async fn test_seccomp_cow_legacy_open_syscall() {
    let workdir = temp_dir("seccomp-legacy-open");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-legacy-open-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use raw syscall ABI to create a file, then verify it's visible during
    // the run but discarded on abort. x86_64 uses legacy SYS_open; ARM64 and
    // riscv64 use the equivalent openat(AT_FDCWD, ...) ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_TRUNC = 512\n",
        "path = b'{wd}/newfile.txt'\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'created via raw open')\n",
        "    os.close(fd)\n",
        "    content = open('{wd}/newfile.txt').read()\n",
        "    open('{out}', 'w').write(content)\n",
        "else:\n",
        "    open('{out}', 'w').write(f'FAILED:errno={{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "created via raw open", "raw open ABI should work with COW");
    // After abort, the file should not exist on the real filesystem
    assert!(!workdir.join("newfile.txt").exists(), "newfile.txt should not exist after abort");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// openat2 must land in the COW layer like open/openat.
///
/// Regression test: COW registered only openat and legacy open, so a raw
/// openat2(O_CREAT|O_TRUNC) under the workdir went straight to the kernel and
/// mutated the real directory, surviving an abort. openat2 also keeps flags
/// and mode in a struct open_how rather than in the syscall args.
#[tokio::test]
async fn test_seccomp_cow_openat2_syscall() {
    let workdir = temp_dir("seccomp-openat2");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-openat2-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // SYS_openat2 = 437 on every supported arch; open_how = {flags, mode, resolve}.
    let script = format!(concat!(
        "import ctypes, os\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "class OpenHow(ctypes.Structure):\n",
        "    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]\n",
        "O_WRONLY = 1; O_CREAT = 64; O_TRUNC = 512\n",
        "how = OpenHow(O_WRONLY | O_CREAT | O_TRUNC, 0o644, 0)\n",
        "fd = libc.syscall(437, -100, b'{wd}/newfile.txt', ctypes.byref(how), ctypes.sizeof(how))\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'created via raw openat2')\n",
        "    os.close(fd)\n",
        "    content = open('{wd}/newfile.txt').read()\n",
        "    open('{out}', 'w').write(content)\n",
        "else:\n",
        "    open('{out}', 'w').write(f'FAILED:errno={{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "created via raw openat2", "raw openat2 should work with COW");
    assert!(!workdir.join("newfile.txt").exists(), "newfile.txt should not exist after abort");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// renameat must land in the COW layer like rename and renameat2.
///
/// Regression test: COW registered renameat2 and legacy rename but not
/// renameat, so a raw renameat under the workdir renamed the real file and
/// survived an abort. On aarch64 libc's rename() compiles to renameat, so
/// there every ordinary rename escaped the branch. riscv64 has no renameat,
/// so the test runs the same check through renameat2 with no flags.
#[tokio::test]
async fn test_seccomp_cow_renameat_syscall() {
    let workdir = temp_dir("seccomp-renameat");
    fs::write(workdir.join("orig.txt"), "keep").unwrap();
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-renameat-{}", std::process::id()
    ));

    let mut policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // renameat is 264 on x86_64 and 38 on aarch64; riscv64 only has renameat2 (276).
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "old = b'{wd}/orig.txt'; new = b'{wd}/moved.txt'\n",
        "m = platform.machine()\n",
        "if m == 'x86_64':\n",
        "    r = libc.syscall(264, -100, old, -100, new)\n",
        "elif m == 'aarch64':\n",
        "    r = libc.syscall(38, -100, old, -100, new)\n",
        "else:\n",
        "    r = libc.syscall(276, -100, old, -100, new, 0)\n",
        "err = ctypes.get_errno()\n",
        "if r == 0 and not os.path.exists(old) and open(new).read() == 'keep':\n",
        "    open('{out}', 'w').write('renamed')\n",
        "else:\n",
        "    open('{out}', 'w').write(f'FAILED:ret={{r}},errno={{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "renamed", "raw renameat should work with COW");
    assert!(workdir.join("orig.txt").exists(), "orig.txt should be back after abort");
    assert!(!workdir.join("moved.txt").exists(), "moved.txt should not exist after abort");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Legacy stat/lstat/access must honor whiteouts.
///
/// Regression test: handle_cow_stat parsed every syscall with the at-variant
/// layout (dirfd=args[0], path=args[1]), but the legacy x86_64 variants put
/// the path in args[0]. The handler read the statbuf pointer as the path,
/// never matched the workdir, and fell through to the kernel, so a
/// static-libc child emitting legacy stat could see whiteouted lower entries
/// that newfstatat already reported as ENOENT. On aarch64/riscv64 the
/// helper's legacy-* commands fall back to newfstatat, keeping the test as
/// an at-variant whiteout check there.
#[tokio::test]
async fn test_seccomp_cow_legacy_stat_honors_whiteout() {
    let workdir = temp_dir("seccomp-legacy-stat");
    fs::write(workdir.join("gone.txt"), "SECRET").unwrap();
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let script = "rm gone.txt ; legacy-stat gone.txt ; legacy-lstat gone.txt ; legacy-access gone.txt";
    let result = policy.clone()
        .run(&[helper.to_str().unwrap(), "sh", "-c", script]).await;
    match result {
        Ok(r) => {
            let out = r.stdout_str().unwrap_or("").to_string();
            println!("legacy_stat_whiteout: stdout={:?}", out);
            assert_eq!(
                out.matches("ERR 2").count(),
                3,
                "legacy stat/lstat/access of a whiteouted file must all be ENOENT: {:?}",
                out
            );
            assert!(
                !out.contains("OK"),
                "whiteouted entry leaked through a legacy stat variant: {:?}",
                out
            );
        }
        Err(e) => eprintln!("legacy stat whiteout test skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// Test that O_CREAT|O_EXCL succeeds after unlink in COW mode.
///
/// Regression test: after unlink marked a file as deleted, the subsequent
/// O_CREAT|O_EXCL open correctly identified the file as deleted and prepared
/// a COW copy, but the supervisor's open() still had O_EXCL in the flags.
/// Since the file was just copied to upper, the kernel's open() returned
/// EEXIST. The fix strips O_EXCL from the supervisor's open flags.
#[tokio::test]
async fn test_seccomp_cow_excl_after_unlink() {
    let workdir = temp_dir("seccomp-excl-unlink");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-excl-unlink-{}", std::process::id()
    ));
    fs::write(workdir.join("target.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Unlink the file, then recreate it with O_CREAT|O_EXCL via raw open ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "path = b'{wd}/target.txt'\n",
        "ret = libc.unlink(path)\n",
        "if ret != 0:\n",
        "    open('{out}', 'w').write(f'UNLINK_FAILED:{{ctypes.get_errno()}}')\n",
        "    raise SystemExit(1)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_EXCL = 128\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'recreated')\n",
        "    os.close(fd)\n",
        "    open('{out}', 'w').write('OK')\n",
        "else:\n",
        "    open('{out}', 'w').write(f'OPEN_FAILED:{{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "O_EXCL after unlink should succeed, got: {}", content);
    // After commit, the file should contain the new content
    let target = fs::read_to_string(workdir.join("target.txt")).unwrap_or_default();
    assert_eq!(target, "recreated", "target.txt should have new content after commit");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Test that seccomp COW read isolation works (reads original before any writes).
#[tokio::test]
async fn test_seccomp_cow_read_existing() {
    let workdir = temp_dir("seccomp-read");
    fs::write(workdir.join("data.txt"), "hello world").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let out_file = workdir.join("out.txt");
    let cmd = format!(
        "cat {} > {}",
        workdir.join("data.txt").display(),
        out_file.display()
    );
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "cat should succeed");
            let content = fs::read_to_string(&out_file).unwrap_or_default();
            assert_eq!(content.trim(), "hello world");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Regression test: a file deleted inside the COW workdir must read back as
/// ENOENT, not its pre-delete content. The read/open path returned
/// `Skip -> Continue` for a whiteout, so the kernel opened the untouched lower
/// file and leaked the original bytes — while stat/access already returned
/// ENOENT, so the two paths disagreed and a deletion was invisible to a reader.
#[tokio::test]
async fn test_seccomp_cow_read_deleted_file_is_enoent() {
    let workdir = temp_dir("seccomp-read-deleted");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-{}", std::process::id()
    ));
    fs::write(workdir.join("secret.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Delete the file, then read it back with `dd`, which issues a bare
    // open(O_RDONLY) with no preceding path stat — unlike `cat FILE` or a shell
    // redirect, which stat first and would short-circuit on the (correct) stat
    // ENOENT without ever exercising the open path this fix targets. `dd`
    // succeeding means the open was honored and the untouched lower bytes leaked;
    // `dd` failing means the whiteout was honored (ENOENT). Both the copied bytes
    // and the marker land in /tmp (not the COW workdir), so they are real writes.
    let secret = workdir.join("secret.txt");
    let leak_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-leak-{}", std::process::id()
    ));
    let cmd = format!(
        "rm -f {secret}; if dd if={secret} of={leak} status=none; then printf 'OPENED' > {marker}; else printf 'DENIED' > {marker}; fi",
        secret = secret.display(),
        leak = leak_file.display(),
        marker = out_file.display(),
    );

    let result = policy.clone().run(&["sh", "-c", &cmd]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let marker = fs::read_to_string(&out_file).unwrap_or_default();
    let leaked = fs::read_to_string(&leak_file).unwrap_or_default();
    assert_eq!(
        marker, "DENIED",
        "open of a deleted COW file must be denied (ENOENT), not read lower content (leaked: {:?})", leaked
    );
    assert!(
        leaked.is_empty(),
        "no pre-delete bytes may leak through the read path, got: {:?}", leaked
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
    let _ = fs::remove_file(&leak_file);
}

/// Regression test: statx on a COW-created file must succeed.
///
/// statx is what `ls`, `stat`, and most modern coreutils use. The COW
/// statx handler returned Continue when the file existed in the upper
/// layer, so the kernel re-ran statx against the un-redirected lower path
/// and returned ENOENT for files that live only in upper.
#[tokio::test]
async fn test_seccomp_cow_statx_created_file() {
    let workdir = temp_dir("seccomp-statx");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-statx-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Create a file that lives only in the COW upper layer, then statx it
    // via the raw syscall (the path coreutils `stat`/`ls` take).
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "open('created.txt', 'w').write('hi')\n",
        "buf = ctypes.create_string_buffer(256)\n",
        "AT_FDCWD = -100\n",
        "STATX_BASIC_STATS = 0x7ff\n",
        "nr = 291 if platform.machine() in ('aarch64', 'riscv64') else 332\n",
        "ret = libc.syscall(nr, AT_FDCWD, b'created.txt', 0, STATX_BASIC_STATS, buf)\n",
        "err = ctypes.get_errno()\n",
        "open('{out}', 'w').write('OK' if ret == 0 else f'FAIL:errno={{err}}')\n",
    ), out = out_file.display());

    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "statx on COW-created file should succeed, got: {}", content);

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Regression test: a binary created inside the COW workdir must
/// be executable. execve had no COW redirect, so the kernel resolved the
/// un-redirected lower path and returned ENOENT for binaries that live
/// only in the upper layer.
#[tokio::test]
async fn test_seccomp_cow_exec_created_file() {
    let workdir = temp_dir("seccomp-exec");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Copy our own static rootfs-helper into the COW workdir (lands in
    // upper), then exec it. The helper (not a system binary like /bin/echo,
    // whose behavior varies across hosts: Ubuntu rust-coreutils ships a
    // multicall binary) is itself busybox-style: invoked as `./echo` it
    // dispatches on basename(argv[0]). That also catches the exec redirect
    // clobbering argv[0]: shells pass the same buffer as execve path and
    // argv[0], so rewriting the path to /proc/self/fd/N must relocate
    // argv[0], or the helper sees basename "N" and exits 127.
    let cmd = format!("cp {} echo && ./echo EXEC_OK", helper.display());
    let result = policy.clone().run(&[
        "sh", "-c", &cmd,
    ]).await.unwrap();

    assert!(
        result.success(),
        "exec of COW-created binary should succeed (argv[0] preserved), exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK"),
        "exec'd binary should print EXEC_OK, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// Exec a COW-created binary with the path and argv strings tightly packed
/// in one buffer: the /proc/self/fd/N rewrite window covers argv[1] too, so
/// the supervisor must relocate every clobbered string, not only argv[0].
/// Shell-driven layouts happen to keep argv[1] out of the window; this
/// crafts the packed layout directly with execve(2) via ctypes.
#[tokio::test]
async fn test_seccomp_cow_exec_packed_argv_relocation() {
    let workdir = temp_dir("seccomp-exec-packed");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, shutil, os\n",
        "shutil.copy('{helper}', 'echo')\n",
        "os.chmod('echo', 0o755)\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "buf = ctypes.create_string_buffer(b'./echo\\0EXEC_OK_PACKED\\0')\n",
        "base = ctypes.addressof(buf)\n",
        "argv = (ctypes.c_void_p * 3)(base, base + 7, None)\n",
        "envp = (ctypes.c_void_p * 1)(None)\n",
        "libc.execve(ctypes.c_void_p(base), argv, envp)\n",
        "raise SystemExit('execve failed errno=%d' % ctypes.get_errno())\n",
    ), helper = helper.display());

    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();

    assert!(
        result.success(),
        "packed-argv exec should succeed, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK_PACKED"),
        "argv[1] must survive the path rewrite, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// Branch disposition on an abandoned sandbox
// ============================================================

/// Number of branch subdirectories under a `fs_storage` dir.
fn branch_count(storage: &std::path::Path) -> usize {
    fs::read_dir(storage).map(|rd| rd.count()).unwrap_or(0)
}

/// `BranchAction::Keep` means "preserve the changes for later inspection", and a
/// sandbox that is abandoned without `wait()` IS the case worth inspecting.
///
/// A branch only reaches `Sandbox`'s own disposition after a completed `wait()`,
/// so on this path the branch's `Drop` backstop is what decides. It must honour
/// an explicit `Keep` — and must still reclaim under the default action, which
/// is the leak the backstop exists to close.
///
/// `Keep` is honoured from EITHER action. An abandoned run has no exit status,
/// so there is no choosing between `on_exit` and `on_error`: a caller who asked
/// to keep the changes in either case asked to keep them here.
#[tokio::test]
async fn test_abandoned_sandbox_honours_keep_and_still_reclaims_by_default() {
    let workdir = temp_dir("abandon-wd");
    let keep_store = temp_dir("abandon-keep-st");
    let on_error_store = temp_dir("abandon-onerror-st");
    let default_store = temp_dir("abandon-default-st");
    for d in [&keep_store, &on_error_store, &default_store] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }

    let base = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir);

    {
        let mut sb = base.clone()
            .fs_storage(&keep_store)
            .on_exit(BranchAction::Keep)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo kept > k.txt"]).await.unwrap();
        sb.start().unwrap();
        // Dropped here, with no wait(): the caller walked away from the run.
    }
    {
        let mut sb = base.clone()
            .fs_storage(&on_error_store)
            .on_error(BranchAction::Keep)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo kept > k.txt"]).await.unwrap();
        sb.start().unwrap();
    }
    {
        let mut sb = base.clone()
            .fs_storage(&default_store)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo gone > g.txt"]).await.unwrap();
        sb.start().unwrap();
    }

    // Dropping the sandbox does not itself drop the branch: the shared COW state
    // is also held by the aborted supervisor task, so the branch is dropped when
    // the runtime reaps it. Wait for the default store to empty — that reclaim IS
    // the proof that the branch drops have run, without which the Keep assertion
    // below would pass on a branch that simply had not been dropped yet.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while branch_count(&default_store) != 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        branch_count(&default_store), 0,
        "an abandoned sandbox with the default action must still reclaim its upper",
    );
    assert_eq!(
        branch_count(&keep_store), 1,
        "an abandoned sandbox configured on_exit(Keep) must still preserve its upper",
    );
    assert_eq!(
        branch_count(&on_error_store), 1,
        "an abandoned sandbox configured on_error(Keep) must still preserve its upper",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&keep_store);
    let _ = fs::remove_dir_all(&on_error_store);
    let _ = fs::remove_dir_all(&default_store);
}

// ============================================================
// Branch disposition on a completed run
// ============================================================

/// Build a COW sandbox over `workdir` with the two dispositions under test.
fn disposition_sandbox(
    workdir: &std::path::Path,
    on_exit: BranchAction,
    on_error: BranchAction,
) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir).workdir(workdir).cwd(workdir)
        .on_exit(on_exit)
        .on_error(on_error)
        .build()
        .unwrap()
}

/// Run `script` in a fresh COW workdir under the two dispositions and report
/// the child's exit code together with whether its write reached the workdir.
async fn run_and_report_landing(
    tag: &str,
    script: &str,
    on_exit: BranchAction,
    on_error: BranchAction,
) -> (Option<i32>, bool) {
    let workdir = temp_dir(tag);
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);

    let code = {
        let mut sb = disposition_sandbox(&workdir, on_exit, on_error);
        let result = sb.run(&["sh", "-c", script]).await.unwrap();
        result.code()
        // Dropped here: the disposition runs in `Sandbox`'s Drop.
    };
    let landed = workdir.join("f.txt").exists();
    let _ = fs::remove_dir_all(&workdir);
    (code, landed)
}

/// Which branch action a completed run applies is selected by the child's exit
/// status: `on_exit` for exit code 0, `on_error` for a non-zero one.
///
/// The two failing runs differ only in which way round the actions are wired,
/// so an implementation that always took `on_exit` and one that always took
/// `on_error` each contradict one of them; the succeeding run pins which of the
/// two names goes with which status.
#[tokio::test]
async fn test_branch_action_is_selected_by_the_child_exit_status() {
    let script_fail = "echo written > f.txt; exit 3";
    let script_ok = "echo written > f.txt";

    let (code, landed) = run_and_report_landing(
        "disp-fail-abort", script_fail, BranchAction::Commit, BranchAction::Abort,
    ).await;
    assert_eq!(code, Some(3), "the failing script must actually have failed");
    assert!(
        !landed,
        "a non-zero exit must apply on_error (Abort), so the write must not reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-fail-commit", script_fail, BranchAction::Abort, BranchAction::Commit,
    ).await;
    assert_eq!(code, Some(3), "the failing script must actually have failed");
    assert!(
        landed,
        "a non-zero exit must apply on_error (Commit), so the write must reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-ok-commit", script_ok, BranchAction::Commit, BranchAction::Abort,
    ).await;
    assert_eq!(code, Some(0), "the succeeding script must actually have succeeded");
    assert!(
        landed,
        "exit code 0 must apply on_exit (Commit), so the write must reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-ok-abort", script_ok, BranchAction::Abort, BranchAction::Commit,
    ).await;
    assert_eq!(code, Some(0), "the succeeding script must actually have succeeded");
    assert!(
        !landed,
        "exit code 0 must apply on_exit (Abort), so the write must not reach the workdir",
    );
}

/// A run kept with `BranchAction::Keep` leaves a marker that records the
/// deletions alongside the upper, so an out-of-band recovery restores the
/// change set instead of resurrecting the files the run deleted.
///
/// The deletion here is the child's own `rm`, so this covers the marker written
/// from the real supervisor path: the COW layer holds that deletion in RAM only
/// and nothing in the upper represents it, which is why copying the upper back
/// over the workdir is not by itself a recovery.
#[tokio::test]
async fn test_kept_branch_marker_records_the_runs_deletion_not_only_its_upper() {
    let workdir = temp_dir("keep-marker-wd");
    let storage = temp_dir("keep-marker-st");
    for d in [&workdir, &storage] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }
    fs::write(workdir.join("victim.txt"), "ORIGINAL").unwrap();

    {
        let mut sb = Sandbox::builder()
            .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
            .fs_read("/proc")
            .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
            .fs_storage(&storage)
            .on_exit(BranchAction::Keep)
            .build()
            .unwrap();
        let result = sb.run(&["sh", "-c", "rm victim.txt && echo NEW > added.txt"]).await.unwrap();
        assert!(
            result.success(),
            "the child must have deleted and written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
    }

    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(preserved.len(), 1, "the kept branch must be findable by a sweep");
    let branch = &preserved[0];
    assert_eq!(branch.reason, sandlock_core::PreserveReason::Kept);
    assert_eq!(
        branch.workdir,
        workdir.canonicalize().unwrap(),
        "the marker must name the workdir the change set belongs to",
    );
    assert_eq!(
        branch.deleted,
        vec![PathBuf::from("victim.txt")],
        "the marker must record the file the run deleted",
    );
    assert_eq!(
        fs::read_to_string(branch.upper.join("added.txt")).unwrap(),
        "NEW\n",
        "the upper must hold the file the run added",
    );

    // Keep does not merge: the workdir still holds the pre-run state, so the
    // marker's deletion is the only record that the file was removed.
    assert_eq!(fs::read_to_string(workdir.join("victim.txt")).unwrap(), "ORIGINAL");
    assert!(!workdir.join("added.txt").exists(), "Keep must not merge the upper");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

// ============================================================
// Merge failure, storage layout, and the syscall error contract
// ============================================================

/// Build a COW sandbox over `workdir` that reads enough of the host to run a
/// shell or python, and writes only inside the workdir.
fn cow_sandbox(workdir: &std::path::Path, on_exit: BranchAction) -> SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(workdir).workdir(workdir).cwd(workdir)
        .on_exit(on_exit)
}

/// A merge that STARTS and then fails leaves the change set on disk under a
/// `MergeInterrupted` marker — the record that the workdir may have been touched
/// and must be reconciled, not merely re-committed. `Defer` is what lets the
/// obstruction be planted between the run and its commit, and it is also the
/// one path where the caller is told: `Sandbox::commit` returns the error.
///
/// The failure is planted so it lands INSIDE the merge, not at the lock: the
/// workdir stays intact (so the commit flock opens) but a symlink sits where the
/// staged file must be written, so the copy fails after the branch has already
/// entered `MergeInterrupted`. (A workdir that vanished before the lock is the
/// untouched `CommitDeferred` case, covered separately in `test_transaction`.)
#[tokio::test]
async fn test_failed_merge_on_the_drop_path_leaves_the_upper_recoverable() {
    let workdir = temp_dir("merge-fail-wd");
    let storage = temp_dir("merge-fail-st");
    for d in [&workdir, &storage] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }

    {
        let mut sb = cow_sandbox(&workdir, BranchAction::Defer)
            .fs_storage(&storage)
            .build()
            .unwrap();
        let result = sb.run(&["sh", "-c", "echo NEW > added.txt"]).await.unwrap();
        assert!(
            result.success(),
            "the child must have written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
        // Obstruct the MERGE, not the lock: the workdir stays, so the commit
        // flock opens, but a symlink where the staged file must land makes the
        // copy fail — the merge has already marked the branch `MergeInterrupted`
        // by then. The child wrote `added.txt` into the upper (COW), so the base
        // path is free to plant here without the child having followed it.
        std::os::unix::fs::symlink("/dev/null", workdir.join("added.txt")).unwrap();
        assert!(sb.commit().is_err(), "the obstructed merge must report its failure");
        assert!(!sb.pending(), "a failed commit disposes the branch by preserving it");
    }

    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(
        preserved.len(), 1,
        "a merge that could not run must leave exactly one branch for a sweep, got {:?}",
        preserved,
    );
    let branch = &preserved[0];
    assert_eq!(
        branch.reason,
        sandlock_core::PreserveReason::MergeInterrupted,
        "the reason must say the workdir may have been touched, not that the caller kept the branch",
    );
    assert_eq!(
        fs::read_to_string(branch.upper.join("added.txt")).unwrap(),
        "NEW\n",
        "the unpublished change must still be readable from the preserved upper",
    );

    let _ = fs::remove_dir_all(&storage);
    let _ = fs::remove_dir_all(&workdir);
}

/// With no `fs_storage`, branch storage goes to a STABLE, per-user base (not
/// per-process), so one `list_preserved` sweep of that base spans multiple pids'
/// preserved work — the property a recovery sweep across process lifetimes needs.
///
/// The base name carries the uid, never the pid; `$XDG_RUNTIME_DIR/sandlock-cow`
/// when unprivileged, else a secure `$TMPDIR/sandlock-cow-<uid>`.
#[tokio::test]
async fn test_default_storage_base_is_per_user_and_spans_pids() {
    let workdir = temp_dir("default-base-wd");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);

    {
        let mut sb = cow_sandbox(&workdir, BranchAction::Keep).build().unwrap();
        let result = sb
            .run(&["sh", "-c", "echo x > default-base-marker.txt"])
            .await
            .unwrap();
        assert!(
            result.success(),
            "the child must have written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
    }

    // Resolve the base the run actually used by finding our marker under either
    // candidate default base (XDG when unprivileged, else per-uid $TMPDIR).
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if euid != 0 {
        if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
            if !x.is_empty() {
                candidates.push(PathBuf::from(x).join("sandlock-cow"));
            }
        }
    }
    candidates.push(std::env::temp_dir().join(format!("sandlock-cow-{uid}")));

    let (base, ours) = candidates
        .iter()
        .find_map(|b| {
            let hit: Vec<_> = sandlock_core::list_preserved(b)
                .into_iter()
                .filter(|p| p.upper.join("default-base-marker.txt").exists())
                .collect();
            if hit.is_empty() { None } else { Some((b.clone(), hit)) }
        })
        .expect("the kept branch must be under a stable per-user default base");
    assert_eq!(ours.len(), 1, "exactly one kept branch under the default base");

    // The base name carries the uid, never the pid.
    assert!(
        !base.to_string_lossy().contains(&format!("sandlock-cow-{}", std::process::id())),
        "the default base must not embed the pid: {}",
        base.display(),
    );

    // Hand-write a second preserved branch under the SAME base carrying a
    // DIFFERENT pid, as a dead sibling process would leave behind. One sweep must
    // find both — the per-user base crosses pids.
    let sibling = base.join("sibling-branch-for-test");
    let _ = fs::remove_dir_all(&sibling);
    fs::create_dir_all(sibling.join("upper")).unwrap();
    let other_pid = std::process::id().wrapping_add(1);
    fs::write(
        sibling.join("PRESERVED"),
        format!(
            "reason=commit-deferred\nworkdir=/some/wd\nupper={}\npid={other_pid}\n",
            sibling.join("upper").display()
        ),
    )
    .unwrap();

    let swept: Vec<u32> = sandlock_core::list_preserved(&base).into_iter().map(|p| p.pid).collect();
    assert!(
        swept.contains(&std::process::id()),
        "our own pid's kept branch must be swept from the per-user base",
    );
    assert!(
        swept.contains(&other_pid),
        "a sibling pid's branch must be swept from the SAME base — the base spans pids",
    );

    let _ = fs::remove_dir_all(&ours[0].branch_dir);
    let _ = fs::remove_dir_all(&sibling);
    let _ = fs::remove_dir_all(&workdir);
}

/// `O_CREAT|O_EXCL` reports EEXIST for a file that exists only in the workdir
/// as well as for one this run created in the upper, and still creates a file
/// whose name neither layer holds.
///
/// The existence check has to span both layers: against the upper alone a
/// lock-file idiom would silently clobber a pre-existing workdir file, and
/// against the workdir alone it would clobber one the same run had just made.
#[tokio::test]
async fn test_o_excl_sees_both_the_workdir_and_the_upper() {
    let workdir = temp_dir("excl-layers");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);
    fs::write(workdir.join("lower.txt"), "LOWER").unwrap();

    let script = concat!(
        "import os, errno\n",
        "def e(*a):\n",
        "    try:\n",
        "        os.close(os.open(*a)); return 'CREATED'\n",
        "    except OSError as ex: return errno.errorcode.get(ex.errno, str(ex.errno))\n",
        "flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY\n",
        "open('upper.txt', 'w').write('UPPER')\n",
        "print('lower', e('lower.txt', flags))\n",
        "print('upper', e('upper.txt', flags))\n",
        "print('fresh', e('fresh.txt', flags))\n",
    );

    let mut sb = cow_sandbox(&workdir, BranchAction::Abort).build().unwrap();
    let result = sb.run(&["python3", "-c", script]).await.unwrap();
    assert!(
        result.success(),
        "the probe must have run, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or(""),
    );
    let out = result.stdout_str().unwrap_or("").to_string();
    assert!(out.contains("lower EEXIST"), "O_EXCL must see the workdir file, stdout={:?}", out);
    assert!(out.contains("upper EEXIST"), "O_EXCL must see the file this run created, stdout={:?}", out);
    assert!(
        out.contains("fresh CREATED"),
        "O_EXCL must still create a name neither layer holds, stdout={:?}", out,
    );

    // Abort: the pre-existing file must be untouched by the probe.
    drop(sb);
    assert_eq!(fs::read_to_string(workdir.join("lower.txt")).unwrap(), "LOWER");

    let _ = fs::remove_dir_all(&workdir);
}

/// `unlink` on a directory reaches the child as EISDIR and `rmdir` on a regular
/// file as ENOTDIR, whether the path exists only in the workdir or was created
/// by this run in the upper.
///
/// The COW layer answers both from the merged view rather than letting the
/// kernel decide, so each layer is a separate arm of the type check and each
/// needs its own case.
#[tokio::test]
async fn test_unlink_type_mismatches_reach_the_child_as_eisdir_and_enotdir() {
    let workdir = temp_dir("unlink-errno");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);
    fs::create_dir_all(workdir.join("lower_dir")).unwrap();
    fs::write(workdir.join("lower_file.txt"), "x").unwrap();

    let script = concat!(
        "import os, errno\n",
        "def e(fn, *a):\n",
        "    try:\n",
        "        fn(*a); return 'OK'\n",
        "    except OSError as ex: return errno.errorcode.get(ex.errno, str(ex.errno))\n",
        "os.mkdir('upper_dir')\n",
        "open('upper_file.txt', 'w').write('x')\n",
        "print('unlink_lower_dir', e(os.unlink, 'lower_dir'))\n",
        "print('rmdir_lower_file', e(os.rmdir, 'lower_file.txt'))\n",
        "print('unlink_upper_dir', e(os.unlink, 'upper_dir'))\n",
        "print('rmdir_upper_file', e(os.rmdir, 'upper_file.txt'))\n",
    );

    let mut sb = cow_sandbox(&workdir, BranchAction::Abort).build().unwrap();
    let result = sb.run(&["python3", "-c", script]).await.unwrap();
    assert!(
        result.success(),
        "the probe must have run, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or(""),
    );
    let out = result.stdout_str().unwrap_or("").to_string();
    for expected in [
        "unlink_lower_dir EISDIR",
        "rmdir_lower_file ENOTDIR",
        "unlink_upper_dir EISDIR",
        "rmdir_upper_file ENOTDIR",
    ] {
        assert!(out.contains(expected), "expected {:?} in stdout={:?}", expected, out);
    }

    // Abort: nothing the probe touched may reach the workdir.
    drop(sb);
    assert!(workdir.join("lower_dir").is_dir(), "a refused unlink must not have deleted the directory");
    assert!(!workdir.join("upper_dir").exists(), "an aborted run must not publish its directory");

    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// Deletion-model regressions (issues #159/#160/#161)
// ============================================================

/// A directory the child removed stays removed after commit, including its
/// contents (issue #159: whiteouts cover the subtree).
#[tokio::test]
async fn test_cow_child_rm_r_directory_stays_deleted() {
    let workdir = temp_dir("seccomp-rm-r");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/secret.txt"), "SECRET").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("rm -r {}/d", workdir.display());
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "rm -r should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(!workdir.join("d").exists(), "d should be gone after commit");
            assert!(!workdir.join("d/secret.txt").exists());
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Renaming a directory preserves its contents through the commit
/// (issue #160: the rename is staged with a recursive copy-up).
#[tokio::test]
async fn test_cow_child_mv_directory_preserves_contents() {
    let workdir = temp_dir("seccomp-mv-dir");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/inner.txt"), "PRECIOUS").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("mv {}/d {}/d2", workdir.display(), workdir.display());
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "mv should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(!workdir.join("d").exists(), "d should be gone after commit");
            assert_eq!(
                fs::read_to_string(workdir.join("d2/inner.txt")).unwrap(),
                "PRECIOUS",
                "d2/inner.txt must survive the rename"
            );
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// rmdir on a non-empty directory fails inside the sandbox and the contents
/// survive the commit (issue #161: ENOTEMPTY from the merged view).
#[tokio::test]
async fn test_cow_child_rmdir_nonempty_fails() {
    let workdir = temp_dir("seccomp-rmdir-nonempty");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/inner.txt"), "DATA").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("rmdir {}/d", workdir.display());
    let result = policy.clone().run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(!r.success(), "rmdir of a non-empty directory must fail");
            assert!(
                workdir.join("d/inner.txt").exists(),
                "contents must survive the failed rmdir and the commit"
            );
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// A hard link cannot be half staged. With one name inside the workdir and the
/// other below it there is nothing for the branch to copy up, and letting the
/// child's own linkat run instead puts the name in the pristine workdir (or
/// hands out an alias for the lower inode that outlives the abort). Both
/// directions have to be refused, and the proof is the link count: neither
/// original may gain a second name.
#[tokio::test]
async fn test_seccomp_cow_hardlink_cannot_cross_the_workdir_boundary() {
    use std::os::unix::fs::MetadataExt;

    let workdir = temp_dir("seccomp-link-inside");
    let outside = temp_dir("seccomp-link-outside");
    for d in [&workdir, &outside] {
        let _ = fs::remove_dir_all(d);
        fs::create_dir_all(d).unwrap();
    }
    fs::write(workdir.join("inside.txt"), "INSIDE").unwrap();
    fs::write(outside.join("outside.txt"), "OUTSIDE").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .fs_write(&outside)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let pull_in = format!(
        "ln {}/outside.txt {}/pulled-in.txt",
        outside.display(),
        workdir.display()
    );
    let result = policy.clone().run(&["sh", "-c", &pull_in]).await;
    let pulled = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Seccomp COW test skipped: {}", e);
            let _ = fs::remove_dir_all(&workdir);
            let _ = fs::remove_dir_all(&outside);
            return;
        }
    };
    assert!(
        !pulled.success(),
        "a hard link into the workdir should be refused, exit={:?} stderr={}",
        pulled.code(),
        pulled.stderr_str().unwrap_or("")
    );

    let push_out = format!(
        "ln {}/inside.txt {}/pushed-out.txt",
        workdir.display(),
        outside.display()
    );
    let pushed = policy
        .clone()
        .run(&["sh", "-c", &push_out])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !pushed.success(),
        "a hard link out of the workdir should be refused, exit={:?} stderr={}",
        pushed.code(),
        pushed.stderr_str().unwrap_or("")
    );

    assert_eq!(
        fs::metadata(outside.join("outside.txt")).unwrap().nlink(),
        1,
        "the file outside the workdir gained a second name inside it"
    );
    assert_eq!(
        fs::metadata(workdir.join("inside.txt")).unwrap().nlink(),
        1,
        "the file the branch was staging over gained a second name outside it"
    );
    assert!(
        !workdir.join("pulled-in.txt").exists(),
        "the aborted branch left a name in the workdir"
    );
    assert!(
        !outside.join("pushed-out.txt").exists(),
        "the aborted branch left a name outside the workdir"
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&outside);
}

// ============================================================
// fchmodat2
// ============================================================

/// glibc issues fchmodat2(2) whenever fchmodat is called with flags, which is
/// what `mkfifo -m`, `chmod -h`, and python's `follow_symlinks=False` do.
/// Left to the kernel it resolves against the real workdir: a branch-created
/// entry got ENOENT and a lower file was changed for real.
#[tokio::test]
async fn test_seccomp_cow_fchmodat2_is_virtualized() {
    use std::os::unix::fs::PermissionsExt;
    let workdir = temp_dir("seccomp-fchmodat2");
    let lower = workdir.join("lower.txt");
    fs::write(&lower, "x").unwrap();
    fs::set_permissions(&lower, fs::Permissions::from_mode(0o644)).unwrap();
    let _ = fs::remove_file(workdir.join("link"));
    std::os::unix::fs::symlink("lower.txt", workdir.join("link")).unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let script = concat!(
        "import ctypes, os\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "def chmod2(path, mode, flags):\n",
        "    r = libc.syscall(452, -100, path.encode(), mode, flags)\n",
        "    return r if r == 0 else -ctypes.get_errno()\n",
        "mode = lambda p: oct(os.stat(p).st_mode & 0o777)\n",
        "os.mkfifo('made')\n",
        "print('made', chmod2('made', 0o640, 0x100), mode('made'))\n",
        "print('lower', chmod2('lower.txt', 0o600, 0), mode('lower.txt'))\n",
        "print('link', chmod2('link', 0o400, 0x100), mode('lower.txt'))\n",
    );
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = result.stdout_str().unwrap_or("");
    assert!(result.success(), "exit={:?} stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    assert!(stdout.contains("made 0 0o640"), "branch-created FIFO: {stdout}");
    assert!(stdout.contains("lower 0 0o600"), "lower file in the merged view: {stdout}");
    // The kernel's own answer for AT_SYMLINK_NOFOLLOW on a symlink, and the
    // target must be left alone.
    assert!(stdout.contains("link -95 0o600"), "symlink with AT_SYMLINK_NOFOLLOW: {stdout}");

    let real = fs::metadata(&lower).unwrap().permissions().mode() & 0o777;
    assert_eq!(real, 0o644, "the abort must leave the real file untouched");
    assert!(!workdir.join("made").exists());
    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// cow_honor_read_grants: a COW copy-up or merged listing never shows the
// child a workdir entry its read grants do not cover.
// ============================================================

/// One file under `private/` per probe, so no probe sees another's effect.
const READ_GATE_FILES: [&str; 6] = ["secret", "trunc", "chmod", "chown", "utime", "link"];

/// A workdir with a granted `pub/` and a `private/` no grant covers, plus
/// lower symlinks under `pub/` that lead to `private/` (absolute, and relative
/// within the workdir) and out of the workdir (absolute, and relative).
/// Returns the workdir and the directory outside it.
fn read_gate_workdir(name: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for dir in [temp_dir(name), temp_dir(&format!("{name}-outside"))] {
        let _ = fs::remove_dir_all(&dir);
    }
    let workdir = temp_dir(name).canonicalize().unwrap();
    let outside = temp_dir(&format!("{name}-outside")).canonicalize().unwrap();
    for d in ["pub/d", "private/sub"] {
        fs::create_dir_all(workdir.join(d)).unwrap();
    }
    fs::write(workdir.join("pub/readme.txt"), "public").unwrap();
    fs::write(workdir.join("pub/d/inner.txt"), "inner").unwrap();
    for f in READ_GATE_FILES {
        let p = workdir.join(format!("private/{f}.txt"));
        fs::write(&p, "TOP SECRET").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(workdir.join("private/hidden-name-in-private.txt"), "").unwrap();
    fs::write(workdir.join("private/sub/deep.txt"), "NESTED SECRET").unwrap();
    fs::write(outside.join("hidden-name-outside.txt"), "").unwrap();
    symlink(workdir.join("private"), workdir.join("pub/lnk")).unwrap();
    symlink(&outside, workdir.join("pub/lnk_out")).unwrap();
    let outside_name = outside.file_name().unwrap().to_str().unwrap();
    symlink(format!("../../{outside_name}"), workdir.join("pub/rel_out")).unwrap();
    symlink("../private", workdir.join("pub/rel_in")).unwrap();
    (workdir, outside)
}

/// Run every way a child has to make the COW layer read `private/` (or a
/// directory a symlink under `pub/` leads to) for it, and print one
/// `name=ok:<value>` or `name=err:<errno>` line per probe. A metadata change
/// and the read after it are separate probes, so a change that reached the
/// real file shows as `ok` even though Landlock then refuses the read.
async fn run_read_gate_probes(workdir: &std::path::Path) -> String {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(workdir.join("pub"))
        .workdir(workdir)
        .cow_honor_read_grants(true)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();
    let script = format!(concat!(
        "import ctypes, os, platform, struct\n",
        "W = '{wd}'\n",
        "P = W + '/private/'\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "GETDENTS64 = 61 if platform.machine() in ('aarch64', 'riscv64') else 217\n",
        "def probe(name, f):\n",
        "    try:\n",
        "        print(f'{{name}}=ok:{{f()!r}}')\n",
        "    except OSError as e:\n",
        "        print(f'{{name}}=err:{{e.errno}}')\n",
        "def raw_getdents(fd):\n",
        "    buf = ctypes.create_string_buffer(8192)\n",
        "    n = libc.syscall(GETDENTS64, fd, buf, len(buf))\n",
        "    if n < 0:\n",
        "        e = ctypes.get_errno()\n",
        "        raise OSError(e, os.strerror(e))\n",
        "    names, off = [], 0\n",
        "    while off < n:\n",
        "        reclen = struct.unpack_from('H', buf.raw, off + 16)[0]\n",
        "        name = buf.raw[off + 19:off + reclen].split(b'\\0', 1)[0].decode()\n",
        "        if name not in ('.', '..'):\n",
        "            names.append(name)\n",
        "        off += reclen\n",
        "    return sorted(names)\n",
        "def list_by_opath(p):\n",
        "    fd = os.open(p, os.O_PATH | os.O_NOFOLLOW)\n",
        "    try:\n",
        "        return raw_getdents(fd)\n",
        "    finally:\n",
        "        os.close(fd)\n",
        "def list_by_plain_fd(p):\n",
        "    fd = os.open(p, os.O_RDONLY)\n",
        "    try:\n",
        "        return sorted(os.listdir(fd))\n",
        "    finally:\n",
        "        os.close(fd)\n",
        "def create(p):\n",
        "    with open(p, 'w') as f:\n",
        "        f.write('new')\n",
        "    return open(p).read()\n",
        "def append_then_read(p):\n",
        "    with open(p, 'a') as f:\n",
        "        f.write('+')\n",
        "    return open(p).read()\n",
        "probe('rdonly', lambda: open(P + 'secret.txt').read())\n",
        "probe('rdwr', lambda: open(P + 'secret.txt', 'r+').read())\n",
        "probe('trunc', lambda: open(P + 'trunc.txt', 'w').close())\n",
        "probe('chmod', lambda: os.chmod(P + 'chmod.txt', 0o644))\n",
        "probe('chmod_read', lambda: open(P + 'chmod.txt').read())\n",
        "probe('chown', lambda: os.chown(P + 'chown.txt', -1, os.getgid()))\n",
        "probe('chown_read', lambda: open(P + 'chown.txt').read())\n",
        "probe('utime', lambda: os.utime(P + 'utime.txt', (0, 0)))\n",
        "probe('utime_read', lambda: open(P + 'utime.txt').read())\n",
        "probe('link', lambda: os.link(P + 'link.txt', W + '/pub/alias'))\n",
        "probe('link_read', lambda: open(W + '/pub/alias').read())\n",
        "probe('rename_dir', lambda: os.rename(P + 'sub', W + '/moved'))\n",
        "probe('rename_read', lambda: (sorted(os.listdir(W + '/moved')), open(W + '/moved/deep.txt').read()))\n",
        "probe('create', lambda: create(P + 'new.txt'))\n",
        "probe('getdents_open', lambda: os.close(os.open(P, os.O_RDONLY)))\n",
        "probe('getdents', lambda: list_by_plain_fd(P))\n",
        "probe('lnk_opath', lambda: list_by_opath(W + '/pub/lnk'))\n",
        "probe('lnk_out_opath', lambda: list_by_opath(W + '/pub/lnk_out'))\n",
        "probe('rel_out_opath', lambda: list_by_opath(W + '/pub/rel_out'))\n",
        "probe('rel_in_opath', lambda: list_by_opath(W + '/pub/rel_in'))\n",
        "probe('lnk_create', lambda: create(W + '/pub/lnk/made.txt'))\n",
        "probe('lnk_listing', lambda: list_by_plain_fd(W + '/pub/lnk'))\n",
        "probe('pub_append', lambda: append_then_read(W + '/pub/readme.txt'))\n",
        "probe('pub_rename_dir', lambda: sorted(os.rename(W + '/pub/d', W + '/pub/d2') or os.listdir(W + '/pub/d2')))\n",
    ), wd = workdir.display());
    let result = policy.clone().run(&["python3", "-I", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?} stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    result.stdout_str().unwrap_or("").to_string()
}

/// Every path by which the COW layer would read `private/` on the child's
/// behalf, or list a directory a lower symlink leads to, answers as Landlock
/// answers a plain read: EACCES, or no lower names. A refusal never falls
/// through to the kernel: the real files keep their content, mode, owner and
/// times. Without the gate, `rdwr`, `chmod`, `chown`, `utime` and `link`
/// expose the secret, `rename_dir` the subtree, and the listings the names
/// under `private/` and outside the workdir.
#[tokio::test]
async fn test_cow_honor_read_grants_refuses_every_copy_up_path() {
    use std::os::unix::fs::MetadataExt;
    let (workdir, outside) = read_gate_workdir("read-gate");
    let before: Vec<(PathBuf, fs::Metadata)> = READ_GATE_FILES
        .iter()
        .map(|f| workdir.join(format!("private/{f}.txt")))
        .map(|p| (p.clone(), fs::metadata(&p).unwrap()))
        .collect();
    let out = run_read_gate_probes(&workdir).await;
    let line = |name: &str| -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} line in: {out}"))
            .to_string()
    };
    // Refused by the gate (the metadata changes Landlock does not mediate).
    for name in ["rdwr", "trunc", "chmod", "chown", "utime", "link", "rename_dir", "getdents", "rel_in_opath"] {
        assert_eq!(line(name), "err:13", "{name} must answer EACCES: {out}");
    }
    // Refused by Landlock, or absent because the operation before it was refused.
    for name in ["rdonly", "chmod_read", "chown_read", "utime_read"] {
        assert_eq!(line(name), "err:13", "{name}: {out}");
    }
    assert_eq!(line("link_read"), "err:2", "{out}");
    assert_eq!(line("rename_read"), "err:2", "{out}");
    // The plain-fd listing reaches the merged getdents (the open itself succeeds).
    assert_eq!(line("getdents_open"), "ok:None", "{out}");
    // A lower symlink cannot make the listing read another directory: a
    // listing of the symlink itself shows no lower names, and one of the upper
    // directory a create made there shows only what the child created.
    for name in ["lnk_opath", "lnk_out_opath", "rel_out_opath"] {
        assert_eq!(line(name), "ok:[]", "{name}: {out}");
    }
    assert_eq!(line("lnk_create"), "ok:'new'", "{out}");
    assert_eq!(line("lnk_listing"), "ok:['made.txt']", "{out}");
    assert!(!out.contains("SECRET"), "no secret byte reaches the child: {out}");
    assert!(!out.contains("hidden-name"), "no lower name reaches the child: {out}");
    // What the grants do cover keeps working, and a new file reveals nothing.
    assert_eq!(line("create"), "ok:'new'");
    assert_eq!(line("pub_append"), "ok:'public+'");
    assert_eq!(line("pub_rename_dir"), "ok:['inner.txt']");

    // A refusal never fell through to the kernel: the run's branch is aborted,
    // so any change left on the real files would have bypassed it.
    for (p, m) in &before {
        let now = fs::metadata(p).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "TOP SECRET", "{}", p.display());
        assert_eq!(now.mode(), m.mode(), "mode of {}", p.display());
        assert_eq!((now.uid(), now.gid()), (m.uid(), m.gid()), "owner of {}", p.display());
        assert_eq!(now.mtime_nsec() + now.mtime() * 1_000_000_000, m.mtime_nsec() + m.mtime() * 1_000_000_000, "mtime of {}", p.display());
        assert_eq!(now.ctime_nsec() + now.ctime() * 1_000_000_000, m.ctime_nsec() + m.ctime() * 1_000_000_000, "ctime of {}", p.display());
    }
    assert!(!workdir.join("pub/alias").exists());
    assert!(workdir.join("private/sub/deep.txt").exists());
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&outside);
}

/// The option belongs to the configurations whose grants mean what the gate
/// checks: with chroot, or with a relative grant (Landlock resolves it against
/// the child's working directory), it is refused rather than silently weak.
#[test]
fn test_cow_honor_read_grants_is_refused_where_it_cannot_hold() {
    let workdir = temp_dir("read-gate-unsupported");
    let err = Sandbox::builder()
        .chroot("/")
        .workdir(&workdir)
        .cow_honor_read_grants(true)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("not supported together with chroot"), "{err}");
    let err = Sandbox::builder()
        .fs_read("relative/dir")
        .workdir(&workdir)
        .cow_honor_read_grants(true)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("absolute"), "{err}");
    let _ = fs::remove_dir_all(&workdir);
}
