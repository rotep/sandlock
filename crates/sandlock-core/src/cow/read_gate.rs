//! Which lower (workdir) entries a COW branch may disclose to the child.
//!
//! The supervisor copies a lower file into the upper when the child opens it
//! for writing or changes its metadata, and lists lower directories when it
//! merges a directory listing. It does both with its own credentials, outside
//! the child's Landlock ruleset, so without a check here a child could read a
//! workdir file its `fs_readable`/`fs_writable` grants do not cover: open it
//! `O_RDWR`, or `chmod` it and then read the copy. `deny_open_verdict` states
//! the rule for every other on-behalf open: a path outside every grant is
//! refused, never looser than Landlock. [`CowReadGate`] applies the same rule
//! to the COW layer. It is opt-in (`SandboxBuilder::cow_honor_read_grants`):
//! with the gate disabled the branch behaves exactly as before.

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The read grants a COW branch honours when it copies a lower entry up or
/// lists a lower directory for the child.
///
/// It holds one set of roots per sandbox that opted in. A real path passes
/// when it lies under some root of *every* set, so a branch shared by the
/// stages of a transaction is never looser than any stage that asked for the
/// check. With no set at all the gate is disabled and everything passes.
#[derive(Clone, Debug, Default)]
pub struct CowReadGate {
    sets: Vec<Arc<[PathBuf]>>,
}

impl CowReadGate {
    /// No check: the branch copies and lists whatever the workdir holds.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// The roots the child can read through Landlock: `fs_readable` and
    /// `fs_writable` (sandlock's write access includes read). Each is
    /// canonicalized once, here, so a grant spelled through a symlink still
    /// matches the real path of what the supervisor opens; a grant that does
    /// not resolve is kept as given. Resolving once, at sandbox creation, also
    /// means a grant path replaced by a symlink later does not move the gate.
    pub fn from_grants<'a>(grants: impl IntoIterator<Item = &'a PathBuf>) -> Self {
        let roots: Vec<PathBuf> = grants
            .into_iter()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
            .collect();
        Self { sets: vec![roots.into()] }
    }

    /// Both gates at once: a path passes only if it passes `self` and `other`.
    pub fn and(mut self, other: Self) -> Self {
        self.sets.extend(other.sets);
        self
    }

    /// Whether any sandbox opted in.
    pub fn is_enabled(&self) -> bool {
        !self.sets.is_empty()
    }

    /// Whether the child may be shown the entry at the real path `real`.
    pub fn allows(&self, real: &Path) -> bool {
        self.sets
            .iter()
            .all(|roots| roots.iter().any(|root| real.starts_with(root)))
    }

    /// Like [`allows`](Self::allows), for the entry `fd` (a descriptor the
    /// supervisor opened) names: its path as `/proc/self/fd` reports it, which
    /// is the path it was opened by. Judging the descriptor the caller then
    /// reads from leaves no window to swap the entry between check and use.
    /// A descriptor whose path cannot be read fails closed.
    pub fn allows_fd(&self, fd: RawFd) -> bool {
        if !self.is_enabled() {
            return true;
        }
        match std::fs::read_link(format!("/proc/self/fd/{fd}")) {
            Ok(real) => self.allows(&real),
            Err(_) => false,
        }
    }
}

/// Why `cow_honor_read_grants` cannot be honoured for a sandbox, if it cannot.
///
/// - Under `chroot` the grants are paths in the jail, and the chroot
///   dispatcher maps branch errors on its own: it has not been checked
///   against a refusal.
/// - A relative grant is resolved by Landlock against the child's working
///   directory, after it changed there; resolving it here against the
///   supervisor's could make the gate looser than Landlock.
pub(crate) fn check_supported<'a>(
    chroot: bool,
    grants: impl IntoIterator<Item = &'a PathBuf>,
) -> Result<(), String> {
    if chroot {
        return Err("cow_honor_read_grants is not supported together with chroot".into());
    }
    if let Some(p) = grants.into_iter().find(|p| p.is_relative()) {
        return Err(format!(
            "cow_honor_read_grants needs absolute fs_read/fs_write paths, got {}",
            p.display()
        ));
    }
    Ok(())
}

/// The error `execute_copy` returns when the gate refuses the source, kept
/// distinct from an ordinary I/O failure so every caller can answer the child
/// with `EACCES` instead of falling back to `Continue` or an empty copy.
#[derive(Debug)]
pub(crate) struct NotGranted;

impl std::fmt::Display for NotGranted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("lower entry is outside the sandbox's read grants")
    }
}

impl std::error::Error for NotGranted {}

pub(crate) fn not_granted_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, NotGranted)
}

pub(crate) fn is_not_granted(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<NotGranted>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn gate(roots: &[&str]) -> CowReadGate {
        CowReadGate { sets: vec![roots.iter().map(PathBuf::from).collect::<Vec<_>>().into()] }
    }

    #[test]
    fn a_disabled_gate_allows_everything() {
        let g = CowReadGate::disabled();
        assert!(!g.is_enabled());
        assert!(g.allows(Path::new("/anything/at/all")));
        assert!(g.allows_fd(-1));
    }

    #[test]
    fn a_path_must_lie_under_a_root_component_wise() {
        let g = gate(&["/w/pub", "/usr"]);
        assert!(g.allows(Path::new("/w/pub")));
        assert!(g.allows(Path::new("/w/pub/readme.txt")));
        assert!(!g.allows(Path::new("/w/private/secret.txt")));
        // A sibling that only shares the name prefix is not under the root.
        assert!(!g.allows(Path::new("/w/public/x")));
        assert!(!g.allows(Path::new("/w")));
    }

    #[test]
    fn an_enabled_gate_with_no_roots_refuses_everything() {
        let g = gate(&[]);
        assert!(g.is_enabled());
        assert!(!g.allows(Path::new("/w/pub/readme.txt")));
    }

    #[test]
    fn combined_gates_require_every_set() {
        let g = gate(&["/w"]).and(gate(&["/w/pub"]));
        assert!(g.allows(Path::new("/w/pub/a")));
        assert!(!g.allows(Path::new("/w/private/a")));
        assert!(gate(&["/w"]).and(CowReadGate::disabled()).allows(Path::new("/w/x")));
    }

    #[test]
    fn grants_are_canonicalized_once_at_construction() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let g = CowReadGate::from_grants([&link]);
        let canon = std::fs::canonicalize(&real).unwrap();
        assert!(g.allows(&canon.join("f")));
        // Re-pointing the link afterwards does not move the gate.
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(!g.allows(&std::fs::canonicalize(&other).unwrap().join("f")));
        assert!(g.allows(&canon.join("f")));
    }

    #[test]
    fn a_descriptor_is_judged_by_the_path_it_was_opened_by() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(root.join("pub")).unwrap();
        std::fs::create_dir(root.join("private")).unwrap();
        std::fs::write(root.join("private/secret"), b"s").unwrap();
        // A hard link from a granted directory to the same inode: the
        // descriptor carries the name it was opened by, as Landlock judges it.
        std::fs::hard_link(root.join("private/secret"), root.join("pub/alias")).unwrap();
        let g = CowReadGate::from_grants([&root.join("pub")]);
        let via_pub = std::fs::File::open(root.join("pub/alias")).unwrap();
        let via_private = std::fs::File::open(root.join("private/secret")).unwrap();
        assert!(g.allows_fd(via_pub.as_raw_fd()));
        assert!(!g.allows_fd(via_private.as_raw_fd()));
        assert!(!g.allows_fd(-1), "an unreadable descriptor path fails closed");
    }

    #[test]
    fn the_not_granted_error_is_recognisable() {
        assert!(is_not_granted(&not_granted_error()));
        assert!(!is_not_granted(&std::io::Error::from_raw_os_error(libc::EACCES)));
    }
}
