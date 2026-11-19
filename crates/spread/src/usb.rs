//! Removable media discovery.
//!
//! Linux uses mount tables and the sysfs removable flag; Windows asks WMI for
//! `DriveType=2`; macOS lists `/Volumes`. Explicit `--mount-root` entries are
//! trusted so tests and unusual mounts work.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Returns candidate removable mount points.
pub fn mounts(explicit: &[PathBuf]) -> Vec<PathBuf> {
    if !explicit.is_empty() {
        let mut found = Vec::new();
        for root in explicit {
            let kids = children(root, false);
            if kids.is_empty() {
                if root.is_dir() {
                    found.push(root.clone());
                }
            } else {
                found.extend(kids);
            }
        }
        found.sort();
        return found;
    }
    #[cfg(target_os = "linux")]
    {
        let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let roots = [
            PathBuf::from("/media").join(&user),
            PathBuf::from("/run/media").join(&user),
            PathBuf::from("/media"),
            PathBuf::from("/mnt"),
        ];
        let table = fs::read_to_string("/proc/mounts").unwrap_or_default();
        let mut found = Vec::new();
        for root in roots {
            for child in children(&root, false) {
                if !is_mountpoint(&table, &child) {
                    continue;
                }
                if let Some(device) = device_for(&table, &child) {
                    if !removable(device) {
                        continue;
                    }
                }
                found.push(child);
            }
        }
        found.sort();
        found
    }
    #[cfg(target_os = "macos")]
    {
        children(Path::new("/Volumes"), true)
    }
    #[cfg(windows)]
    {
        let mut found = Vec::new();
        let script = "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=2\" | ForEach-Object { $_.DeviceID }";
        if let Some(text) = crate::lan::run("powershell", &["-NoProfile", "-Command", script]) {
            for line in text.lines() {
                let drive = line.trim();
                if drive.len() >= 2 {
                    let path = PathBuf::from(format!("{drive}/"));
                    if path.is_dir() {
                        found.push(path);
                    }
                }
            }
        }
        found
    }
}

fn children(root: &Path, skip_shadow: bool) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            !skip_shadow || fs::canonicalize(path).map_or(true, |real| real != Path::new("/"))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn is_mountpoint(table: &str, path: &Path) -> bool {
    let needle = format!(" {} ", path.display());
    table.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        fields
            .next()
            .is_some_and(|mount| format!(" {mount} ") == needle)
    })
}

#[cfg(target_os = "linux")]
fn device_for<'a>(table: &'a str, path: &Path) -> Option<&'a str> {
    let needle = path.display().to_string();
    table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let device = fields.next()?;
        (fields.next()? == needle).then_some(device)
    })
}

#[cfg(target_os = "linux")]
fn removable(device: &str) -> bool {
    let name = device.rsplit('/').next().unwrap_or_default();
    let trimmed: String = name
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if trimmed.is_empty() {
        return false;
    }
    fs::read_to_string(format!("/sys/block/{trimmed}/removable"))
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}
