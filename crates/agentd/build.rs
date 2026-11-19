//! Embeds an optional payload config and coordinator key into the binary.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=AF_EMBED_DIR");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let mut code = String::new();
    match env::var("AF_EMBED_DIR") {
        Ok(dir) => {
            let dir = PathBuf::from(dir);
            let config = fs::read_to_string(dir.join("config.toml")).expect("embedded config");
            let coord = fs::read(dir.join("coordinator.pub")).expect("embedded coordinator.pub");
            code.push_str(&format!("pub const CONFIG: &str = {config:?};\n"));
            code.push_str(&format!("pub const COORD: &[u8] = &{coord:?};\n"));
        }
        Err(_) => {
            code.push_str("pub const CONFIG: &str = \"\";\n");
            code.push_str("pub const COORD: &[u8] = &[];\n");
        }
    }
    fs::write(out.join("embedded.rs"), code).expect("write embedded.rs");
}
