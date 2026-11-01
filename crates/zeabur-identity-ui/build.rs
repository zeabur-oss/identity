//! Points `ZEABUR_IDENTITY_UI_DIR` at the sign-in pages' built styles, scripts and font for
//! `src/assets.rs` to embed: `ZEABUR_IDENTITY_UI_DIST`, which `scripts/build-ui.sh` fills. A debug
//! build without it embeds empty placeholders; a release build fails.

use std::path::PathBuf;
use std::{env, fs};

const VAR: &str = "ZEABUR_IDENTITY_UI_DIST";
/// Each file, and whether it is brotli-encoded.
const FILES: [(&str, bool); 5] = [
    ("app.css.br", true),
    ("login.js.br", true),
    ("setup.js.br", true),
    ("account.js.br", true),
    ("Geist-Variable.woff2", false),
];
/// An empty brotli stream.
const EMPTY_BROTLI: &[u8] = &[0x3F];

fn main() {
    println!("cargo::rerun-if-env-changed={VAR}");
    let dir = match env::var_os(VAR).filter(|v| !v.is_empty()) {
        Some(dist) => PathBuf::from(dist),
        None if env::var("PROFILE").as_deref() == Ok("release") => {
            return error(&format!(
                "{VAR} is not set. A release build must embed the sign-in pages: run \
                 scripts/build-ui.sh and set {VAR} to the absolute path of ui/dist."
            ));
        }
        None => match placeholders() {
            Ok(dir) => dir,
            Err(message) => return error(&message),
        },
    };
    for (file, _) in FILES {
        let path = dir.join(file);
        if !path.is_file() {
            return error(&format!("{VAR}: {} is missing", path.display()));
        }
        println!("cargo::rerun-if-changed={}", path.display());
    }
    println!("cargo::rustc-env=ZEABUR_IDENTITY_UI_DIR={}", dir.display());
}

fn placeholders() -> Result<PathBuf, String> {
    let dir = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("placeholder");
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for (file, brotli) in FILES {
        let bytes = if brotli { EMPTY_BROTLI } else { &[] };
        fs::write(dir.join(file), bytes).map_err(|e| format!("cannot write {file}: {e}"))?;
    }
    Ok(dir)
}

fn error(message: &str) {
    println!("cargo::error={message}");
}
