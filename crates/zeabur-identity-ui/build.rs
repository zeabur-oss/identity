//! Embeds the sign-in pages' built styles, scripts and font. `ZEABUR_IDENTITY_UI_DIST` points at
//! the directory `scripts/build-ui.sh` fills, whose `manifest.json` lists every asset; this script
//! writes the table `src/assets.rs` includes. A debug build without it embeds no assets; a
//! release build fails.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

use serde::Deserialize;

const VAR: &str = "ZEABUR_IDENTITY_UI_DIST";

#[derive(Deserialize)]
struct Entry {
    file: String,
    #[serde(rename = "type")]
    content_type: String,
    brotli: bool,
}

fn main() {
    println!("cargo::rerun-if-env-changed={VAR}");
    let table = match env::var_os(VAR).filter(|v| !v.is_empty()) {
        Some(dist) => table(&PathBuf::from(dist)),
        None if env::var("PROFILE").as_deref() == Ok("release") => Err(format!(
            "{VAR} is not set. A release build must embed the sign-in pages: run \
             scripts/build-ui.sh and set {VAR} to the absolute path of ui/dist."
        )),
        None => Ok(String::from("static ASSETS: [Asset; 0] = [];\n")),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("assets.rs");
    match table.and_then(|table| fs::write(&out, table).map_err(|e| e.to_string())) {
        Ok(()) => {}
        Err(message) => println!("cargo::error={message}"),
    }
}

/// The `static ASSETS` item for every file the manifest lists.
fn table(dist: &Path) -> Result<String, String> {
    let manifest = dist.join("manifest.json");
    println!("cargo::rerun-if-changed={}", manifest.display());
    let text = fs::read_to_string(&manifest)
        .map_err(|e| format!("{VAR}: cannot read {}: {e}", manifest.display()))?;
    let entries: BTreeMap<String, Entry> = serde_json::from_str(&text)
        .map_err(|e| format!("{VAR}: {} is not a manifest: {e}", manifest.display()))?;
    let count = entries.len();
    let mut table = format!("static ASSETS: [Asset; {count}] = [\n");
    for (name, entry) in entries {
        let path = dist.join(&entry.file);
        if !path.is_file() {
            return Err(format!("{VAR}: {} is missing", path.display()));
        }
        println!("cargo::rerun-if-changed={}", path.display());
        writeln!(
            table,
            "    Asset {{ name: {name:?}, content_type: {:?}, stored: include_bytes!({:?}), \
             brotli: {}, decoded: OnceLock::new() }},",
            entry.content_type,
            path.display().to_string(),
            entry.brotli,
        )
        .map_err(|e| e.to_string())?;
    }
    table.push_str("];\n");
    Ok(table)
}
