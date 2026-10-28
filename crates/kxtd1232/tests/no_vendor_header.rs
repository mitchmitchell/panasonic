//! Clean-room guard (design v2.4 §15, decision 74). The DBH header block 0x1E-0xFF is
//! copied vendor content. It must never be embedded in code or fixtures: a DBH writer reads
//! it at runtime from the unit's pre-write backup and refuses to write without one.
//!
//! The real bytes can't appear here either, so this test fails on any embedded opaque
//! block: binary files, DBH images, a run of 64 or more byte literals with varying values,
//! or a hex string of 128 or more digits. A synthetic placeholder should be a short pattern
//! or a generated value, not a pasted block.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use std::path::{Path, PathBuf};

const MAX_BYTE_RUN: usize = 64;
const MAX_HEX_DIGITS: usize = 128;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// UI and README artwork are not vendor DBH header blocks (design v2.4 §15).
fn is_allowed_binary(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if !lower.ends_with(".png") {
        return false;
    }
    lower.contains("/.github/assets/") || lower.contains("/crates/kxprov-web/assets/")
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == ".git" || name == "target" {
            continue;
        }
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn is_byte_token(t: &str) -> bool {
    let t = t.strip_suffix("u8").unwrap_or(t);
    let h = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    h.len() == 2 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Problems found in one text: long runs of byte literals or long hex strings.
fn scan(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut run: Vec<String> = Vec::new();
    let flush = |run: &mut Vec<String>, found: &mut Vec<String>| {
        let mut distinct = run.clone();
        distinct.sort();
        distinct.dedup();
        if run.len() >= MAX_BYTE_RUN && distinct.len() > 1 {
            found.push(format!("{} byte literals starting {:?}", run.len(), run[0]));
        }
        run.clear();
    };
    for tok in text.split(|c: char| c.is_whitespace() || ",[]();{}\"'".contains(c)) {
        if tok.is_empty() {
            continue;
        }
        if is_byte_token(tok) {
            run.push(tok.to_ascii_lowercase());
        } else {
            flush(&mut run, &mut found);
        }
        let digits = tok.bytes().filter(u8::is_ascii_hexdigit).count();
        if digits >= MAX_HEX_DIGITS && digits * 10 >= tok.len() * 9 {
            found.push(format!("hex string of {digits} digits"));
        }
    }
    flush(&mut run, &mut found);
    found
}

#[test]
fn test_repo_embeds_no_opaque_header_block() {
    let mut all = Vec::new();
    files(&repo_root(), &mut all);
    assert!(all.len() > 10, "walked the repo");
    let mut bad = Vec::new();
    for p in &all {
        let name = p.to_string_lossy().to_ascii_lowercase();
        if name.ends_with(".dbh") {
            bad.push(format!("{}: DBH image", p.display()));
            continue;
        }
        match std::fs::read_to_string(p) {
            Err(_) if is_allowed_binary(p) => {}
            Err(_) => bad.push(format!("{}: binary file", p.display())),
            Ok(text) => bad.extend(
                scan(&text)
                    .into_iter()
                    .map(|s| format!("{}: {s}", p.display())),
            ),
        }
    }
    assert!(bad.is_empty(), "embedded blocks found:\n{}", bad.join("\n"));
}

#[test]
fn test_scanner_catches_blocks_and_allows_short_patterns() {
    let block: Vec<String> = (0..226).map(|i| format!("0x{:02x}", i % 256)).collect();
    assert_eq!(scan(&block.join(", ")).len(), 1);
    let spaced: Vec<String> = (0..80).map(|i| format!("{i:02X}")).collect();
    assert_eq!(scan(&spaced.join(" ")).len(), 1);
    assert_eq!(scan(&"ab".repeat(70)).len(), 1);
    // Fine: frame headers, a fill pattern, a Cargo.lock checksum.
    assert!(scan("08 01 06 00 00 00 00 03 12").is_empty());
    assert!(scan(&vec!["0xEE"; 300].join(", ")).is_empty());
    assert!(scan(&"0123456789abcdef".repeat(4)).is_empty());
}
