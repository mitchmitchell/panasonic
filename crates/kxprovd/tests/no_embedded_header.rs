//! v2.4: vendor header bytes 0x1E–0xFF must not be embedded as static blocks in source.

use std::path::PathBuf;

fn rs_files_under(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let path = ent.path();
        if path.is_dir() {
            rs_files_under(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Reject large `[u8; N] = [0x.., ...]` literals (vendor tail must be runtime-only).
fn has_large_byte_array_literal(source: &str) -> bool {
    const MIN_COMMA_BYTES: usize = 80;
    for chunk in source.split("[u8;") {
        let Some(rest) = chunk.split_once("] = [") else {
            continue;
        };
        let body = rest.1;
        let Some(end) = body.find(']') else {
            continue;
        };
        let inner = &body[..end];
        let commas = inner.matches(',').count();
        if commas >= MIN_COMMA_BYTES {
            return true;
        }
    }
    false
}

const FORBIDDEN_TAIL_BUILDERS: &[&str] = &[
    "spec_header_tail",
    "fn spec_header_tail",
    "dir_length(",
    "3.11K",
];

#[test]
fn kxprovd_sources_have_no_embedded_header_tail_block() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files_under(&root, &mut files).expect("walk src");
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            !has_large_byte_array_literal(&text),
            "suspected embedded byte block in {}",
            path.display()
        );
        assert!(
            !text.contains("fn assemble("),
            "legacy assemble() must not exist in {}",
            path.display()
        );
        for needle in FORBIDDEN_TAIL_BUILDERS {
            assert!(
                !text.contains(needle),
                "forbidden header-tail builder {needle:?} in {}",
                path.display()
            );
        }
    }
}
