#![allow(clippy::unwrap_used)]

use std::process::Command;

/// Ensures `scripts/run-a4.sh smoke` boots the debug sim stack (CI / local Artisan).
#[test]
fn run_a4_script_smoke_exits_zero() {
    if std::env::var("RUN_A4_SCRIPT_SMOKE").ok().as_deref() != Some("1") {
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let output = Command::new("bash")
        .arg(root.join("scripts/run-a4.sh"))
        .arg("smoke")
        .current_dir(&root)
        .output()
        .expect("run-a4.sh smoke");
    if !output.status.success() {
        eprintln!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        output.status.success(),
        "run-a4.sh smoke failed (first run)"
    );

    let output2 = Command::new("bash")
        .arg(root.join("scripts/run-a4.sh"))
        .arg("smoke")
        .current_dir(&root)
        .output()
        .expect("run-a4.sh smoke second run");
    if !output2.status.success() {
        eprintln!(
            "second run stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output2.stdout),
            String::from_utf8_lossy(&output2.stderr)
        );
    }
    assert!(
        output2.status.success(),
        "run-a4.sh smoke failed on second consecutive run (stale socket/pid)"
    );
}
