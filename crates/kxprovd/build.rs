fn main() {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=KXPROV_BUILD_HASH={hash}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo::rustc-check-cfg=cfg(kxprov_api_sim)");
    println!("cargo::rerun-if-env-changed=DEP_KXPROV_API_SIM_FAULT_TRIGGERS");
    if std::env::var_os("DEP_KXPROV_API_SIM_FAULT_TRIGGERS").is_some() {
        println!("cargo::rustc-cfg=kxprov_api_sim");
    }
}
