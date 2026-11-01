fn main() {
    if std::env::var_os("CARGO_FEATURE_SIM_FAULT_TRIGGERS").is_some() {
        println!("cargo::metadata=sim_fault_triggers=1");
    }
}
