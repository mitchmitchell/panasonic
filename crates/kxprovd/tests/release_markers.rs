//! Release binaries must not embed sim-fault trigger markers (see CI `release-sim-fault-strings`).

#[test]
fn release_sim_fault_marker_list_for_ci() {
    const MARKERS: &[&str] = &[
        "sim_trigger_busy",
        "SimTriggerGoliathCopyFail",
        "trigger_next_copy_fail",
        "sim_trigger_goliath",
    ];
    assert_eq!(MARKERS.len(), 4);
}
