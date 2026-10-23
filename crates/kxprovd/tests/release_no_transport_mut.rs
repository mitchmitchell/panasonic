//! Guard against Cargo feature unification pulling `test-transport-access` into release kxprovd (review 5632443566).

#![allow(clippy::assertions_on_constants)]

#[cfg(not(feature = "test-util"))]
#[test]
fn release_graph_has_no_test_transport_access() {
    assert!(
        !kxtd1232::TEST_TRANSPORT_ACCESS,
        "kxprovd default/release build must not enable kxtd1232/test-transport-access"
    );
}

#[cfg(feature = "test-util")]
#[test]
fn test_util_build_enables_test_transport_access() {
    assert!(
        kxtd1232::TEST_TRANSPORT_ACCESS,
        "test-util must enable kxtd1232/test-transport-access for fault-injection tests"
    );
}
