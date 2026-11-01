#[test]
fn smdr_handle_cannot_send() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/smdr_handle_send.rs");
    t.compile_fail("tests/ui/smdr_handle_not_transport.rs");
    t.compile_fail("tests/ui/arbiter_lease_not_transport.rs");
}
