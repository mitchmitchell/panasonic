use kxtd1232::smdr::{parse_line, DateOrder, LineSplitter, ParsedLine, SmdrRecord};
use kxtd1232_sim::smdr::{BufferPolicy, LineEnding, SmdrEmitter, SyntheticCall};

fn call(time: &str, number: &str) -> SyntheticCall {
    SyntheticCall {
        date: "10/23/26".into(),
        time: time.into(),
        ext: "101".into(),
        co: "01".into(),
        number: number.into(),
        duration: "00:01'00".into(),
        ..SyntheticCall::default()
    }
}

fn records(bytes: &[u8]) -> Vec<SmdrRecord> {
    let mut s = LineSplitter::new();
    let mut lines = s.push(bytes);
    lines.extend(s.finish());
    let mut recs = Vec::new();
    for l in lines {
        match parse_line(l, DateOrder::Mdy) {
            ParsedLine::Record { record, .. } => recs.push(*record),
            ParsedLine::PageHeader(_) => {}
            unexpected => panic!("unexpected {unexpected:?}"),
        }
    }
    recs
}

#[test]
fn synthetic_lines_round_trip_through_the_parser() {
    let incoming = SyntheticCall {
        date: "10/23/26".into(),
        time: "01:12PM".into(),
        ext: "102".into(),
        co: "02".into(),
        incoming: true,
        number: "5559870000".into(),
        cid_name: "DOE JOHN".into(),
        ring: "0'07".into(),
        duration: "00:00'41".into(),
        ..SyntheticCall::default()
    };
    let fixture = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kxtd1232/tests/fixtures/smdr-v1/incoming_cid.txt"),
    )
    .expect("fixture");
    assert_eq!(format!("{}\r\n", incoming.to_line()), fixture);
}

#[test]
fn idle_calls_print_immediately_with_page_header() {
    for ending in [LineEnding::CrLf, LineEnding::Cr] {
        let mut e = SmdrEmitter::new(BufferPolicy::Drop, ending);
        e.page_header();
        e.call_ended(&call("01:05PM", "5551230000"));
        let recs = records(&e.take_output());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].number, "5551230000");
    }
}

#[test]
fn replay_policy_buffers_during_programming_and_prints_after_bye() {
    let mut e = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    e.begin_programming();
    e.call_ended(&call("01:05PM", "5551230000"));
    e.call_ended(&call("01:06PM", "5551230001"));
    assert!(e.take_output().is_empty());
    assert_eq!(e.pending(), 2);
    e.end_programming();
    let recs = records(&e.take_output());
    let numbers: Vec<&str> = recs.iter().map(|r| r.number.as_str()).collect();
    assert_eq!(numbers, ["5551230000", "5551230001"]);
    assert_eq!(e.dropped(), 0);
    assert_eq!(e.pending(), 0);
}

#[test]
fn drop_policy_loses_calls_during_programming() {
    let mut e = SmdrEmitter::new(BufferPolicy::Drop, LineEnding::CrLf);
    e.begin_programming();
    assert!(e.is_programming());
    e.call_ended(&call("01:05PM", "5551230000"));
    e.end_programming();
    assert!(e.take_output().is_empty());
    assert_eq!(e.dropped(), 1);
    e.call_ended(&call("01:07PM", "5551230002"));
    let recs = records(&e.take_output());
    assert_eq!(recs.len(), 1);
}
