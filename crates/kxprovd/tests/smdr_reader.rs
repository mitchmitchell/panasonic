use chrono::{DateTime, TimeZone, Utc};
use kxprovd::smdr_reader::{
    ReaderError, ReaderEvent, ReceiveOnly, SmdrReader, SmdrSink, SmdrSource,
};
use kxprovd::smdr_store::{IngestOutcome, SmdrStore};
use kxtd1232::smdr::{DateOrder, SPEC_HEADER};
use kxtd1232::{LinkDownError, Transport, TransportError};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Default)]
struct FakePort {
    chunks: Rc<RefCell<VecDeque<Vec<u8>>>>,
    sent: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl Transport for FakePort {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.sent.borrow_mut().push(data.to_vec());
        Ok(())
    }

    fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.chunks
            .borrow_mut()
            .pop_front()
            .ok_or(TransportError::Timeout)
    }

    fn now_ms(&mut self) -> u64 {
        0
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../kxtd1232/tests/fixtures/smdr-v1")
}

fn rx() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, 18, 5, 0)
        .single()
        .expect("rx")
}

fn chunked(bytes: &[u8], size: usize) -> VecDeque<Vec<u8>> {
    bytes.chunks(size).map(<[u8]>::to_vec).collect()
}

fn drain<S: SmdrSource>(reader: &mut SmdrReader<S>, store: &mut SmdrStore) -> Vec<ReaderEvent> {
    let mut events = Vec::new();
    loop {
        let batch = reader.poll_once(store, 10, rx).expect("poll");
        if batch == [ReaderEvent::Idle] {
            break;
        }
        events.extend(batch);
    }
    events.extend(reader.finish(store, rx).expect("finish"));
    events
}

fn store(tmp: &tempfile::TempDir) -> SmdrStore {
    SmdrStore::open(tmp.path(), &[&tmp.path().join("backups")], DateOrder::Mdy).expect("open")
}

#[test]
fn reader_stores_a_chunked_mixed_stream_from_a_fake_source() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = store(&tmp);
    let bytes = std::fs::read(fixture_dir().join("mixed_stream.txt")).expect("fixture");
    let port = FakePort {
        chunks: Rc::new(RefCell::new(chunked(&bytes, 7))),
        ..FakePort::default()
    };
    let mut reader = SmdrReader::new(ReceiveOnly::new(port));
    let events = drain(&mut reader, &mut store);
    let stored = events
        .iter()
        .filter(|e| **e == ReaderEvent::Ingested(IngestOutcome::Stored))
        .count();
    assert_eq!(stored, 5);
    assert!(!events
        .iter()
        .any(|e| matches!(e, ReaderEvent::HeaderMismatch { .. })));
    assert_eq!(store.call_count().expect("count"), 5);
}

#[test]
fn reader_never_writes_to_the_port_across_every_fixture() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = store(&tmp);
    let mut chunks = VecDeque::new();
    let mut names: Vec<_> = std::fs::read_dir(fixture_dir())
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "txt"))
        .collect();
    names.sort();
    for p in &names {
        chunks.extend(chunked(&std::fs::read(p).expect("fixture"), 3));
    }
    chunks.push_back(b"AT&F\r\n\x00\x11\x13\x0c\r\n".to_vec());
    let port = FakePort {
        chunks: Rc::new(RefCell::new(chunks)),
        ..FakePort::default()
    };
    let (remaining, sent) = (Rc::clone(&port.chunks), Rc::clone(&port.sent));
    let mut reader = SmdrReader::new(ReceiveOnly::new(port));
    let events = drain(&mut reader, &mut store);
    assert!(!events.is_empty());
    assert!(remaining.borrow().is_empty());
    assert!(sent.borrow().is_empty(), "reader wrote {:?}", sent.borrow());
}

#[test]
fn header_that_differs_from_spec_emits_a_typed_mismatch_event() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = store(&tmp);
    let changed = SPEC_HEADER.replace("Acc code", "Cost    ");
    assert_eq!(changed.len(), SPEC_HEADER.len());
    let outgoing = std::fs::read(fixture_dir().join("outgoing.txt")).expect("fixture");
    let mut chunks = VecDeque::new();
    chunks.push_back(format!("{SPEC_HEADER}\r\n{changed}\r\n").into_bytes());
    chunks.push_back(outgoing);
    let mut reader = SmdrReader::new(ReceiveOnly::new(FakePort {
        chunks: Rc::new(RefCell::new(chunks)),
        ..FakePort::default()
    }));
    let events = drain(&mut reader, &mut store);
    let mismatches: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ReaderEvent::HeaderMismatch { rx: at, raw } => Some((*at, raw.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(mismatches, vec![(rx(), changed)]);
    assert_eq!(store.call_count().expect("count"), 1);
    let journal = std::fs::read_to_string(store.journal_path(rx().date_naive())).expect("journal");
    assert_eq!(journal.lines().count(), 3);
}

#[test]
fn link_down_is_an_error_not_idle() {
    struct Down;
    impl SmdrSource for Down {
        fn recv(&mut self, _: u64) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::LinkDown(LinkDownError {
                detail: "down".into(),
                bytes_sent: None,
            }))
        }
    }
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = store(&tmp);
    let mut reader = SmdrReader::new(Down);
    assert!(matches!(
        reader.poll_once(&mut store, 1, rx),
        Err(ReaderError::LinkDown(_))
    ));
}

#[test]
fn a_failed_ingest_keeps_the_rest_of_the_batch_for_the_next_poll() {
    struct Flaky {
        fail_at: usize,
        seen: Vec<String>,
    }
    impl SmdrSink for Flaky {
        fn ingest(
            &mut self,
            line: kxtd1232::smdr::SmdrLine,
            _rx: DateTime<Utc>,
        ) -> Result<IngestOutcome, kxprovd::smdr_store::SmdrStoreError> {
            if self.seen.len() == self.fail_at {
                self.fail_at = usize::MAX;
                return Err(std::io::Error::other("disk full").into());
            }
            self.seen.push(line.raw().to_string());
            Ok(IngestOutcome::Stored)
        }
    }
    let bytes = std::fs::read(fixture_dir().join("mixed_stream.txt")).expect("fixture");
    let mut chunks = VecDeque::new();
    chunks.push_back(bytes.clone());
    let mut reader = SmdrReader::new(ReceiveOnly::new(FakePort {
        chunks: Rc::new(RefCell::new(chunks)),
        ..FakePort::default()
    }));
    let mut sink = Flaky {
        fail_at: 4,
        seen: Vec::new(),
    };
    assert!(matches!(
        reader.poll_once(&mut sink, 1, rx),
        Err(ReaderError::Store(_))
    ));
    assert_eq!(reader.pending(), 7);
    let retried = reader.poll_once(&mut sink, 1, rx).expect("retry");
    assert_eq!(
        retried,
        vec![ReaderEvent::Ingested(IngestOutcome::Stored); 11],
        "events for lines ingested before the failure are kept"
    );
    let text = String::from_utf8(bytes).expect("ascii");
    let want: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(sink.seen, want);
}

#[test]
fn a_header_mismatch_ahead_of_a_failed_ingest_is_not_lost() {
    struct FailSecond {
        calls: usize,
    }
    impl SmdrSink for FailSecond {
        fn ingest(
            &mut self,
            _line: kxtd1232::smdr::SmdrLine,
            _rx: DateTime<Utc>,
        ) -> Result<IngestOutcome, kxprovd::smdr_store::SmdrStoreError> {
            self.calls += 1;
            if self.calls == 2 {
                return Err(std::io::Error::other("disk full").into());
            }
            Ok(IngestOutcome::Skipped)
        }
    }
    let changed = SPEC_HEADER.replace("Acc code", "Cost    ");
    let mut chunks = VecDeque::new();
    chunks.push_back(format!("{changed}\r\n{SPEC_HEADER}\r\n").into_bytes());
    let mut reader = SmdrReader::new(ReceiveOnly::new(FakePort {
        chunks: Rc::new(RefCell::new(chunks)),
        ..FakePort::default()
    }));
    let mut sink = FailSecond { calls: 0 };
    assert!(matches!(
        reader.poll_once(&mut sink, 1, rx),
        Err(ReaderError::Store(_))
    ));
    let retried = reader.poll_once(&mut sink, 1, rx).expect("retry");
    assert_eq!(
        retried,
        vec![
            ReaderEvent::Ingested(IngestOutcome::Skipped),
            ReaderEvent::HeaderMismatch {
                rx: rx(),
                raw: changed
            },
            ReaderEvent::Ingested(IngestOutcome::Skipped),
        ]
    );
}
