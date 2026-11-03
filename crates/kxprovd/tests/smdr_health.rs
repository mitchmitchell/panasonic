#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use chrono::{DateTime, TimeZone, Utc};
use kxprov_api::{SmdrAlert, SmdrAlertKind, SmdrAlertState};
use kxprovd::smdr_bus::SmdrLive;
use kxprovd::smdr_health::{
    observations_from_reader, ByteCounter, ByteTap, HealthBoard, HealthConfig, ModemStatusError,
    Observation, PortState,
};
use kxprovd::smdr_reader::{ReaderEvent, ReceiveOnly, SmdrReader};
use kxprovd::smdr_store::SmdrStore;
use kxtd1232::smdr::{DateOrder, SmdrLine, SPEC_HEADER};
use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::smdr::{BufferPolicy, LineEnding, SmdrEmitter, SyntheticCall};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const SILENCE: Duration = Duration::from_secs(86_400);
const DEBOUNCE: Duration = Duration::from_secs(30);
const EPS: Duration = Duration::from_millis(1);

fn wall() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 2, 18, 0, 0)
        .single()
        .unwrap()
}

fn cfg(cts_monitor: bool) -> HealthConfig {
    HealthConfig {
        silence_after: SILENCE,
        cts_low_after: DEBOUNCE,
        cts_monitor,
    }
}

#[derive(Default)]
struct NeverSend {
    chunks: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl Transport for NeverSend {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        panic!("S7 health path transmitted {data:?}");
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

fn call(n: u32) -> SyntheticCall {
    SyntheticCall {
        date: "11/02/26".into(),
        time: "10:15AM".into(),
        ext: format!("{}", 101 + n),
        co: "01".into(),
        incoming: false,
        number: "5550100".into(),
        ring: String::new(),
        duration: "00:01'05".into(),
        ..SyntheticCall::default()
    }
}

/// Simulator, S4 reader, store and S7 board, all on a fake monotonic clock.
struct Rig {
    reader: SmdrReader<ByteTap<ReceiveOnly<NeverSend>>>,
    chunks: Rc<RefCell<VecDeque<Vec<u8>>>>,
    bytes: ByteCounter,
    store: SmdrStore,
    board: HealthBoard,
    live: Arc<SmdrLive>,
    edges: broadcast::Receiver<SmdrAlert>,
    t0: Instant,
    _tmp: tempfile::TempDir,
}

impl Rig {
    fn new(cfg: HealthConfig) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            SmdrStore::open(tmp.path(), &[&tmp.path().join("backups")], DateOrder::Mdy).unwrap();
        let port = NeverSend::default();
        let chunks = Rc::clone(&port.chunks);
        let (tap, bytes) = ByteTap::new(ReceiveOnly::new(port));
        let live = Arc::new(SmdrLive::new());
        let edges = live.subscribe_alerts();
        let mut rig = Self {
            reader: SmdrReader::new(tap),
            chunks,
            bytes,
            store,
            board: HealthBoard::new(cfg, Arc::clone(&live)),
            live,
            edges,
            t0: Instant::now(),
            _tmp: tmp,
        };
        rig.board
            .observe(Observation::Port(PortState::Smdr), rig.t0, wall());
        rig
    }

    fn feed(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.chunks.borrow_mut().push_back(bytes);
        }
    }

    /// Drains the source through S4, feeds header signals to S7, then ticks once at `t0 + at`.
    fn run(&mut self, at: Duration) -> Vec<SmdrAlert> {
        let now = self.t0 + at;
        loop {
            let events = self.reader.poll_once(&mut self.store, 1, wall).unwrap();
            if events == [ReaderEvent::Idle] {
                break;
            }
            for obs in observations_from_reader(&events) {
                self.board.observe(obs, now, wall());
            }
        }
        self.board.tick(&mut self.bytes, now, wall());
        self.drain_edges()
    }

    fn observe(&mut self, obs: Observation, at: Duration) -> Vec<SmdrAlert> {
        self.board.observe(obs, self.t0 + at, wall());
        self.board.tick(&mut self.bytes, self.t0 + at, wall());
        self.drain_edges()
    }

    fn drain_edges(&mut self) -> Vec<SmdrAlert> {
        std::iter::from_fn(|| self.edges.try_recv().ok()).collect()
    }

    fn active(&self) -> Vec<SmdrAlertKind> {
        self.live.snapshot().alerts.iter().map(|a| a.kind).collect()
    }
}

fn is_raised(kind: SmdrAlertKind) -> impl Fn(&SmdrAlert) -> bool {
    move |a| a.kind == kind && matches!(a.state, SmdrAlertState::Raised { .. })
}

fn is_cleared(kind: SmdrAlertKind) -> impl Fn(&SmdrAlert) -> bool {
    move |a| a.kind == kind && matches!(a.state, SmdrAlertState::Cleared { .. })
}

fn one(edges: &[SmdrAlert], pred: impl Fn(&SmdrAlert) -> bool) {
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert!(pred(&edges[0]), "{edges:?}");
}

#[test]
fn line_silence_raises_once_clears_on_a_byte_and_ignores_records_and_program_mode() {
    use SmdrAlertKind::LineSilence;
    let mut r = Rig::new(cfg(false));

    assert!(
        r.run(SILENCE - EPS).is_empty(),
        "1. threshold - ε raises nothing"
    );

    let line = SmdrLine::new(call(90).to_line().unwrap());
    r.store.ingest(line, wall()).unwrap();
    let records = r.store.call_count().unwrap();
    assert!(
        records > 0,
        "5. a record arrived without any byte on the port"
    );

    let raised = r.run(SILENCE);
    one(&raised, is_raised(LineSilence));
    assert_eq!(
        r.active(),
        vec![LineSilence],
        "2. and 5. the record did not reset the timer"
    );

    for step in 1..=10 {
        assert!(r.run(SILENCE * (1 + step)).is_empty(), "3. still one alert");
    }
    assert_eq!(
        r.live.snapshot().alerts,
        vec![raised[0].clone()],
        "3. since stays fixed"
    );

    r.feed(b"\r\n".to_vec());
    one(&r.run(SILENCE * 12), is_cleared(LineSilence));
    assert!(r.active().is_empty(), "4. one byte clears");

    let mut em = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    let start = SILENCE * 12;
    assert!(r
        .observe(Observation::Port(PortState::Programming), start)
        .is_empty());
    em.begin_programming();
    em.call_ended(&call(0)).unwrap();
    r.feed(em.take_output());
    assert!(
        r.run(start + SILENCE * 3).is_empty(),
        "6. program mode longer than threshold"
    );
    assert!(r
        .observe(Observation::Port(PortState::Smdr), start + SILENCE * 3)
        .is_empty());
    assert!(
        r.run(start + SILENCE * 4 - EPS).is_empty(),
        "6. timer restarts on return to Smdr"
    );
    em.end_programming();
    r.feed(em.take_output());
    assert!(
        r.run(start + SILENCE * 4).is_empty(),
        "6. replayed bytes reset it"
    );
    assert_eq!(r.store.call_count().unwrap(), records + 1);
}

#[test]
fn cts_low_is_debounced_both_ways_and_disabled_or_unreadable_cts_never_alerts() {
    use SmdrAlertKind::CtsLow;
    let low = || Observation::ModemStatus(Ok(false));
    let high = || Observation::ModemStatus(Ok(true));
    let s = Duration::from_secs;

    let mut r = Rig::new(cfg(true));
    assert!(r.observe(low(), s(0)).is_empty());
    assert!(
        r.observe(high(), s(10)).is_empty(),
        "1. flicker shorter than debounce"
    );
    assert!(r.observe(Observation::Tick, s(100)).is_empty());

    assert!(r.observe(low(), s(200)).is_empty());
    assert!(r.observe(low(), s(229)).is_empty());
    one(&r.observe(low(), s(230)), is_raised(CtsLow));
    assert_eq!(r.active(), vec![CtsLow], "2. sustained low raises");

    for t in (240..2000).step_by(10) {
        assert!(
            r.observe(low(), s(t)).is_empty(),
            "3. still one alert at {t}"
        );
    }

    assert!(r.observe(high(), s(2000)).is_empty());
    assert!(
        r.observe(low(), s(2010)).is_empty(),
        "a high flicker does not clear"
    );
    assert!(r.observe(high(), s(2020)).is_empty());
    assert!(r.observe(high(), s(2049)).is_empty());
    one(&r.observe(high(), s(2050)), is_cleared(CtsLow));
    assert!(r.active().is_empty(), "4. high for the debounce clears");

    let mut off = Rig::new(cfg(false));
    for t in (0..5000).step_by(30) {
        assert!(
            off.observe(low(), s(t)).is_empty(),
            "5. disabled never alerts"
        );
    }
    let cts = off.live.snapshot().cts;
    assert!(!cts.monitored);
    assert_eq!(cts.high, Some(false), "5. disabled still reports CTS");

    let mut err = Rig::new(cfg(true));
    let failed = || {
        Observation::ModemStatus(Err(ModemStatusError::from(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe,
        ))))
    };
    assert!(err.observe(low(), s(0)).is_empty());
    assert!(err.observe(failed(), s(20)).is_empty());
    assert!(err.observe(low(), s(25)).is_empty());
    assert!(
        err.observe(Observation::Tick, s(40)).is_empty(),
        "6. error reset continuity"
    );
    let mut seen = Vec::new();
    for t in (100..1000).step_by(10) {
        seen.extend(err.observe(failed(), s(t)));
    }
    assert!(seen.is_empty(), "6. read errors raise no CtsLow");
    let cts = err.live.snapshot().cts;
    assert_eq!(cts.high, None, "6. an error is neither high nor low");
    assert_eq!(
        cts.read_error.as_deref(),
        Some("modem status read failed: broken pipe"),
        "6. error visible in status"
    );
}

#[test]
fn header_mismatch_raises_once_and_clears_on_the_s4_matched_signal() {
    use SmdrAlertKind::HeaderMismatch;
    let changed = SPEC_HEADER.replace("Acc code", "Cost    ");
    let page = |header: &str| format!("{header}\r\n").into_bytes();
    let mut em = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    let mut r = Rig::new(cfg(false));
    let s = Duration::from_secs;

    em.page_header();
    r.feed(em.take_output());
    assert!(r.run(s(1)).is_empty(), "1. matching header raises nothing");

    em.call_ended(&call(0)).unwrap();
    r.feed(em.take_output());
    assert!(r.run(s(2)).is_empty());
    let before = r.store.call_count().unwrap();

    r.feed(page(&changed));
    let raised = r.run(s(3));
    one(&raised, is_raised(HeaderMismatch));
    let json = serde_json::to_string(&raised[0]).unwrap();
    assert!(
        !json.contains("Cost"),
        "payload carries no header text: {json}"
    );

    for p in 0..5u32 {
        r.feed(page(&changed));
        em.call_ended(&call(p + 1)).unwrap();
        r.feed(em.take_output());
        assert!(r.run(s(10 + u64::from(p))).is_empty(), "3. still one alert");
    }
    assert_eq!(r.board.monitor().header_mismatches(), 6);
    assert_eq!(
        r.store.call_count().unwrap(),
        before + 5,
        "5. records parse identically during the mismatch"
    );

    em.page_header();
    r.feed(em.take_output());
    one(&r.run(s(100)), is_cleared(HeaderMismatch));
    assert!(r.active().is_empty(), "4. matching header clears");
}

fn data_version(db: &rusqlite::Connection) -> i64 {
    db.query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn evaluation_writes_nothing_to_sqlite_or_the_port() {
    let mut r = Rig::new(cfg(true));
    let path = r.store.dir().join(kxprovd::smdr_store::SMDR_DB_NAME);
    assert!(path.is_file(), "store db at {}", path.display());
    let watcher = rusqlite::Connection::open(&path).unwrap();
    let calls = r.store.call_count().unwrap();
    let before = data_version(&watcher);
    let mut edges = Vec::new();
    for i in 0..50u32 {
        let at = SILENCE * i;
        edges.extend(r.observe(Observation::ModemStatus(Ok(i % 2 == 0)), at));
        edges.extend(r.observe(Observation::HeaderMismatch, at));
        edges.extend(r.observe(Observation::HeaderMatched, at));
        edges.extend(r.run(at));
    }
    let tally = |kind: SmdrAlertKind, raised: bool| {
        edges
            .iter()
            .filter(|e| {
                e.kind == kind && matches!(e.state, SmdrAlertState::Raised { .. }) == raised
            })
            .count()
    };
    assert_eq!(tally(SmdrAlertKind::HeaderMismatch, true), 50);
    assert_eq!(tally(SmdrAlertKind::HeaderMismatch, false), 50);
    assert_eq!(tally(SmdrAlertKind::LineSilence, true), 1);
    assert_eq!(tally(SmdrAlertKind::LineSilence, false), 0);
    assert_eq!(tally(SmdrAlertKind::CtsLow, true), 0);
    assert_eq!(tally(SmdrAlertKind::CtsLow, false), 0);
    assert_eq!(r.store.call_count().unwrap(), calls);
    assert_eq!(
        data_version(&watcher),
        before,
        "alert evaluation committed to SQLite"
    );

    let line = SmdrLine::new(call(42).to_line().unwrap());
    r.store.ingest(line, wall()).unwrap();
    assert_ne!(
        data_version(&watcher),
        before,
        "the watcher sees a real ingest, so the check above can fail"
    );
}
