use chrono::{DateTime, TimeZone, Utc};
use kxprovd::smdr_health::{
    alert_text, observations_from_reader, HealthConfig, HealthMonitor, HealthSignal, Observation,
    Severity, SignalKind, Transition,
};
use kxprovd::smdr_reader::{ReaderEvent, ReceiveOnly, SmdrReader};
use kxprovd::smdr_store::SmdrStore;
use kxtd1232::smdr::{DateOrder, SPEC_HEADER};
use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::smdr::{BufferPolicy, LineEnding, SmdrEmitter, SyntheticCall};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

const H: Duration = Duration::from_secs(3600);
const M: Duration = Duration::from_secs(60);

fn wall() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 2, 18, 0, 0)
        .single()
        .expect("wall")
}

fn raised(kind: SignalKind, sev: Severity) -> impl Fn(&Transition) -> bool {
    move |t| matches!(t, Transition::Raised { signal, severity } if signal.kind() == kind && *severity == sev)
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

fn call() -> SyntheticCall {
    SyntheticCall {
        date: "11/02/26".into(),
        time: "10:15AM".into(),
        ext: "101".into(),
        co: "01".into(),
        incoming: false,
        number: "5550100".into(),
        ring: String::new(),
        duration: "00:01'05".into(),
        ..SyntheticCall::default()
    }
}

struct Rig {
    reader: SmdrReader<ReceiveOnly<NeverSend>>,
    chunks: Rc<RefCell<VecDeque<Vec<u8>>>>,
    store: SmdrStore,
    _tmp: tempfile::TempDir,
}

impl Rig {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = SmdrStore::open(tmp.path(), &[&tmp.path().join("backups")], DateOrder::Mdy)
            .expect("open");
        let port = NeverSend::default();
        let chunks = Rc::clone(&port.chunks);
        Self {
            reader: SmdrReader::new(ReceiveOnly::new(port)),
            chunks,
            store,
            _tmp: tmp,
        }
    }

    fn pump(
        &mut self,
        emitter: &mut SmdrEmitter,
        mon: &mut HealthMonitor,
        now: Instant,
    ) -> Vec<Transition> {
        let bytes = emitter.take_output();
        let had_bytes = !bytes.is_empty();
        if had_bytes {
            self.chunks.borrow_mut().push_back(bytes);
        }
        let mut out = Vec::new();
        loop {
            let events = self
                .reader
                .poll_once(&mut self.store, 1, wall)
                .expect("poll");
            if events == [ReaderEvent::Idle] {
                break;
            }
            for obs in observations_from_reader(&events) {
                out.extend(mon.step(obs, now, wall()));
            }
        }
        if had_bytes {
            out.extend(mon.step(Observation::Byte, now, wall()));
        }
        out.extend(mon.step(Observation::Tick, now, wall()));
        out
    }
}

#[test]
fn silence_raises_warn_at_24h_not_before_then_crit_then_clears_on_byte() {
    let t0 = Instant::now();
    let mut m = HealthMonitor::new(HealthConfig::default(), t0);
    assert!(m
        .step(Observation::Tick, t0 + 24 * H - M, wall())
        .is_empty());
    let w = m.step(Observation::Tick, t0 + 24 * H, wall());
    assert_eq!(w.len(), 1);
    assert!(raised(SignalKind::LineSilence, Severity::Warn)(&w[0]));
    assert!(m.step(Observation::Tick, t0 + 30 * H, wall()).is_empty());
    let c = m.step(Observation::Tick, t0 + 72 * H, wall());
    assert_eq!(c.len(), 1);
    assert!(raised(SignalKind::LineSilence, Severity::Crit)(&c[0]));
    assert!(m.step(Observation::Tick, t0 + 80 * H, wall()).is_empty());
    let cl = m.step(Observation::Byte, t0 + 81 * H, wall());
    assert_eq!(
        cl,
        vec![Transition::Cleared {
            kind: SignalKind::LineSilence
        }]
    );
    assert!(m.active().is_empty());
}

#[test]
fn silence_clock_is_suspended_across_a_programming_lease() {
    let t0 = Instant::now();
    let mut m = HealthMonitor::new(HealthConfig::default(), t0);
    assert!(m
        .step(Observation::ReaderPaused, t0 + 23 * H, wall())
        .is_empty());
    assert!(m.step(Observation::Tick, t0 + 25 * H, wall()).is_empty());
    assert!(m
        .step(Observation::ReaderResumed, t0 + 25 * H, wall())
        .is_empty());
    assert_eq!(m.silence(t0 + 25 * H), 23 * H);
    assert!(m
        .step(Observation::Tick, t0 + 26 * H - M, wall())
        .is_empty());
    let w = m.step(Observation::Tick, t0 + 26 * H, wall());
    assert!(raised(SignalKind::LineSilence, Severity::Warn)(&w[0]));
}

#[test]
fn cts_low_raises_after_grace_once_and_clears_when_high() {
    let t0 = Instant::now();
    let mut m = HealthMonitor::new(HealthConfig::default(), t0);
    let s = Duration::from_secs(1);
    assert!(m
        .step(Observation::Modem { cts: false }, t0, wall())
        .is_empty());
    assert!(m
        .step(Observation::Modem { cts: false }, t0 + 29 * s, wall())
        .is_empty());
    let r = m.step(Observation::Modem { cts: false }, t0 + 30 * s, wall());
    assert_eq!(r.len(), 1);
    assert!(raised(SignalKind::CtsLow, Severity::Warn)(&r[0]));
    for i in 31..40 {
        assert!(m
            .step(Observation::Modem { cts: false }, t0 + i * s, wall())
            .is_empty());
    }
    let c = m.step(Observation::Modem { cts: true }, t0 + 41 * s, wall());
    assert_eq!(
        c,
        vec![Transition::Cleared {
            kind: SignalKind::CtsLow
        }]
    );
}

#[test]
fn cts_blip_shorter_than_grace_raises_nothing() {
    let t0 = Instant::now();
    let mut m = HealthMonitor::new(HealthConfig::default(), t0);
    let s = Duration::from_secs(1);
    assert!(m
        .step(Observation::Modem { cts: false }, t0, wall())
        .is_empty());
    assert!(m
        .step(Observation::Modem { cts: true }, t0 + 10 * s, wall())
        .is_empty());
    assert!(m.step(Observation::Tick, t0 + 60 * s, wall()).is_empty());
}

#[test]
fn header_mismatch_raises_once_counts_and_clears_after_window() {
    let t0 = Instant::now();
    let mut m = HealthMonitor::new(HealthConfig::default(), t0);
    let r = m.step(Observation::HeaderMismatch { rx: wall() }, t0, wall());
    assert_eq!(
        r,
        vec![Transition::Raised {
            signal: HealthSignal::HeaderMismatch {
                rx: wall(),
                count_24h: 1
            },
            severity: Severity::Warn
        }]
    );
    assert!(m
        .step(Observation::HeaderMismatch { rx: wall() }, t0 + H, wall())
        .is_empty());
    assert!(m.step(Observation::Byte, t0 + 24 * H, wall()).is_empty());
    let c = m.step(Observation::Tick, t0 + 25 * H, wall());
    assert_eq!(
        c,
        vec![Transition::Cleared {
            kind: SignalKind::HeaderMismatch
        }]
    );
}

#[test]
fn sim_emitter_stop_raises_line_silence_without_transmitting() {
    let t0 = Instant::now();
    let mut rig = Rig::new();
    let mut em = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    let mut mon = HealthMonitor::new(HealthConfig::default(), t0);
    em.page_header();
    em.call_ended(&call()).expect("call");
    assert!(rig.pump(&mut em, &mut mon, t0 + H).is_empty());
    let w = rig.pump(&mut em, &mut mon, t0 + 25 * H);
    assert!(w
        .iter()
        .any(raised(SignalKind::LineSilence, Severity::Warn)));
    em.call_ended(&call()).expect("call");
    let c = rig.pump(&mut em, &mut mon, t0 + 26 * H);
    assert!(c.contains(&Transition::Cleared {
        kind: SignalKind::LineSilence
    }));
}

#[test]
fn sim_header_variant_raises_header_mismatch_from_the_s4_event() {
    let t0 = Instant::now();
    let mut rig = Rig::new();
    let mut em = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    let mut mon = HealthMonitor::new(HealthConfig::default(), t0);
    em.page_header();
    assert!(rig.pump(&mut em, &mut mon, t0).is_empty());
    let changed = SPEC_HEADER.replace("Acc code", "Cost    ");
    rig.chunks
        .borrow_mut()
        .push_back(format!("{changed}\r\n").into_bytes());
    let r = rig.pump(&mut em, &mut mon, t0 + M);
    assert!(r
        .iter()
        .any(raised(SignalKind::HeaderMismatch, Severity::Warn)));
}

#[test]
fn sim_lease_pause_suspends_silence_while_emitter_buffers() {
    let t0 = Instant::now();
    let mut rig = Rig::new();
    let mut em = SmdrEmitter::new(BufferPolicy::ReplayAfterBye, LineEnding::CrLf);
    let mut mon = HealthMonitor::new(HealthConfig::default(), t0);
    em.page_header();
    assert!(rig.pump(&mut em, &mut mon, t0).is_empty());
    em.begin_programming();
    assert!(mon
        .step(Observation::ReaderPaused, t0 + 23 * H, wall())
        .is_empty());
    em.call_ended(&call()).expect("buffered");
    assert!(mon.step(Observation::Tick, t0 + 30 * H, wall()).is_empty());
    em.end_programming();
    assert!(mon
        .step(Observation::ReaderResumed, t0 + 30 * H, wall())
        .is_empty());
    assert!(rig.pump(&mut em, &mut mon, t0 + 30 * H).is_empty());
    assert_eq!(mon.silence(t0 + 30 * H), Duration::ZERO);
}

#[test]
fn alert_text_carries_no_call_data() {
    let t = Transition::Raised {
        signal: HealthSignal::HeaderMismatch {
            rx: wall(),
            count_24h: 3,
        },
        severity: Severity::Warn,
    };
    let text = alert_text(&t);
    assert!(text.contains("header mismatch"));
    assert!(!text.contains("5550100"));
}
