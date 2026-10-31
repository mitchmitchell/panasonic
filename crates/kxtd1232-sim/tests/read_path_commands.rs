#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]

use kxtd1232::frame::Access;
use kxtd1232::tables::TABLES;
use kxtd1232::{Client, Timing, Transport, TransportError};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

struct Recording {
    inner: SimTransport,
    recording: bool,
    frames: Vec<Vec<u8>>,
}

impl Transport for Recording {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.recording {
            self.frames.push(data.to_vec());
        }
        self.inner.send(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.inner.recv(timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        self.inner.now_ms()
    }

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.inner.cycle_dtr()
    }
}

#[test]
fn a_full_read_session_sends_only_read_clock_probe_and_end_binary_commands() {
    let t = Recording {
        inner: SimTransport::new(SimPbx::default()),
        recording: false,
        frames: Vec::new(),
    };
    let mut c = Client::with(t, Access::ReadOnly, Timing::default());
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c.transport_mut().recording = true;
    for spec in TABLES.iter() {
        c.read_table(spec.id).unwrap();
    }
    c.end_binary().unwrap();
    let sent = &c.transport().frames;
    let end = sent
        .iter()
        .position(|f| f.as_slice() == [0x02, 0x0B, 0x0D])
        .expect("end-binary 02 0B 0D was never sent");
    let (binary, text) = sent.split_at(end + 1);
    assert!(binary.len() > TABLES.len(), "{} frames", binary.len());
    for f in binary {
        assert!(
            matches!(f.get(1), Some(0x01 | 0x03 | 0x08 | 0x0B)),
            "read path sent command outside 01/03/08/0B: {f:02X?}"
        );
    }
    for f in text {
        assert_eq!(f.as_slice(), b"BYE\r\n", "after end-binary: {f:02X?}");
    }
}
