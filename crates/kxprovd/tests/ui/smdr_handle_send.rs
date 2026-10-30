use kxprovd::port::{journal::LeaseJournal, PortManager};
use kxtd1232_sim::{SimPbx, SimTransport};

fn main() {
    let pm = PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new("/dev/null"),
        1,
    );
    let mut handle = pm.smdr_handle();
    handle.send(b"BYE\r\n");
}
