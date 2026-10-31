use kxprovd::port::{journal::LeaseJournal, PortManager};
use kxtd1232::Transport;
use kxtd1232_sim::{SimPbx, SimTransport};

fn needs_transport<T: Transport>(_: T) {}

fn main() {
    let pm = PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new("/dev/null"),
        1,
    );
    needs_transport(pm.smdr_handle());
}
