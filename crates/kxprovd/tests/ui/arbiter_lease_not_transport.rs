use kxprovd::port::{journal::LeaseJournal, DeviceArbiter};
use kxtd1232::Transport;

fn needs_transport<T: Transport>(_: T) {}

fn main() {
    let pm = DeviceArbiter::new((), LeaseJournal::new("/dev/null"), 1);
    let lease = pm
        .request_lease("job", std::time::Duration::from_millis(1))
        .unwrap();
    needs_transport(lease);
}
