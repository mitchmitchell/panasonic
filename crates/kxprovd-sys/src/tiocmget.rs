use rustix::fd::AsFd;
use std::io;

/// Reads whether CTS is high via `TIOCMGET`. Never sets modem control lines.
pub fn read_cts<Fd: AsFd>(fd: Fd) -> io::Result<bool> {
    use libc::{TIOCMGET, TIOCM_CTS};
    use rustix::ffi as c;
    use rustix::ioctl;
    // SAFETY: Linux documents `TIOCMGET` as writing one `c_int` of modem status (tty_ioctl(4)).
    let bits = unsafe {
        let ctl = ioctl::Getter::<{ TIOCMGET as ioctl::Opcode }, c::c_int>::new();
        rustix::ioctl::ioctl(fd, ctl)?
    };
    Ok(bits & TIOCM_CTS != 0)
}
