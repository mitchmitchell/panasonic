use rustix::fd::AsFd;
use std::io;

/// Maps a `TIOCMGET` status word to CTS high (`true`) or low (`false`).
pub fn modem_cts_high(bits: i32) -> bool {
    bits & libc::TIOCM_CTS != 0
}

/// Reads whether CTS is high via `TIOCMGET`. Never sets modem control lines.
pub fn read_cts<Fd: AsFd>(fd: Fd) -> io::Result<bool> {
    use libc::TIOCMGET;
    use rustix::ffi as c;
    use rustix::ioctl;
    // SAFETY: Linux documents `TIOCMGET` as writing one `c_int` of modem status (tty_ioctl(4)).
    let bits = unsafe {
        let ctl = ioctl::Getter::<{ TIOCMGET as ioctl::Opcode }, c::c_int>::new();
        rustix::ioctl::ioctl(fd, ctl)?
    };
    Ok(modem_cts_high(bits))
}

#[cfg(test)]
mod tests {
    use super::modem_cts_high;
    use libc::{TIOCM_CTS, TIOCM_DSR};

    #[test]
    fn tiocmget_cts_bit_set_means_high() {
        assert!(modem_cts_high(TIOCM_CTS));
        assert!(modem_cts_high(TIOCM_CTS | TIOCM_DSR));
        assert!(!modem_cts_high(0));
        assert!(!modem_cts_high(TIOCM_DSR));
    }
}
