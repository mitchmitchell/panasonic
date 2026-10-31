use crate::smdr_reader::SmdrSource;
use kxtd1232::TransportError;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::sys::termios::{self, BaudRate, ControlFlags, InputFlags, LocalFlags, SetArg, Termios};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const SMDR_BAUD: BaudRate = BaudRate::B9600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmdrLineOptions {
    pub rtscts: bool,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceError {
    #[error("open {0}")]
    Open(std::io::Error),
    #[error("device is locked by another process")]
    Locked,
    #[error("flock: {0}")]
    Flock(Errno),
    #[error("isatty: {0}")]
    Isatty(Errno),
    #[error("not a tty")]
    NotATty,
    #[error("termios: {0}")]
    Termios(Errno),
    #[error("the SMDR device is already open in this PortManager")]
    AlreadyOpen,
    #[error("termios flag {0} still set after tcsetattr")]
    TermiosNotApplied(&'static str),
}

pub(crate) struct SmdrDevice {
    file: Flock<File>,
}

impl SmdrDevice {
    pub(crate) fn open(path: &Path, options: SmdrLineOptions) -> Result<Self, DeviceError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(DeviceError::Open)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
            if e == Errno::EWOULDBLOCK {
                DeviceError::Locked
            } else {
                DeviceError::Flock(e)
            }
        })?;
        if !nix::unistd::isatty(file.as_raw_fd()).map_err(DeviceError::Isatty)? {
            return Err(DeviceError::NotATty);
        }
        let mut t = termios::tcgetattr(&*file).map_err(DeviceError::Termios)?;
        apply_smdr_termios(&mut t, options)?;
        termios::tcsetattr(&*file, SetArg::TCSANOW, &t).map_err(DeviceError::Termios)?;
        verify_smdr_termios(
            &termios::tcgetattr(&*file).map_err(DeviceError::Termios)?,
            options,
        )?;
        Ok(Self { file })
    }

    fn access_mode_is_read_only(&self) -> Result<bool, Errno> {
        let fl = nix::fcntl::fcntl(self.file.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL)?;
        Ok(fl & nix::libc::O_ACCMODE == nix::libc::O_RDONLY)
    }
}

fn apply_smdr_termios(t: &mut Termios, options: SmdrLineOptions) -> Result<(), DeviceError> {
    termios::cfmakeraw(t);
    t.input_flags &= !(InputFlags::IXON | InputFlags::IXOFF | InputFlags::IXANY);
    t.local_flags &= !(LocalFlags::ECHO
        | LocalFlags::ECHOE
        | LocalFlags::ECHOK
        | LocalFlags::ECHONL
        | LocalFlags::ECHOCTL
        | LocalFlags::ECHOKE
        | LocalFlags::ECHOPRT
        | LocalFlags::ICANON);
    t.control_flags &= !(ControlFlags::PARENB | ControlFlags::CSTOPB | ControlFlags::CSIZE);
    t.control_flags |= ControlFlags::CS8 | ControlFlags::CREAD | ControlFlags::CLOCAL;
    t.control_flags.set(ControlFlags::CRTSCTS, options.rtscts);
    termios::cfsetspeed(t, SMDR_BAUD).map_err(DeviceError::Termios)
}

pub const CLEARED_INPUT_FLAGS: [(&str, InputFlags); 3] = [
    ("IXON", InputFlags::IXON),
    ("IXOFF", InputFlags::IXOFF),
    ("IXANY", InputFlags::IXANY),
];

pub const CLEARED_LOCAL_FLAGS: [(&str, LocalFlags); 8] = [
    ("ECHO", LocalFlags::ECHO),
    ("ECHOE", LocalFlags::ECHOE),
    ("ECHOK", LocalFlags::ECHOK),
    ("ECHONL", LocalFlags::ECHONL),
    ("ECHOCTL", LocalFlags::ECHOCTL),
    ("ECHOKE", LocalFlags::ECHOKE),
    ("ECHOPRT", LocalFlags::ECHOPRT),
    ("ICANON", LocalFlags::ICANON),
];

fn verify_smdr_termios(t: &Termios, options: SmdrLineOptions) -> Result<(), DeviceError> {
    for (name, flag) in CLEARED_INPUT_FLAGS {
        if t.input_flags.contains(flag) {
            return Err(DeviceError::TermiosNotApplied(name));
        }
    }
    for (name, flag) in CLEARED_LOCAL_FLAGS {
        if t.local_flags.contains(flag) {
            return Err(DeviceError::TermiosNotApplied(name));
        }
    }
    if t.control_flags.contains(ControlFlags::CRTSCTS) != options.rtscts {
        return Err(DeviceError::TermiosNotApplied("CRTSCTS"));
    }
    Ok(())
}

pub struct SmdrDeviceHandle {
    device: Arc<Mutex<SmdrDevice>>,
}

impl SmdrDeviceHandle {
    pub(crate) fn new(device: Arc<Mutex<SmdrDevice>>) -> Self {
        Self { device }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SmdrDevice> {
        self.device
            .lock()
            .unwrap_or_else(super::recover_from_poison)
    }

    pub fn access_mode_is_read_only(&self) -> Result<bool, Errno> {
        self.lock().access_mode_is_read_only()
    }
}

impl SmdrSource for SmdrDeviceHandle {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let device = self.lock();
        let mut reader: &File = &device.file;
        crate::transport::recv_with_poll(&mut reader, timeout_ms)
    }
}
