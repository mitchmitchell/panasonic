use crate::smdr_reader::SmdrSource;
use kxtd1232::{Transport, TransportError};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::sys::termios::{self, BaudRate, ControlFlags, InputFlags, LocalFlags, SetArg, Termios};
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SMDR_BAUD: BaudRate = BaudRate::B9600;
pub const PROGRAMMING_SEND_BOUND_MS: u64 = 2_000;

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
    #[error("a programming open needs this PortManager's held programming lease")]
    NoLease,
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
    leased: Arc<AtomicBool>,
}

impl SmdrDeviceHandle {
    pub(crate) fn new(device: Arc<Mutex<SmdrDevice>>, leased: Arc<AtomicBool>) -> Self {
        Self { device, leased }
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
        if self.leased.load(Ordering::SeqCst) {
            return Err(TransportError::Timeout);
        }
        let device = self.lock();
        let mut reader: &File = &device.file;
        crate::transport::recv_with_poll(&mut reader, timeout_ms)
    }
}

pub(crate) enum FlockCover {
    HeldBySmdr(Arc<Mutex<SmdrDevice>>),
    Own,
}

enum ProgrammingFile {
    CoveredBySmdr {
        file: File,
        _smdr: Arc<Mutex<SmdrDevice>>,
    },
    Locked(Flock<File>),
}

impl ProgrammingFile {
    fn file(&self) -> &File {
        match self {
            Self::CoveredBySmdr { file, .. } => file,
            Self::Locked(f) => f,
        }
    }
}

pub struct ProgrammingDevice<'lease> {
    file: ProgrammingFile,
    session: super::SessionMode,
    ended: bool,
    _lease: PhantomData<&'lease ()>,
}

impl ProgrammingDevice<'_> {
    pub(crate) fn open(
        path: &Path,
        options: SmdrLineOptions,
        cover: FlockCover,
    ) -> Result<Self, DeviceError> {
        let raw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(DeviceError::Open)?;
        let file = match cover {
            FlockCover::HeldBySmdr(smdr) => ProgrammingFile::CoveredBySmdr {
                file: raw,
                _smdr: smdr,
            },
            FlockCover::Own => ProgrammingFile::Locked(
                Flock::lock(raw, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
                    if e == Errno::EWOULDBLOCK {
                        DeviceError::Locked
                    } else {
                        DeviceError::Flock(e)
                    }
                })?,
            ),
        };
        let fd = file.file();
        if !nix::unistd::isatty(fd.as_raw_fd()).map_err(DeviceError::Isatty)? {
            return Err(DeviceError::NotATty);
        }
        let mut t = termios::tcgetattr(fd).map_err(DeviceError::Termios)?;
        apply_smdr_termios(&mut t, options)?;
        termios::tcsetattr(fd, SetArg::TCSANOW, &t).map_err(DeviceError::Termios)?;
        verify_smdr_termios(
            &termios::tcgetattr(fd).map_err(DeviceError::Termios)?,
            options,
        )?;
        Ok(Self {
            file,
            session: super::SessionMode::SignedOut,
            ended: false,
            _lease: PhantomData,
        })
    }

    pub fn holds_own_flock(&self) -> bool {
        matches!(self.file, ProgrammingFile::Locked(_))
    }

    pub fn session_mode(&self) -> super::SessionMode {
        self.session
    }

    pub fn end(mut self, step_timeout: std::time::Duration) -> Result<(), super::PortReleaseError> {
        self.end_inner(step_timeout)
    }

    fn end_inner(
        &mut self,
        step_timeout: std::time::Duration,
    ) -> Result<(), super::PortReleaseError> {
        if self.ended {
            return Ok(());
        }
        self.ended = true;
        let mode = self.session;
        self.session = super::SessionMode::SignedOut;
        super::end_session(self, mode, step_timeout)
    }
}

impl Drop for ProgrammingDevice<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.end_inner(super::DEFAULT_RELEASE_STEP_TIMEOUT) {
            tracing::error!(error = %e, "programming device release failed");
        }
    }
}

impl Transport for ProgrammingDevice<'_> {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut writer: &File = self.file.file();
        let sent = crate::transport::send_all_port(&mut writer, data, PROGRAMMING_SEND_BOUND_MS);
        if sent.is_ok() {
            self.session = self.session.after_send(data);
        }
        sent
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let mut reader: &File = self.file.file();
        crate::transport::recv_with_poll(&mut reader, timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

impl super::PortRelease for ProgrammingDevice<'_> {
    fn drop_dtr(&mut self) -> Result<(), TransportError> {
        let fd = self.file.file();
        let hangup = termios::tcgetattr(fd).and_then(|mut t| {
            termios::cfsetspeed(&mut t, BaudRate::B0)?;
            termios::tcsetattr(fd, SetArg::TCSANOW, &t)
        });
        hangup.map_err(|e| TransportError::NothingWritten(format!("DTR drop (B0): {e}")))
    }
}
