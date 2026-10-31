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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    #[error("TIOCEXCL: {0}")]
    Exclusive(Errno),
    #[error("a programming open needs this PortManager's held programming lease")]
    NoLease,
    #[error("termios not applied: {0}")]
    TermiosNotApplied(TermiosMismatch),
}

pub(crate) struct SmdrDevice {
    file: Flock<File>,
    options: SmdrLineOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    ReadOnly,
    ReadWrite,
}

pub(crate) enum Exclusion<'held> {
    Own,
    UnderHeld(&'held File),
}

pub(crate) enum OpenedPort {
    Own(Flock<File>),
    UnderHeld(File),
}

impl OpenedPort {
    fn file(&self) -> &File {
        match self {
            Self::Own(f) => f,
            Self::UnderHeld(f) => f,
        }
    }
}

fn open_raw(path: &Path, access: Access) -> Result<File, DeviceError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(access == Access::ReadWrite)
        .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(nix::libc::EBUSY) {
                DeviceError::Locked
            } else {
                DeviceError::Open(e)
            }
        })
}

fn set_tiocexcl(file: &File) -> Result<(), DeviceError> {
    rustix::termios::ioctl_tiocexcl(file)
        .map_err(|e| DeviceError::Exclusive(Errno::from_raw(e.raw_os_error())))
}

pub(crate) fn open_exclusive(
    path: &Path,
    access: Access,
    exclusion: Exclusion<'_>,
    options: SmdrLineOptions,
) -> Result<OpenedPort, DeviceError> {
    let port = match exclusion {
        Exclusion::Own => {
            let file = open_raw(path, access)?;
            let locked = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
                if e == Errno::EWOULDBLOCK {
                    DeviceError::Locked
                } else {
                    DeviceError::Flock(e)
                }
            })?;
            OpenedPort::Own(locked)
        }
        Exclusion::UnderHeld(held) => {
            rustix::termios::ioctl_tiocnxcl(held)
                .map_err(|e| DeviceError::Exclusive(Errno::from_raw(e.raw_os_error())))?;
            let opened = open_raw(path, access);
            set_tiocexcl(held)?;
            OpenedPort::UnderHeld(opened?)
        }
    };
    let file = port.file();
    if !nix::unistd::isatty(file.as_raw_fd()).map_err(DeviceError::Isatty)? {
        return Err(DeviceError::NotATty);
    }
    set_tiocexcl(file)?;
    let mut t = termios::tcgetattr(file).map_err(DeviceError::Termios)?;
    apply_smdr_termios(&mut t, options)?;
    termios::tcsetattr(file, SetArg::TCSANOW, &t).map_err(DeviceError::Termios)?;
    verify_smdr_termios(
        &termios::tcgetattr(file).map_err(DeviceError::Termios)?,
        options,
    )?;
    Ok(port)
}

impl SmdrDevice {
    pub(crate) fn open(path: &Path, options: SmdrLineOptions) -> Result<Self, DeviceError> {
        match open_exclusive(path, Access::ReadOnly, Exclusion::Own, options)? {
            OpenedPort::Own(file) => Ok(Self { file, options }),
            OpenedPort::UnderHeld(_) => Err(DeviceError::Locked),
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermiosMismatch {
    StillSet(&'static str),
    Missing(&'static str),
    WrongSpeed {
        which: &'static str,
        got: BaudRate,
        expected: BaudRate,
    },
}

impl TermiosMismatch {
    pub fn name(&self) -> &'static str {
        match self {
            Self::StillSet(n) | Self::Missing(n) => n,
            Self::WrongSpeed { which, .. } => which,
        }
    }
}

impl std::fmt::Display for TermiosMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StillSet(n) => write!(f, "{n} is set but must be cleared"),
            Self::Missing(n) => write!(f, "{n} is cleared but must be set"),
            Self::WrongSpeed {
                which,
                got,
                expected,
            } => write!(f, "{which} reads back as {got:?}, expected {expected:?}"),
        }
    }
}

pub const REQUIRED_CONTROL_FLAGS: [(&str, ControlFlags); 3] = [
    ("CS8", ControlFlags::CS8),
    ("CREAD", ControlFlags::CREAD),
    ("CLOCAL", ControlFlags::CLOCAL),
];

fn verify_smdr_termios(t: &Termios, options: SmdrLineOptions) -> Result<(), DeviceError> {
    for (name, flag) in CLEARED_INPUT_FLAGS {
        if t.input_flags.contains(flag) {
            return Err(DeviceError::TermiosNotApplied(TermiosMismatch::StillSet(
                name,
            )));
        }
    }
    for (name, flag) in CLEARED_LOCAL_FLAGS {
        if t.local_flags.contains(flag) {
            return Err(DeviceError::TermiosNotApplied(TermiosMismatch::StillSet(
                name,
            )));
        }
    }
    match (
        t.control_flags.contains(ControlFlags::CRTSCTS),
        options.rtscts,
    ) {
        (true, false) => {
            return Err(DeviceError::TermiosNotApplied(TermiosMismatch::StillSet(
                "CRTSCTS",
            )))
        }
        (false, true) => {
            return Err(DeviceError::TermiosNotApplied(TermiosMismatch::Missing(
                "CRTSCTS",
            )))
        }
        (true, true) | (false, false) => {}
    }
    for (name, flag) in REQUIRED_CONTROL_FLAGS {
        if !t.control_flags.contains(flag) {
            return Err(DeviceError::TermiosNotApplied(TermiosMismatch::Missing(
                name,
            )));
        }
    }
    for (which, got) in [
        ("ospeed", termios::cfgetospeed(t)),
        ("ispeed", termios::cfgetispeed(t)),
    ] {
        if got != SMDR_BAUD {
            return Err(DeviceError::TermiosNotApplied(
                TermiosMismatch::WrongSpeed {
                    which,
                    got,
                    expected: SMDR_BAUD,
                },
            ));
        }
    }
    Ok(())
}

pub struct SmdrDeviceHandle {
    device: Arc<Mutex<SmdrDevice>>,
    leased: Arc<AtomicBool>,
    lease_epoch: Arc<AtomicU64>,
    configured_epoch: u64,
    resume_guard: Arc<Mutex<()>>,
    #[cfg(feature = "test-util")]
    readback_hook: Option<ReadbackHook>,
    #[cfg(feature = "test-util")]
    pre_read_hook: Option<PreReadHook>,
    #[cfg(feature = "test-util")]
    in_read_hook: Option<PreReadHook>,
}

#[cfg(feature = "test-util")]
pub type PreReadHook = Box<dyn FnMut() + Send>;

pub const SMDR_READ_SLICE_MS: u64 = 50;

pub fn read_slice_ms(remaining: std::time::Duration) -> Option<u64> {
    if remaining.is_zero() {
        return None;
    }
    if remaining >= SMDR_READ_SLICE {
        return Some(SMDR_READ_SLICE_MS);
    }
    Some(
        u64::from(remaining.subsec_micros())
            .div_ceil(1000)
            .clamp(1, SMDR_READ_SLICE_MS),
    )
}
const SMDR_READ_SLICE: std::time::Duration = std::time::Duration::from_millis(SMDR_READ_SLICE_MS);

#[cfg(feature = "test-util")]
pub type ReadbackHook = Box<dyn FnMut(&mut Termios) + Send>;

impl SmdrDeviceHandle {
    pub(crate) fn new(
        device: Arc<Mutex<SmdrDevice>>,
        leased: Arc<AtomicBool>,
        lease_epoch: Arc<AtomicU64>,
        resume_guard: Arc<Mutex<()>>,
    ) -> Self {
        let configured_epoch = lease_epoch.load(Ordering::SeqCst);
        Self {
            device,
            leased,
            lease_epoch,
            configured_epoch,
            resume_guard,
            #[cfg(feature = "test-util")]
            readback_hook: None,
            #[cfg(feature = "test-util")]
            pre_read_hook: None,
            #[cfg(feature = "test-util")]
            in_read_hook: None,
        }
    }

    #[cfg(feature = "test-util")]
    pub fn set_resume_readback_hook(&mut self, hook: ReadbackHook) {
        self.readback_hook = Some(hook);
    }

    #[cfg(feature = "test-util")]
    pub fn set_pre_read_hook(&mut self, hook: PreReadHook) {
        self.pre_read_hook = Some(hook);
    }

    #[cfg(feature = "test-util")]
    pub fn set_in_read_hook(&mut self, hook: PreReadHook) {
        self.in_read_hook = Some(hook);
    }

    pub fn resume_after_lease(&mut self) -> Result<bool, DeviceError> {
        let guard = Arc::clone(&self.resume_guard);
        let _resume = guard.lock().unwrap_or_else(super::recover_from_poison);
        if self.leased.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.reapply_if_leased_since()?;
        Ok(true)
    }

    fn reapply_if_leased_since(&mut self) -> Result<(), DeviceError> {
        let epoch = self.lease_epoch.load(Ordering::SeqCst);
        if epoch == self.configured_epoch {
            return Ok(());
        }
        let device = self.lock();
        let file: &File = &device.file;
        let mut t = termios::tcgetattr(file).map_err(DeviceError::Termios)?;
        apply_smdr_termios(&mut t, device.options)?;
        termios::tcsetattr(file, SetArg::TCSANOW, &t).map_err(DeviceError::Termios)?;
        let options = device.options;
        #[cfg_attr(
            not(feature = "test-util"),
            allow(
                unused_mut,
                reason = "only the test-util readback hook mutates the readback"
            )
        )]
        let mut back = termios::tcgetattr(file).map_err(DeviceError::Termios)?;
        drop(device);
        #[cfg(feature = "test-util")]
        if let Some(hook) = self.readback_hook.as_mut() {
            hook(&mut back);
        }
        verify_smdr_termios(&back, options)?;
        self.configured_epoch = epoch;
        Ok(())
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let Some(slice_ms) = read_slice_ms(remaining) else {
                return Err(TransportError::Timeout);
            };
            let resumed = self.resume_after_lease().map_err(|e| {
                TransportError::LinkDown(kxtd1232::LinkDownError {
                    detail: format!("SMDR line settings not restored after a lease: {e}"),
                    bytes_sent: None,
                })
            })?;
            if resumed {
                #[cfg(feature = "test-util")]
                if let Some(hook) = self.pre_read_hook.as_mut() {
                    hook();
                }
                let port = Arc::clone(&self.device);
                let device = port.lock().unwrap_or_else(super::recover_from_poison);
                let unchanged = self.lease_epoch.load(Ordering::SeqCst) == self.configured_epoch;
                if !self.leased.load(Ordering::SeqCst) && unchanged {
                    let mut reader: &File = &device.file;
                    let read = crate::transport::recv_with_poll(&mut reader, slice_ms);
                    #[cfg(feature = "test-util")]
                    if let Some(hook) = self.in_read_hook.as_mut() {
                        hook();
                    }
                    drop(device);
                    return read;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(slice_ms));
        }
    }
}

pub(crate) enum FlockCover {
    HeldBySmdr(Arc<Mutex<SmdrDevice>>),
    Own,
}

pub struct ProgrammingLine {
    file: OpenedPort,
    _smdr: Option<Arc<Mutex<SmdrDevice>>>,
    session: super::SessionMode,
    ended: bool,
    send_bound_ms: u64,
    #[cfg(feature = "test-util")]
    restore_readback_hook: Option<ReadbackHook>,
}

impl ProgrammingLine {
    pub(crate) fn open(
        path: &Path,
        options: SmdrLineOptions,
        cover: FlockCover,
        send_bound_ms: u64,
    ) -> Result<Self, DeviceError> {
        let (file, smdr) = match cover {
            FlockCover::HeldBySmdr(smdr) => {
                let opened = {
                    let held = smdr.lock().unwrap_or_else(super::recover_from_poison);
                    open_exclusive(
                        path,
                        Access::ReadWrite,
                        Exclusion::UnderHeld(&held.file),
                        options,
                    )?
                };
                (opened, Some(smdr))
            }
            FlockCover::Own => (
                open_exclusive(path, Access::ReadWrite, Exclusion::Own, options)?,
                None,
            ),
        };
        Ok(Self {
            file,
            _smdr: smdr,
            session: super::SessionMode::SignedOut,
            ended: false,
            send_bound_ms,
            #[cfg(feature = "test-util")]
            restore_readback_hook: None,
        })
    }

    #[cfg(feature = "test-util")]
    pub fn set_restore_readback_hook(&mut self, hook: ReadbackHook) {
        self.restore_readback_hook = Some(hook);
    }

    pub fn holds_own_flock(&self) -> bool {
        matches!(self.file, OpenedPort::Own(_))
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

    fn hangup_flush_restore(&mut self) -> Result<(), super::DtrError> {
        hang_up_then_restore(self, super::DTR_LOW_PERIOD)
    }
}

pub(crate) trait HangupLine {
    fn hang_up(&mut self) -> Result<(), super::DtrError>;
    fn flush_input(&mut self) -> Result<(), super::DtrError>;
    fn restore_speed(&mut self) -> Result<(), super::DtrError>;
}

pub(crate) fn hang_up_then_restore<L: HangupLine>(
    line: &mut L,
    low_period: std::time::Duration,
) -> Result<(), super::DtrError> {
    line.hang_up()?;
    std::thread::sleep(low_period);
    line.flush_input()?;
    line.restore_speed()
}

impl HangupLine for ProgrammingLine {
    fn hang_up(&mut self) -> Result<(), super::DtrError> {
        let fd = self.file.file();
        let mut t = termios::tcgetattr(fd).map_err(|e| super::DtrError::Hangup(e.to_string()))?;
        termios::cfsetspeed(&mut t, BaudRate::B0)
            .and_then(|()| termios::tcsetattr(fd, SetArg::TCSANOW, &t))
            .map_err(|e| super::DtrError::Hangup(e.to_string()))
    }

    fn flush_input(&mut self) -> Result<(), super::DtrError> {
        termios::tcflush(self.file.file(), termios::FlushArg::TCIFLUSH)
            .map_err(|e| super::DtrError::Flush(e.to_string()))
    }

    fn restore_speed(&mut self) -> Result<(), super::DtrError> {
        #[cfg(feature = "test-util")]
        let hook = self.restore_readback_hook.as_mut();
        #[cfg(not(feature = "test-util"))]
        let hook: Option<&mut ReadbackHook> = None;
        restore_line_speed(self.file.file(), hook)
    }
}

impl Drop for ProgrammingLine {
    fn drop(&mut self) {
        if let Err(e) = self.end_inner(super::DEFAULT_RELEASE_STEP_TIMEOUT) {
            tracing::error!(error = %e, "programming device release failed");
        }
        if let OpenedPort::Own(file) = &self.file {
            if let Err(e) = rustix::termios::ioctl_tiocnxcl(&**file) {
                tracing::error!(error = %e, "clearing TIOCEXCL on the programming close failed");
            }
        }
    }
}

impl Transport for ProgrammingLine {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut writer: &File = self.file.file();
        let sent = crate::transport::send_all_port(&mut writer, data, self.send_bound_ms);
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

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.hangup_flush_restore().map_err(|e| {
            TransportError::LinkDown(kxtd1232::LinkDownError {
                detail: format!("serial: DTR cycle: {e}"),
                bytes_sent: Some(0),
            })
        })?;
        Ok(true)
    }
}

impl super::PortRelease for ProgrammingLine {
    fn drop_dtr(&mut self) -> Result<(), super::DtrError> {
        self.hangup_flush_restore()
    }
}

pub struct ProgrammingDevice<'lease> {
    line: ProgrammingLine,
    _lease: PhantomData<&'lease ()>,
}

impl ProgrammingDevice<'_> {
    pub(crate) fn new(line: ProgrammingLine) -> Self {
        Self {
            line,
            _lease: PhantomData,
        }
    }

    #[cfg(feature = "test-util")]
    pub fn set_restore_readback_hook(&mut self, hook: ReadbackHook) {
        self.line.set_restore_readback_hook(hook);
    }

    pub fn holds_own_flock(&self) -> bool {
        self.line.holds_own_flock()
    }

    pub fn session_mode(&self) -> super::SessionMode {
        self.line.session_mode()
    }

    pub fn end(self, step_timeout: std::time::Duration) -> Result<(), super::PortReleaseError> {
        self.line.end(step_timeout)
    }
}

impl Transport for ProgrammingDevice<'_> {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.line.send(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.line.recv(timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        self.line.now_ms()
    }

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.line.cycle_dtr()
    }
}

impl super::PortRelease for ProgrammingDevice<'_> {
    fn drop_dtr(&mut self) -> Result<(), super::DtrError> {
        self.line.drop_dtr()
    }
}

pub struct LeasedDevice {
    line: ProgrammingLine,
    lease: super::ProgrammingLease<()>,
}

impl LeasedDevice {
    pub(crate) fn new(line: ProgrammingLine, lease: super::ProgrammingLease<()>) -> Self {
        Self { line, lease }
    }

    #[cfg(feature = "test-util")]
    pub fn set_restore_readback_hook(&mut self, hook: ReadbackHook) {
        self.line.set_restore_readback_hook(hook);
    }

    pub fn job_id(&self) -> &str {
        self.lease.job_id()
    }

    pub fn holds_own_flock(&self) -> bool {
        self.line.holds_own_flock()
    }

    pub fn session_mode(&self) -> super::SessionMode {
        self.line.session_mode()
    }

    pub fn end(self, step_timeout: std::time::Duration) -> Result<(), super::PortReleaseError> {
        let Self { line, lease } = self;
        let ended = line.end(step_timeout);
        let released = lease.release();
        ended.and(released)
    }
}

impl Transport for LeasedDevice {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.line.send(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.line.recv(timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        self.line.now_ms()
    }

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.line.cycle_dtr()
    }
}

#[cfg(not(feature = "test-util"))]
type ReadbackHook = std::convert::Infallible;

#[cfg(feature = "test-util")]
fn apply_readback_hook(hook: Option<&mut ReadbackHook>, t: &mut Termios) {
    if let Some(hook) = hook {
        hook(t);
    }
}

#[cfg(not(feature = "test-util"))]
fn apply_readback_hook(hook: Option<&mut ReadbackHook>, _t: &mut Termios) {
    if let Some(never) = hook {
        match *never {}
    }
}

fn restore_line_speed(fd: &File, hook: Option<&mut ReadbackHook>) -> Result<(), super::DtrError> {
    let mut t = termios::tcgetattr(fd).map_err(|e| super::DtrError::Restore(e.to_string()))?;
    termios::cfsetspeed(&mut t, SMDR_BAUD)
        .and_then(|()| termios::tcsetattr(fd, SetArg::TCSANOW, &t))
        .map_err(|e| super::DtrError::Restore(e.to_string()))?;
    let mut back = termios::tcgetattr(fd).map_err(|e| super::DtrError::Restore(e.to_string()))?;
    apply_readback_hook(hook, &mut back);
    let (ispeed, ospeed) = (termios::cfgetispeed(&back), termios::cfgetospeed(&back));
    if ispeed != SMDR_BAUD || ospeed != SMDR_BAUD {
        return Err(super::DtrError::SpeedMismatch {
            expected: format!("{SMDR_BAUD:?}"),
            got: format!("in {ispeed:?} / out {ospeed:?}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hang_up_then_restore, read_slice_ms, HangupLine, SMDR_READ_SLICE_MS};
    use crate::port::DtrError;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingLine {
        ops: Vec<&'static str>,
        fail_flush: bool,
    }

    impl HangupLine for RecordingLine {
        fn hang_up(&mut self) -> Result<(), DtrError> {
            self.ops.push("b0_dtr_low");
            Ok(())
        }

        fn flush_input(&mut self) -> Result<(), DtrError> {
            self.ops.push("tciflush");
            if self.fail_flush {
                return Err(DtrError::Flush("flush failed".into()));
            }
            Ok(())
        }

        fn restore_speed(&mut self) -> Result<(), DtrError> {
            self.ops.push("9600_dtr_high");
            Ok(())
        }
    }

    #[test]
    fn hangup_flushes_input_before_dtr_rises() {
        let mut line = RecordingLine::default();
        assert!(hang_up_then_restore(&mut line, Duration::ZERO).is_ok());
        assert_eq!(line.ops, ["b0_dtr_low", "tciflush", "9600_dtr_high"]);
    }

    #[test]
    fn a_failed_flush_leaves_dtr_low() {
        let mut line = RecordingLine {
            fail_flush: true,
            ..RecordingLine::default()
        };
        assert!(matches!(
            hang_up_then_restore(&mut line, Duration::ZERO),
            Err(DtrError::Flush(_))
        ));
        assert_eq!(line.ops, ["b0_dtr_low", "tciflush"]);
    }

    #[test]
    fn read_slice_rounds_up_and_clamps() {
        assert_eq!(read_slice_ms(Duration::ZERO), None);
        assert_eq!(read_slice_ms(Duration::from_micros(500)), Some(1));
        assert_eq!(read_slice_ms(Duration::from_micros(49_900)), Some(50));
        assert_eq!(
            read_slice_ms(Duration::from_millis(50)),
            Some(SMDR_READ_SLICE_MS)
        );
        assert_eq!(
            read_slice_ms(Duration::from_secs(3)),
            Some(SMDR_READ_SLICE_MS)
        );
        assert_eq!(read_slice_ms(Duration::from_nanos(1)), Some(1));
        assert_eq!(read_slice_ms(Duration::from_micros(10_001)), Some(11));
    }
}
