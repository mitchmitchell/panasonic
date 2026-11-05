//! Kernel tty helpers for kxprovd. This crate may use `unsafe`; kxprovd itself does not.

#[cfg(kxprovd_sys_has_tiocmget)]
mod tiocmget;

#[cfg(kxprovd_sys_has_tiocmget)]
pub use tiocmget::read_cts;
