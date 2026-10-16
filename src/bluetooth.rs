//! Explicit Linux RFCOMM character-device transport. The kernel connection must already exist.
use crate::{
    format::Id,
    network::{self, SyncReport},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(20);

/// Opens one explicitly named `/dev/rfcommN` endpoint and performs the Noise initiator exchange.
pub fn connect(
    path: &Path,
    store: &Store,
    secret: &[u8],
    pinned_peer: &[u8],
    ids: &[Id],
) -> Result<SyncReport> {
    let mut endpoint = Endpoint::open(path)?;
    network::sync_stream(&mut endpoint, store, secret, pinned_peer, ids, true)
}
/// Opens one explicitly named `/dev/rfcommN` endpoint and performs the Noise responder exchange.
pub fn accept(
    path: &Path,
    store: &Store,
    secret: &[u8],
    pinned_peer: &[u8],
    ids: &[Id],
) -> Result<SyncReport> {
    let mut endpoint = Endpoint::open(path)?;
    network::sync_stream(&mut endpoint, store, secret, pinned_peer, ids, false)
}

pub struct Endpoint {
    file: File,
    original_termios: libc::termios,
    deadline: Instant,
}
impl Endpoint {
    pub fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid RFCOMM endpoint")?;
        ensure!(
            name.strip_prefix("rfcomm")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
            "endpoint must be /dev/rfcommN"
        );
        ensure!(
            path.parent() == Some(Path::new("/dev")),
            "endpoint must be directly under /dev"
        );
        let metadata = std::fs::symlink_metadata(path).context("RFCOMM endpoint unavailable")?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.file_type().is_char_device(),
            "RFCOMM endpoint must be a character device (not a symlink)"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::NOCTTY)
                    .bits() as i32,
            )
            .open(path)
            .context("opening RFCOMM endpoint")?;
        let opened = file.metadata()?;
        ensure!(
            opened.file_type().is_char_device() && opened.rdev() == metadata.rdev(),
            "RFCOMM endpoint changed during open"
        );
        Self::configure(file, TIMEOUT)
    }
    fn configure(file: File, timeout: Duration) -> Result<Self> {
        file.try_lock()
            .context("another Arc process is using this endpoint")?;
        let fd = file.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        ensure!(
            unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
            "RFCOMM endpoint is not a configurable terminal"
        );
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        ensure!(
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } == 0,
            "configuring raw RFCOMM terminal"
        );
        Ok(Self {
            file,
            original_termios: original,
            deadline: Instant::now() + timeout,
        })
    }
    fn wait(&self, events: i16) -> std::io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RFCOMM session timed out",
            ));
        }
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pfd, 1, millis) };
        if result == 0 || Instant::now() >= self.deadline {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RFCOMM session timed out",
            ))
        } else if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original_termios);
        }
    }
}
impl Read for Endpoint {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLIN)?;
            match self.file.read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }
}
impl Write for Endpoint {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLOUT)?;
            match self.file.write(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    fn pty() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        // Fresh anonymous test terminals; no desktop or user's terminal is accessed.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for file in [&master, &slave] {
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        (master, slave)
    }
    fn attributes(file: &File) -> libc::termios {
        let mut value = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
            0
        );
        unsafe { value.assume_init() }
    }
    #[test]
    fn raw_pty_session_has_absolute_deadline_and_restores_terminal() {
        let (_master, slave) = pty();
        let observer = slave.try_clone().unwrap();
        let original = attributes(&observer);
        let mut endpoint = Endpoint::configure(slave, Duration::from_millis(50)).unwrap();
        assert_eq!(
            attributes(&observer).c_lflag & (libc::ICANON | libc::ECHO),
            0
        );
        let before = Instant::now();
        assert_eq!(
            endpoint.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(before.elapsed() < Duration::from_secs(2));
        assert_eq!(
            endpoint.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(endpoint);
        let restored = attributes(&observer);
        assert_eq!(
            (
                restored.c_iflag,
                restored.c_oflag,
                restored.c_lflag,
                restored.c_cflag,
                restored.c_cc
            ),
            (
                original.c_iflag,
                original.c_oflag,
                original.c_lflag,
                original.c_cflag,
                original.c_cc
            )
        );
    }
    #[test]
    fn binary_bytes_cross_raw_pty_without_line_translation() {
        let (mut master, slave) = pty();
        let mut endpoint = Endpoint::configure(slave, Duration::from_secs(2)).unwrap();
        let bytes = b"\0\r\n\xff";
        master.write_all(bytes).unwrap();
        let mut read = [0; 4];
        endpoint.read_exact(&mut read).unwrap();
        assert_eq!(&read, bytes);
    }
}
