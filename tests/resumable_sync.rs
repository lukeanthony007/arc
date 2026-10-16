use arc_store::{format, network, store::Store};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    thread,
    time::Duration,
};

struct CutWrite {
    stream: UnixStream,
    remaining: usize,
}
impl Read for CutWrite {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.read(out)
    }
}
impl Write for CutWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected contact interruption",
            ));
        }
        let n = self
            .stream
            .write(&bytes[..bytes.len().min(self.remaining)])?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn streams() -> (UnixStream, UnixStream) {
    let (a, b) = UnixStream::pair().unwrap();
    for s in [&a, &b] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    (a, b)
}
#[test]
fn live_reconnect_reuses_partial_fragments_after_receiver_restart() {
    let t = tempfile::tempdir().unwrap();
    let source = Store::create(&t.path().join("source")).unwrap();
    let dest = Store::create(&t.path().join("dest")).unwrap();
    let bytes: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let id = source.put(&bytes).unwrap();
    let a = [17; 32];
    let b = [23; 32];
    let ap = network::public(&a).unwrap();
    let bp = network::public(&b).unwrap();
    let (left, mut right) = streams();
    thread::scope(|scope| {
        let server = scope.spawn(|| network::sync_stream(&mut right, &dest, &b, &ap, &[], false));
        let mut cut = CutWrite {
            stream: left,
            remaining: 25_000,
        };
        assert!(network::sync_stream(&mut cut, &source, &a, &bp, &[id], true).is_err());
        drop(cut);
        assert!(server.join().unwrap().is_err());
    });
    assert!(!dest.contains(&id).unwrap());
    // Reopen both the store and receiver through a wholly new connection.
    let dest = Store::open(dest.path()).unwrap();
    let (mut left, mut right) = streams();
    thread::scope(|scope| {
        let server = scope.spawn(|| network::sync_stream(&mut right, &dest, &b, &ap, &[], false));
        let report = network::sync_stream(&mut left, &source, &a, &bp, &[id], true).unwrap();
        assert_eq!(report.sent, 1);
        assert!(report.fragments_reused > 0);
        assert!(report.fragments_sent < bytes.len() / 4096);
        assert_eq!(server.join().unwrap().unwrap().received, 1);
    });
    assert_eq!(format::id(&dest.get(&id).unwrap()), id);
    assert_eq!(dest.get(&id).unwrap(), bytes);
}
