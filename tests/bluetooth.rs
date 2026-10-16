use arc_store::{network, store::Store};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    thread,
};

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::create(&dir.path().join("store")).unwrap();
    (dir, store)
}

#[test]
fn authenticated_duplex_exchange_over_stream_socketpair() {
    let (_left_dir, left_store) = store();
    let (_right_dir, right_store) = store();
    let payload = vec![0x5a; 256 * 1024];
    let id = left_store.put(&payload).unwrap();
    let left_secret = [17u8; 32];
    let right_secret = [29u8; 32];
    let left_public = network::public(&left_secret).unwrap();
    let right_public = network::public(&right_secret).unwrap();
    let (mut left, mut right) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        network::sync_stream(
            &mut right,
            &right_store,
            &right_secret,
            &left_public,
            &[],
            false,
        )
    });
    let report = network::sync_stream(
        &mut left,
        &left_store,
        &left_secret,
        &right_public,
        &[id],
        true,
    )
    .unwrap();
    server.join().unwrap().unwrap();
    assert_eq!(report.sent, 1);
    assert_eq!(report.received, 0);
}

#[test]
fn stream_peer_pin_mismatch_is_rejected() {
    let (_left_dir, left_store) = store();
    let (_right_dir, right_store) = store();
    let left_secret = [31u8; 32];
    let right_secret = [47u8; 32];
    let (mut left, mut right) = UnixStream::pair().unwrap();
    let wrong_pin = [0u8; 32];
    let server = thread::spawn(move || {
        network::sync_stream(
            &mut right,
            &right_store,
            &right_secret,
            &network::public(&left_secret).unwrap(),
            &[],
            false,
        )
    });
    let result = network::sync_stream(&mut left, &left_store, &left_secret, &wrong_pin, &[], true);
    assert!(result.is_err());
    drop(left);
    let _ = server.join();
}

#[test]
fn explicit_endpoint_rejects_non_rfcomm_paths() {
    let dir = tempfile::tempdir().unwrap();
    let ordinary_file = dir.path().join("rfcomm0");
    std::fs::write(&ordinary_file, b"not a device").unwrap();
    let (_store_dir, store) = store();
    let result = arc_store::bluetooth::connect(&ordinary_file, &store, &[1; 32], &[2; 32], &[]);
    assert!(result.is_err());
}

#[test]
fn stream_io_timeout_propagates() {
    struct TimedOut;
    impl Read for TimedOut {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "deliberate stalled peer",
            ))
        }
    }
    impl Write for TimedOut {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_dir, store) = store();
    let result = network::sync_stream(&mut TimedOut, &store, &[1; 32], &[2; 32], &[], true);
    assert_eq!(
        result
            .unwrap_err()
            .downcast::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}
