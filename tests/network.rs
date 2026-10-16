use arc_store::{
    constrained::{self, Link},
    store::Store,
};
use std::os::unix::fs::PermissionsExt;
fn node(root: &tempfile::TempDir) -> Store {
    Store::create(&root.path().join("node")).unwrap()
}
#[test]
fn authenticated_loopback_sync_is_bidirectional_and_idempotent() {
    use snow::Builder;
    use std::{net::TcpListener, thread};
    let p: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let ka = Builder::new(p.clone()).generate_keypair().unwrap();
    let kb = Builder::new(p).generate_keypair().unwrap();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let sa = std::sync::Arc::new(node(&a));
    let sb = std::sync::Arc::new(node(&b));
    let ida = sa.put(&vec![b'l'; 200_000]).unwrap();
    let idb = sb.put(b"right").unwrap();
    let mut aids = vec![ida];
    let mut bids = vec![idb];
    for i in 0u32..2050 {
        let bytes = i.to_be_bytes();
        let x = sa.put(&bytes).unwrap();
        assert_eq!(sb.put(&bytes).unwrap(), x);
        aids.push(x);
        bids.push(x);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = sb.clone();
    let sk = kb.private.clone();
    let pk = ka.public.clone();
    let server_ids = bids.clone();
    let server = thread::spawn(move || {
        arc_store::network::serve_once(&listener, &srv, &sk, &pk, &server_ids).unwrap()
    });
    let c = arc_store::network::sync_client(addr, &sa, &ka.private, &kb.public, &aids).unwrap();
    let s = server.join().unwrap();
    assert_eq!((c.sent, c.received), (1, 1));
    assert_eq!((s.sent, s.received), (1, 1));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = sb.clone();
    let sk = kb.private.clone();
    let pk = ka.public.clone();
    let server_ids = bids.clone();
    let client_ids = aids.clone();
    let server = thread::spawn(move || {
        arc_store::network::serve_once(&listener, &srv, &sk, &pk, &server_ids).unwrap()
    });
    let c =
        arc_store::network::sync_client(addr, &sa, &ka.private, &kb.public, &client_ids).unwrap();
    let s = server.join().unwrap();
    assert_eq!(c.received, 0);
    assert_eq!(s.received, 0);
}
#[test]
fn network_rejects_mismatched_pinned_key() {
    use snow::Builder;
    use std::{net::TcpListener, thread};
    let p: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let akey = Builder::new(p.clone()).generate_keypair().unwrap();
    let bkey = Builder::new(p.clone()).generate_keypair().unwrap();
    let wrong = Builder::new(p).generate_keypair().unwrap();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let sa = node(&a);
    let sb = node(&b);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        arc_store::network::serve_once(&listener, &sb, &bkey.private, &akey.public, &[])
    });
    assert!(arc_store::network::sync_client(addr, &sa, &akey.private, &wrong.public, &[]).is_err());
    assert!(server.join().unwrap().is_err());
}
#[test]
fn constrained_transfer_rejects_loss_then_resumes_from_ids() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let src = node(&a);
    let dst = node(&b);
    let id = src.put(&vec![7u8; 4096]).unwrap();
    let lossy = Link {
        mtu: 128,
        drop_every: 3,
        reorder_window: 4,
        duplicate_every: 2,
        corrupt_every: 0,
        interrupt_after: None,
    };
    let r = constrained::transfer(&src, &dst, &[id], &lossy).unwrap();
    assert_eq!(r.objects_received, 0);
    assert!(!dst.contains(&id).unwrap());
    let clean = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 5,
        duplicate_every: 3,
        corrupt_every: 0,
        interrupt_after: None,
    };
    assert_eq!(
        constrained::transfer(&src, &dst, &[id], &clean)
            .unwrap()
            .objects_received,
        1
    );
    assert_eq!(dst.get(&id).unwrap(), src.get(&id).unwrap());
    assert_eq!(
        constrained::transfer(&src, &dst, &[id], &clean)
            .unwrap()
            .resumed_objects,
        1
    );
}
#[test]
fn constrained_interrupt_does_not_publish_partial_objects() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let src = node(&a);
    let dst = node(&b);
    let id = src.put(&vec![3u8; 2048]).unwrap();
    let link = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 0,
        duplicate_every: 0,
        corrupt_every: 0,
        interrupt_after: Some(2),
    };
    assert_eq!(
        constrained::transfer(&src, &dst, &[id], &link)
            .unwrap()
            .objects_received,
        0
    );
    assert!(!dst.contains(&id).unwrap());
    let clean = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 0,
        duplicate_every: 0,
        corrupt_every: 0,
        interrupt_after: None,
    };
    assert_eq!(
        constrained::transfer(&src, &dst, &[id], &clean)
            .unwrap()
            .objects_received,
        1
    );
}
#[test]
fn constrained_corruption_never_publishes_and_bundle_mixed_resume() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let src = node(&a);
    let dst = node(&b);
    let first = src.put(&vec![1u8; 1024]).unwrap();
    let second = src.put(&vec![2u8; 1024]).unwrap();
    let corrupt = Link {
        mtu: 64,
        drop_every: 0,
        reorder_window: 3,
        duplicate_every: 0,
        corrupt_every: 2,
        interrupt_after: None,
    };
    assert_eq!(
        constrained::transfer(&src, &dst, &[first], &corrupt)
            .unwrap()
            .objects_received,
        0
    );
    assert!(!dst.contains(&first).unwrap());
    let bundle = a.path().join("part.arc");
    arc_store::bundle::export(&src, &[second], &bundle).unwrap();
    arc_store::bundle::import(&dst, &bundle).unwrap();
    let clean = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 2,
        duplicate_every: 2,
        corrupt_every: 0,
        interrupt_after: None,
    };
    let r = constrained::transfer(&src, &dst, &[first, second], &clean).unwrap();
    assert_eq!(r.objects_received, 1);
    assert_eq!(r.resumed_objects, 1);
}
#[test]
fn encrypted_identity_round_trips_and_rejects_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("noise.key");
    let public = arc_store::network::identity_create(&p, "secret passphrase").unwrap();
    let secret = arc_store::network::identity_load(&p, "secret passphrase").unwrap();
    assert_eq!(arc_store::network::public(&*secret).unwrap(), public);
    assert!(arc_store::network::identity_load(&p, "wrong").is_err());
    assert_eq!(
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
