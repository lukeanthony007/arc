use arc_store::{
    constrained::{self, Link},
    format,
    fragments::{MAX_PARTIALS, MAX_STAGED, Receiver},
    store::Store,
};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, symlink},
};

#[test]
fn fragments_survive_restart_reordering_and_duplicates() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::create(&t.path().join("node")).unwrap();
    let bytes = b"abcdefghijkl";
    let id = format::id(bytes);
    let root = store.path().join("incoming");
    let mut r = Receiver::open(&root).unwrap();
    assert!(!r.accept(&id, 12, 4, 2, &bytes[8..]).unwrap());
    assert!(!r.accept(&id, 12, 4, 0, &bytes[..4]).unwrap());
    assert!(!r.accept(&id, 12, 4, 0, &bytes[..4]).unwrap());
    drop(r);
    let mut r = Receiver::open(&root).unwrap();
    assert_eq!(r.missing(&id, 12, 4).unwrap(), vec![1]);
    assert!(r.accept(&id, 12, 4, 1, &bytes[4..8]).unwrap());
    assert_eq!(store.get(&id).unwrap(), bytes);
}
#[test]
fn contacts_too_short_for_one_object_eventually_complete() {
    let t = tempfile::tempdir().unwrap();
    let source = Store::create(&t.path().join("source")).unwrap();
    let dest = Store::create(&t.path().join("dest")).unwrap();
    let id = source.put(&vec![7; 4096]).unwrap();
    let link = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 4,
        duplicate_every: 2,
        corrupt_every: 0,
        interrupt_after: Some(2),
    };
    let mut sent = 0;
    for contact in 0..16 {
        let report = constrained::transfer(&source, &dest, &[id], &link).unwrap();
        sent += report.fragments_sent;
        assert_eq!(dest.contains(&id).unwrap(), contact == 15);
    }
    assert_eq!(sent, 32);
    assert_eq!(dest.get(&id).unwrap(), source.get(&id).unwrap());
}
#[test]
fn corruption_is_never_published_and_clean_retry_recovers() {
    let t = tempfile::tempdir().unwrap();
    let source = Store::create(&t.path().join("source")).unwrap();
    let dest = Store::create(&t.path().join("dest")).unwrap();
    let id = source.put(&vec![8; 1024]).unwrap();
    let bad = Link {
        mtu: 128,
        drop_every: 0,
        reorder_window: 5,
        duplicate_every: 2,
        corrupt_every: 3,
        interrupt_after: None,
    };
    constrained::transfer(&source, &dest, &[id], &bad).unwrap();
    assert!(!dest.contains(&id).unwrap());
    let clean = Link {
        corrupt_every: 0,
        ..bad
    };
    constrained::transfer(&source, &dest, &[id], &clean).unwrap();
    assert_eq!(dest.get(&id).unwrap(), source.get(&id).unwrap());
}
#[test]
fn fragment_lock_and_conflicting_metadata_preserve_state() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::create(&t.path().join("node")).unwrap();
    let root = store.path().join("incoming");
    let mut r = Receiver::open(&root).unwrap();
    assert!(Receiver::open(&root).is_err());
    let id = format::id(b"abcdefgh");
    r.accept(&id, 8, 4, 0, b"abcd").unwrap();
    assert!(r.accept(&id, 9, 4, 1, b"efgh").is_err());
    assert!(r.missing(&id, 8, 2).is_err());
    assert_eq!(r.missing(&id, 8, 4).unwrap(), vec![1]);
    r.discard(&id).unwrap();
    assert_eq!(r.missing(&id, 8, 2).unwrap(), vec![0, 1, 2, 3]);
}
#[test]
fn disk_payload_damage_becomes_missing_and_symlinks_are_refused() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::create(&t.path().join("node")).unwrap();
    let root = store.path().join("incoming");
    let mut r = Receiver::open(&root).unwrap();
    let data = [22; 64];
    let id = format::id(&data);
    r.accept(&id, 64, 32, 0, &data[..32]).unwrap();
    let partial = root.join("fragments").join(hex::encode(id));
    let mut raw = fs::read(&partial).unwrap();
    let offset = raw.windows(32).position(|b| b == [22; 32]).unwrap();
    raw[offset] ^= 1;
    fs::write(&partial, raw).unwrap();
    assert_eq!(r.missing(&id, 64, 32).unwrap(), vec![0, 1]);
    r.accept(&id, 64, 32, 0, &data[..32]).unwrap();
    assert!(r.accept(&id, 64, 32, 1, &data[32..]).unwrap());
    let outside = t.path().join("outside");
    fs::write(&outside, b"untouched").unwrap();
    let other = format::id(b"other");
    symlink(&outside, root.join("fragments").join(hex::encode(other))).unwrap();
    assert!(r.missing(&other, 8, 4).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");
}
#[test]
fn object_count_quota_is_reclaimable_and_byte_quota_is_aggregate() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::create(&t.path().join("node")).unwrap();
    let root = store.path().join("incoming");
    let mut r = Receiver::open(&root).unwrap();
    let mut first = [0; 32];
    for i in 0..MAX_PARTIALS {
        let id = format::id(&(i as u64).to_be_bytes());
        if i == 0 {
            first = id;
        }
        r.accept(&id, 8, 4, 0, b"abcd").unwrap();
    }
    let extra = format::id(b"extra");
    assert!(r.accept(&extra, 8, 4, 0, b"abcd").is_err());
    r.discard(&first).unwrap();
    r.accept(&extra, 8, 4, 0, b"abcd").unwrap();
    drop(r);
    let other = Store::create(&t.path().join("other")).unwrap();
    drop(Receiver::open(&other.path().join("incoming")).unwrap());
    let staging = other.path().join("incoming/fragments");
    for i in 0..=(MAX_STAGED / format::MAX_OBJECT as u64) {
        let name = hex::encode(format::id(&i.to_be_bytes()));
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.join(name))
            .unwrap();
        f.set_len(format::MAX_OBJECT as u64).unwrap();
    }
    assert!(Receiver::open(&other.path().join("incoming")).is_err());
}
#[test]
fn completed_bundle_reclaims_partial_state_and_empty_object_works() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::create(&t.path().join("node")).unwrap();
    let mut r = Receiver::open(&store.path().join("incoming")).unwrap();
    let bytes = b"abcdefgh";
    let id = format::id(bytes);
    r.accept(&id, 8, 4, 0, &bytes[..4]).unwrap();
    store.put(bytes).unwrap();
    assert!(r.missing(&id, 8, 4).unwrap().is_empty());
    assert!(
        !store
            .path()
            .join("incoming/fragments")
            .join(hex::encode(id))
            .exists()
    );
    let empty = format::id(&[]);
    assert!(r.accept(&empty, 0, 4, 0, &[]).unwrap());
    assert!(r.missing(&id, u64::MAX, 1).is_err());
    assert!(r.missing(&id, format::MAX_OBJECT as u64, 1).is_err());
}
