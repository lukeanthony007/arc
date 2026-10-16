use arc_store::{
    app,
    crypto::Secrets,
    devices,
    format::{self, Genesis, Id, Record},
    policy::{Policy, Role},
    store::Store,
};
use std::{fs, path::Path};

fn new_root(tmp: &Path) -> (std::path::PathBuf, &'static str) {
    let node = tmp.join("root");
    let password = "correct horse";
    app::init(&node, password).unwrap();
    (node, password)
}
fn genesis(store: &Store) -> (Id, Genesis) {
    let id: Id = store.read_control("genesis").unwrap().try_into().unwrap();
    let Record::Genesis(record) = format::inspect(&store.get(&id).unwrap()).unwrap() else {
        panic!("pinned genesis is not a genesis record")
    };
    (id, record)
}
fn secrets(store: &Store, password: &str) -> Secrets {
    let (_, record) = genesis(store);
    Secrets::unlock(
        &record.collection,
        &store.read_control("keys").unwrap(),
        password,
    )
    .unwrap()
}
fn current_policy(node: &Path) -> Policy {
    let store = Store::open(node).unwrap();
    let (_, record) = genesis(&store);
    Policy::load(&store, &record.root).unwrap().unwrap()
}
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dst = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dst);
            fs::set_permissions(&dst, entry.metadata().unwrap().permissions()).unwrap();
        } else {
            fs::copy(entry.path(), dst).unwrap();
        }
    }
    fs::set_permissions(to, fs::metadata(from).unwrap().permissions()).unwrap();
}
fn assert_repaired(node: &Path, password: &str) {
    devices::repair(node, password).unwrap();
    devices::repair(node, password).unwrap();
    assert!(!node.join("control/membership-pending").exists());
}
fn source(tmp: &Path) -> std::path::PathBuf {
    let path = tmp.join("source");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("file"), b"membership repair snapshot").unwrap();
    path
}

#[test]
fn enable_recovers_every_durable_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let (baseline, password) = new_root(tmp.path());
    let source = source(tmp.path());
    for boundary in 1..=6 {
        let trial = tmp.path().join(format!("enable-{boundary}"));
        copy_tree(&baseline, &trial);
        assert!(devices::enable_with_failpoint(&trial, password, Some(boundary)).is_err());
        assert_repaired(&trial, password);
        assert_eq!(current_policy(&trial).epoch, 0);
        assert!(app::capture(&trial, &source, password).is_ok());
    }
}

#[test]
fn grant_recovers_every_boundary_and_publishes_package() {
    let tmp = tempfile::tempdir().unwrap();
    let (baseline, password) = new_root(tmp.path());
    devices::enable(&baseline, password).unwrap();
    let private = tmp.path().join("reader.key");
    let request_path = tmp.path().join("reader.req");
    devices::create_request(&private, &request_path, "reader password").unwrap();
    let trusted = genesis(&Store::open(&baseline).unwrap()).0;
    let source = source(tmp.path());
    for boundary in 1..=7 {
        let trial = tmp.path().join(format!("grant-{boundary}"));
        copy_tree(&baseline, &trial);
        let invitation = tmp.path().join(format!("grant-{boundary}.inv"));
        assert!(
            devices::grant_with_failpoint(
                &trial,
                &request_path,
                &invitation,
                Role::Reader,
                password,
                Some(boundary),
            )
            .is_err()
        );
        assert_repaired(&trial, password);
        assert_eq!(current_policy(&trial).epoch, 1);
        let joined = tmp.path().join(format!("joined-{boundary}"));
        devices::join_node(&joined, &private, &invitation, trusted, "reader password").unwrap();
        assert_eq!(current_policy(&joined).epoch, 1);
        assert!(app::capture(&joined, &source, "reader password").is_err());
    }
}

#[test]
fn revoke_recovers_every_boundary_without_a_second_key_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let (baseline, password) = new_root(tmp.path());
    devices::enable(&baseline, password).unwrap();
    let private = tmp.path().join("reader.key");
    let request_path = tmp.path().join("reader.req");
    let request = devices::create_request(&private, &request_path, "reader password").unwrap();
    devices::grant(
        &baseline,
        &request_path,
        &tmp.path().join("reader.inv"),
        Role::Reader,
        password,
    )
    .unwrap();
    let baseline_store = Store::open(&baseline).unwrap();
    let (_, root_genesis) = genesis(&baseline_store);
    let old_policy_id = current_policy(&baseline).id().unwrap();
    let old_epoch_key = secrets(&baseline_store, password).epoch_key();
    let source = source(tmp.path());
    for boundary in 1..=7 {
        let trial = tmp.path().join(format!("revoke-{boundary}"));
        copy_tree(&baseline, &trial);
        let package = tmp.path().join(format!("revoke-{boundary}.pkg"));
        assert!(
            devices::revoke_with_failpoint(
                &trial,
                request.signing,
                &[],
                &package,
                password,
                Some(boundary),
            )
            .is_err()
        );
        assert_repaired(&trial, password);
        assert!(app::capture(&trial, &source, password).is_ok());
        let policy = current_policy(&trial);
        assert_eq!(policy.epoch, 2);
        assert!(
            policy
                .members
                .iter()
                .find(|m| m.key == request.signing)
                .unwrap()
                .revoked
        );
        assert!(fs::read(package).is_ok());
        let repaired_store = Store::open(&trial).unwrap();
        assert_eq!(
            devices::secrets_for_policy(&repaired_store, old_policy_id, password)
                .unwrap()
                .epoch_key(),
            old_epoch_key
        );
        let new_key = secrets(&repaired_store, password).epoch_key();
        assert_ne!(new_key, old_epoch_key);
        assert_eq!(root_genesis.root, genesis(&repaired_store).1.root);
    }
}

#[test]
fn apply_recovers_every_boundary_and_preserves_epoch_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, password) = new_root(tmp.path());
    devices::enable(&root, password).unwrap();
    let reader_private = tmp.path().join("reader.key");
    let reader_request_path = tmp.path().join("reader.req");
    let reader_request =
        devices::create_request(&reader_private, &reader_request_path, "reader password").unwrap();
    let reader_node = tmp.path().join("reader-node");
    let reader_invitation = tmp.path().join("reader.inv");
    devices::grant(
        &root,
        &reader_request_path,
        &reader_invitation,
        Role::Reader,
        password,
    )
    .unwrap();
    let trusted = genesis(&Store::open(&root).unwrap()).0;
    devices::join_node(
        &reader_node,
        &reader_private,
        &reader_invitation,
        trusted,
        "reader password",
    )
    .unwrap();
    let reader_store = Store::open(&reader_node).unwrap();
    let old_reader_policy = current_policy(&reader_node).id().unwrap();
    let old_reader_epoch_key = secrets(&reader_store, "reader password").epoch_key();
    let writer_private = tmp.path().join("writer.key");
    let writer_request_path = tmp.path().join("writer.req");
    let writer_request =
        devices::create_request(&writer_private, &writer_request_path, "writer password").unwrap();
    devices::grant(
        &root,
        &writer_request_path,
        &tmp.path().join("writer.inv"),
        Role::Writer,
        password,
    )
    .unwrap();
    let rotation = tmp.path().join("rotation.pkg");
    devices::revoke(
        &root,
        writer_request.signing,
        &[reader_request],
        &rotation,
        password,
    )
    .unwrap();
    let source = source(tmp.path());

    for boundary in 1..=9 {
        let trial = tmp.path().join(format!("apply-{boundary}"));
        copy_tree(&reader_node, &trial);
        assert!(
            devices::apply_with_failpoint(
                &trial,
                &reader_private,
                &rotation,
                "reader password",
                Some(boundary),
            )
            .is_err()
        );
        assert_repaired(&trial, "reader password");
        let id = current_policy(&trial).id().unwrap();
        assert_eq!(current_policy(&trial).epoch, 3);
        assert!(app::capture(&trial, &source, "reader password").is_err());
        let repaired_store = Store::open(&trial).unwrap();
        assert_eq!(
            devices::secrets_for_policy(&repaired_store, old_reader_policy, "reader password")
                .unwrap()
                .epoch_key(),
            old_reader_epoch_key
        );
        assert_ne!(
            secrets(&repaired_store, "reader password").epoch_key(),
            old_reader_epoch_key
        );
        devices::repair(&trial, "reader password").unwrap();
        assert_eq!(current_policy(&trial).id().unwrap(), id);
    }
}

#[test]
fn wrong_password_tamper_legacy_markers_and_writer_lock_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let (node, password) = new_root(tmp.path());
    assert!(devices::enable_with_failpoint(&node, password, Some(1)).is_err());
    let marker = node.join("control/membership-pending");
    let original = fs::read(&marker).unwrap();
    let lock_path = node.join("control/writer.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lock.try_lock().unwrap();
    assert!(devices::repair(&node, password).is_err());
    drop(lock);
    assert!(devices::repair(&node, "wrong password").is_err());
    assert_eq!(fs::read(&marker).unwrap(), original);
    fs::write(&marker, b"tampered journal").unwrap();
    assert!(devices::repair(&node, password).is_err());
    assert_eq!(fs::read(&marker).unwrap(), b"tampered journal");

    let legacy = tmp.path().join("legacy");
    app::init(&legacy, password).unwrap();
    let store = Store::open(&legacy).unwrap();
    store
        .write_new_control("membership-pending", b"rotation")
        .unwrap();
    assert!(devices::repair(&legacy, password).is_err());
    assert_eq!(
        store.read_control("membership-pending").unwrap(),
        b"rotation"
    );
}

#[test]
fn stale_authenticated_journal_cannot_overwrite_a_later_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let (node, password) = new_root(tmp.path());
    devices::enable(&node, password).unwrap();
    let private = tmp.path().join("reader.key");
    let request_path = tmp.path().join("reader.req");
    let request = devices::create_request(&private, &request_path, "reader password").unwrap();
    let invitation = tmp.path().join("reader.inv");
    assert!(
        devices::grant_with_failpoint(
            &node,
            &request_path,
            &invitation,
            Role::Reader,
            password,
            Some(1)
        )
        .is_err()
    );
    let store = Store::open(&node).unwrap();
    let stale = store.read_control("membership-pending").unwrap();
    devices::repair(&node, password).unwrap();
    let package = tmp.path().join("revoke.pkg");
    devices::revoke(&node, request.signing, &[], &package, password).unwrap();
    store.remove_control("membership-pending").unwrap();
    store
        .write_new_control("membership-pending", &stale)
        .unwrap();
    assert!(devices::repair(&node, password).is_err());
    assert_eq!(current_policy(&node).epoch, 2);
    assert_eq!(store.read_control("membership-pending").unwrap(), stale);
}
#[test]
fn invalid_request_is_rejected_before_journal_publication() {
    let tmp = tempfile::tempdir().unwrap();
    let (node, password) = new_root(tmp.path());
    devices::enable(&node, password).unwrap();
    let bad_request = tmp.path().join("invalid.req");
    fs::write(&bad_request, b"invalid request").unwrap();
    assert!(
        devices::grant(
            &node,
            &bad_request,
            &tmp.path().join("invite"),
            Role::Reader,
            password,
        )
        .is_err()
    );
    assert!(!node.join("control/membership-pending").exists());
    assert_eq!(current_policy(&node).epoch, 0);
}
