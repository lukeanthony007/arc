use std::fs;

use arc_store::{
    app,
    format::{self, CHUNK_SIZE, Record},
    history,
    store::Store,
};
use tempfile::tempdir;

const PASSWORD: &str = "history-test-password";

fn chunks(node: &std::path::Path, snapshot: &[u8; 32]) -> Vec<[u8; 32]> {
    let store = Store::open(node).unwrap();
    let Record::Snapshot(record) = format::inspect(&store.get(snapshot).unwrap()).unwrap() else {
        panic!("snapshot expected")
    };
    record
        .objects
        .into_iter()
        .filter(|id| *id != record.manifest)
        .collect()
}
fn entries(node: &std::path::Path, id: &[u8; 32]) -> Vec<format::Entry> {
    let store = Store::open(node).unwrap();
    let Record::Snapshot(snapshot) = format::inspect(&store.get(id).unwrap()).unwrap() else {
        panic!("snapshot expected")
    };
    let Record::Genesis(genesis) = format::inspect(&store.get(&snapshot.genesis).unwrap()).unwrap()
    else {
        panic!("genesis expected")
    };
    let keys = arc_store::crypto::Secrets::unlock(
        &genesis.collection,
        &store.read_control("keys").unwrap(),
        PASSWORD,
    )
    .unwrap();
    let manifest = keys
        .open(
            &genesis.collection,
            2,
            &store.get(&snapshot.manifest).unwrap(),
        )
        .unwrap();
    format::decode_manifest(&manifest).unwrap()
}

#[test]
fn reuses_authenticated_unchanged_chunks_and_diff_reports_changed_path() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let mut bytes = vec![b'a'; CHUNK_SIZE * 2];
    fs::write(source.join("large"), &bytes).unwrap();
    app::init(&node, PASSWORD).unwrap();
    let first = app::capture(&node, &source, PASSWORD).unwrap();
    let first_chunks = chunks(&node, &first);
    let unchanged = app::capture(&node, &source, PASSWORD).unwrap();
    assert!(
        history::diff(&node, &first, &unchanged, PASSWORD)
            .unwrap()
            .is_empty()
    );
    assert_eq!(chunks(&node, &unchanged), first_chunks);
    assert_eq!(
        entries(&node, &first)[0].entry_id,
        entries(&node, &unchanged)[0].entry_id
    );
    bytes[0] = b'b';
    fs::write(source.join("large"), &bytes).unwrap();
    let changed = app::capture(&node, &source, PASSWORD).unwrap();
    let changed_chunks = chunks(&node, &changed);
    assert_eq!(changed_chunks.len(), 2);
    assert_eq!(
        changed_chunks
            .iter()
            .filter(|id| first_chunks.contains(id))
            .count(),
        1
    );
    let diff = history::diff(&node, &unchanged, &changed, PASSWORD).unwrap();
    assert_eq!(diff.len(), 1);
    assert_eq!(diff[0].path, "large");
    assert_eq!(diff[0].kind, history::ChangeKind::Modified);
}

#[test]
fn policy_attestations_authorize_current_writer_and_frontier_preserves_revoked_history() {
    use arc_store::policy::{Member, Policy, Role};

    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"before policy").unwrap();
    let genesis_id = app::init(&node, PASSWORD).unwrap();
    let first = app::capture(&node, &source, PASSWORD).unwrap();

    let store = Store::open(&node).unwrap();
    let Record::Genesis(genesis) = format::inspect(&store.get(&genesis_id).unwrap()).unwrap()
    else {
        panic!("genesis expected")
    };
    let secrets = arc_store::crypto::Secrets::unlock(
        &genesis.collection,
        &store.read_control("keys").unwrap(),
        PASSWORD,
    )
    .unwrap();
    let policy = Policy::new_with_secrets(
        genesis.collection,
        0,
        None,
        vec![Member {
            key: genesis.root,
            role: Role::Writer,
            revoked: false,
        }],
        vec![first],
        &secrets,
    )
    .unwrap();
    policy.publish(&store).unwrap();

    fs::write(source.join("file"), b"current epoch writer").unwrap();
    let second = app::capture(&node, &source, PASSWORD).unwrap();
    assert!(app::verify(&node, &second, Some(PASSWORD)).is_ok());

    let revoked = Policy::new_with_secrets(
        genesis.collection,
        1,
        Some(policy.id().unwrap()),
        vec![Member {
            key: genesis.root,
            role: Role::Writer,
            revoked: true,
        }],
        vec![first, second],
        &secrets,
    )
    .unwrap();
    revoked.publish(&store).unwrap();
    assert!(app::verify(&node, &second, None).is_ok());
    assert!(app::capture(&node, &source, PASSWORD).is_err());
    assert_eq!(store.read_control("genesis").unwrap(), genesis_id);
}

#[test]
fn missing_parent_descriptor_cannot_hide_an_existing_head() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"head").unwrap();
    let genesis_id = app::init(&node, PASSWORD).unwrap();
    let head = app::capture(&node, &source, PASSWORD).unwrap();
    let store = Store::open(&node).unwrap();
    let Record::Snapshot(mut descriptor) = format::inspect(&store.get(&head).unwrap()).unwrap()
    else {
        panic!("snapshot expected")
    };
    let Record::Genesis(genesis) = format::inspect(&store.get(&genesis_id).unwrap()).unwrap()
    else {
        panic!("genesis expected")
    };
    let keys = arc_store::crypto::Secrets::unlock(
        &genesis.collection,
        &store.read_control("keys").unwrap(),
        PASSWORD,
    )
    .unwrap();
    let missing = [0xff; 32];
    assert!(!store.contains(&missing).unwrap());
    descriptor.parents = vec![head, missing];
    descriptor.parents.sort();
    let forged = store
        .put(&keys.sign_snapshot(&descriptor).unwrap())
        .unwrap();

    let snapshots = history::list(&node).unwrap();
    assert!(
        snapshots
            .iter()
            .any(|snapshot| snapshot.id == head && snapshot.is_head)
    );
    assert!(!snapshots.iter().any(|snapshot| snapshot.id == forged));
}

#[test]
fn selection_preserves_offline_branch_and_explicit_merge_has_both_parents() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"base").unwrap();
    app::init(&node, PASSWORD).unwrap();
    let base = app::capture(&node, &source, PASSWORD).unwrap();
    fs::write(source.join("file"), b"branch one").unwrap();
    let one = app::capture(&node, &source, PASSWORD).unwrap();
    history::select(&node, &base).unwrap();
    fs::write(source.join("file"), b"branch two").unwrap();
    let two = app::capture(&node, &source, PASSWORD).unwrap();
    assert!(app::verify(&node, &one, None).is_ok());
    let heads: Vec<_> = history::list(&node)
        .unwrap()
        .into_iter()
        .filter(|item| item.is_head)
        .map(|item| item.id)
        .collect();
    assert!(heads.contains(&one));
    assert!(heads.contains(&two));
    let merged = app::merge_capture(&node, &source, &[one, two], PASSWORD).unwrap();
    let listed = history::list(&node).unwrap();
    let item = listed.iter().find(|item| item.id == merged).unwrap();
    assert_eq!(item.parents.len(), 2);
    assert!(item.parents.contains(&one) && item.parents.contains(&two));
    assert!(app::verify(&node, &merged, Some(PASSWORD)).is_ok());
}
