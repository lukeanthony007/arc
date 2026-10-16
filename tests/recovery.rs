use std::fs;

use arc_store::app;
use tempfile::tempdir;

#[test]
fn recovery_restores_complete_inventory_and_authenticates_kit() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("item"), b"first").unwrap();
    app::init(&node, "recovery-password").unwrap();
    let old = app::capture(&node, &source, "recovery-password").unwrap();
    fs::write(source.join("item"), b"second").unwrap();
    let new = app::capture(&node, &source, "recovery-password").unwrap();

    fs::write(
        node.join("objects/.tmp-0123456789abcdef0123456789abcdef"),
        b"unpublished temporary",
    )
    .unwrap();
    let kit = temp.path().join("recovery.arc");
    app::export_recovery(&node, &kit, "recovery-password").unwrap();
    assert!(app::export_recovery(&node, &kit, "recovery-password").is_err());

    let restored = temp.path().join("recovered");
    assert!(
        app::recover(
            &restored,
            &kit,
            &app::verify(&node, &old, None).unwrap().genesis,
            "wrong-password"
        )
        .is_err()
    );
    assert!(!restored.exists());
    let genesis = app::verify(&node, &old, None).unwrap().genesis;
    app::recover(&restored, &kit, &genesis, "recovery-password").unwrap();
    assert!(
        !restored
            .join("objects/.tmp-0123456789abcdef0123456789abcdef")
            .exists()
    );
    assert!(
        app::verify(&restored, &old, Some("recovery-password"))
            .unwrap()
            .materialized
    );
    assert!(
        app::verify(&restored, &new, Some("recovery-password"))
            .unwrap()
            .materialized
    );
    let wrong_pin_dest = temp.path().join("wrong-pin");
    assert!(app::recover(&wrong_pin_dest, &kit, &[0; 32], "recovery-password").is_err());
    assert!(!wrong_pin_dest.exists());
    let tampered = temp.path().join("tampered.arc");
    let mut damaged = fs::read(&kit).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(&tampered, damaged).unwrap();
    let damaged_dest = temp.path().join("damaged");
    assert!(app::recover(&damaged_dest, &tampered, &genesis, "recovery-password").is_err());
    assert!(!damaged_dest.exists());
    assert!(app::export_recovery(&node, &temp.path().join("wrong.arc"), "wrong-password").is_err());
    assert!(app::recover(&restored, &kit, &genesis, "recovery-password").is_err());
}

#[test]
fn policy_admin_and_reader_recovery_preserve_separate_authority() {
    use arc_store::{devices, policy::Role, store::Store};

    let temp = tempdir().unwrap();
    let admin = temp.path().join("admin");
    let genesis = app::init(&admin, "admin-password").unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("item"), b"before rotation").unwrap();
    let first = app::capture(&admin, &source, "admin-password").unwrap();
    devices::enable(&admin, "admin-password").unwrap();

    let private = temp.path().join("member.key");
    let request_path = temp.path().join("member.req");
    let request = devices::create_request(&private, &request_path, "member-password").unwrap();
    let invitation = temp.path().join("invite");
    devices::grant(
        &admin,
        &request_path,
        &invitation,
        Role::Reader,
        "admin-password",
    )
    .unwrap();
    let member = temp.path().join("member");
    devices::join_node(&member, &private, &invitation, genesis, "member-password").unwrap();

    let member_kit = temp.path().join("member.recovery");
    app::export_recovery(&member, &member_kit, "member-password").unwrap();
    let recovered_member = temp.path().join("member-recovered");
    app::recover(&recovered_member, &member_kit, &genesis, "member-password").unwrap();
    let member_store = Store::open(&recovered_member).unwrap();
    let policy_id: [u8; 32] = member_store
        .read_control("policy")
        .unwrap()
        .try_into()
        .unwrap();
    let genesis_record = member_store.get(&genesis).unwrap();
    let arc_store::format::Record::Genesis(genesis_record) =
        arc_store::format::inspect(&genesis_record).unwrap()
    else {
        panic!("expected genesis")
    };
    let policy = arc_store::policy::Policy::decode(&member_store.get(&policy_id).unwrap()).unwrap();
    policy.verify(&genesis_record.root).unwrap();
    assert_eq!(
        policy
            .members
            .iter()
            .find(|m| m.key == request.signing)
            .unwrap()
            .role,
        Role::Reader
    );
    assert!(!policy.allows_writer(&request.signing));
    assert_ne!(request.signing, genesis_record.root);
    assert!(app::capture(&recovered_member, &source, "member-password").is_err());
    assert_ne!(policy_id, [0; 32]);

    devices::revoke(
        &admin,
        request.signing,
        &[],
        &temp.path().join("rotation"),
        "admin-password",
    )
    .unwrap();
    fs::write(source.join("item"), b"after rotation").unwrap();
    let latest = app::capture(&admin, &source, "admin-password").unwrap();
    let admin_kit = temp.path().join("admin.recovery");
    app::export_recovery(&admin, &admin_kit, "admin-password").unwrap();
    let recovered_admin = temp.path().join("admin-recovered");
    app::recover(&recovered_admin, &admin_kit, &genesis, "admin-password").unwrap();

    assert!(
        app::verify(&recovered_admin, &first, Some("admin-password"))
            .unwrap()
            .materialized
    );
    assert!(
        app::verify(&recovered_admin, &latest, Some("admin-password"))
            .unwrap()
            .materialized
    );
}
#[test]
fn legacy_single_root_kit_remains_keys_only() {
    use arc_store::store::Store;
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("item"), b"legacy data").unwrap();
    app::init(&node, "legacy-password").unwrap();
    let snapshot = app::capture(&node, &source, "legacy-password").unwrap();
    let store = Store::open(&node).unwrap();
    let genesis: [u8; 32] = store.read_control("genesis").unwrap().try_into().unwrap();
    let genesis_bytes = store.get(&genesis).unwrap();
    let keys = store.read_control("keys").unwrap();
    let kit = temp.path().join("legacy.arc");
    let mut bytes = b"ARCKEY1\n".to_vec();
    bytes.extend_from_slice(&genesis);
    bytes.extend_from_slice(&(genesis_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&genesis_bytes);
    bytes.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&keys);
    fs::write(&kit, bytes).unwrap();
    let recovered = temp.path().join("legacy-recovered");
    app::recover(&recovered, &kit, &genesis, "legacy-password").unwrap();
    let recovered_store = Store::open(&recovered).unwrap();
    assert!(recovered_store.head().unwrap().is_none());
    assert!(app::verify(&recovered, &snapshot, None).is_err());
}

#[test]
fn recovery_export_refuses_interrupted_membership_state() {
    use arc_store::store::Store;
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    app::init(&node, "recovery-password").unwrap();
    Store::open(&node)
        .unwrap()
        .write_new_control("membership-pending", b"rotation")
        .unwrap();
    let kit = temp.path().join("recovery.arc");
    assert!(app::export_recovery(&node, &kit, "recovery-password").is_err());
    assert!(!kit.exists());
}

#[test]
fn recovery_preserves_untrusted_and_incomplete_cas_evidence() {
    use arc_store::{
        bundle, devices,
        format::{Id, Record, Snapshot},
        policy::Role,
        store::Store,
    };
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let genesis = app::init(&node, "admin-password").unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("item"), b"trusted root snapshot").unwrap();
    let good = app::capture(&node, &source, "admin-password").unwrap();

    let foreign_node = temp.path().join("foreign");
    app::init(&foreign_node, "foreign-password").unwrap();
    let foreign_source = temp.path().join("foreign-source");
    fs::create_dir(&foreign_source).unwrap();
    fs::write(foreign_source.join("item"), b"foreign").unwrap();
    let foreign = app::capture(&foreign_node, &foreign_source, "foreign-password").unwrap();
    let foreign_bundle = temp.path().join("foreign.bundle");
    app::export(&foreign_node, &foreign, &foreign_bundle).unwrap();
    app::import(&node, &foreign_bundle).unwrap();
    assert!(app::verify(&node, &foreign, None).is_err());

    devices::enable(&node, "admin-password").unwrap();
    let private = temp.path().join("writer.key");
    let request_path = temp.path().join("writer.req");
    let request = devices::create_request(&private, &request_path, "writer-password").unwrap();
    let invitation = temp.path().join("writer.invite");
    devices::grant(
        &node,
        &request_path,
        &invitation,
        Role::Writer,
        "admin-password",
    )
    .unwrap();
    let member = temp.path().join("writer");
    devices::join_node(&member, &private, &invitation, genesis, "writer-password").unwrap();
    let member_store = Store::open(&member).unwrap();
    let member_genesis = member_store.get(&genesis).unwrap();
    let Record::Genesis(member_genesis) = arc_store::format::inspect(&member_genesis).unwrap()
    else {
        panic!("expected genesis")
    };
    let device =
        arc_store::crypto::DeviceSecrets::unlock(&fs::read(&private).unwrap(), "writer-password")
            .unwrap();
    let policy_id: Id = member_store
        .read_control("policy")
        .unwrap()
        .try_into()
        .unwrap();
    let policy = arc_store::policy::Policy::load(&member_store, &member_genesis.root)
        .unwrap()
        .unwrap();
    assert_eq!(policy.id().unwrap(), policy_id);
    let missing = [0xA5; 32];
    let incomplete = Snapshot {
        collection: member_genesis.collection,
        genesis,
        writer: device.public(),
        parents: vec![],
        manifest: missing,
        objects: vec![missing],
    };
    let incomplete_id = member_store
        .put(&device.sign_snapshot(&incomplete).unwrap())
        .unwrap();
    let attestation = policy.attest(incomplete_id, &device).unwrap();
    let attestation_id = member_store.put(&attestation.encode().unwrap()).unwrap();
    let incomplete_bundle = temp.path().join("incomplete.bundle");
    bundle::export(
        &member_store,
        &[incomplete_id, attestation_id],
        &incomplete_bundle,
    )
    .unwrap();
    app::import(&node, &incomplete_bundle).unwrap();
    assert!(app::verify(&node, &incomplete_id, None).is_err());

    devices::revoke(
        &node,
        request.signing,
        &[],
        &temp.path().join("rotation"),
        "admin-password",
    )
    .unwrap();
    let late_source = temp.path().join("late-source");
    fs::create_dir(&late_source).unwrap();
    fs::write(late_source.join("late"), b"revoked writer late work").unwrap();
    let late = app::capture(&member, &late_source, "writer-password").unwrap();
    let late_bundle = temp.path().join("late.bundle");
    app::export(&member, &late, &late_bundle).unwrap();
    app::import(&node, &late_bundle).unwrap();
    assert!(app::verify(&node, &late, None).is_err());

    let opaque = Store::open(&node)
        .unwrap()
        .put(b"opaque quarantined bytes")
        .unwrap();
    let kit = temp.path().join("complete-local-inventory.arc");
    app::export_recovery(&node, &kit, "admin-password").unwrap();
    let recovered = temp.path().join("recovered");
    app::recover(&recovered, &kit, &genesis, "admin-password").unwrap();
    let recovered_store = Store::open(&recovered).unwrap();
    for id in [good, foreign, incomplete_id, late, opaque] {
        assert!(recovered_store.contains(&id).unwrap());
    }
    assert!(
        app::verify(&recovered, &good, Some("admin-password"))
            .unwrap()
            .materialized
    );
    assert!(app::verify(&recovered, &foreign, None).is_err());
    assert!(app::verify(&recovered, &incomplete_id, None).is_err());
    assert!(app::verify(&recovered, &late, None).is_err());
}
