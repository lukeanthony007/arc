use arc_store::{
    app,
    crypto::Secrets,
    diagnostics, format,
    policy::{Member, Policy, Role},
    store::Store,
};
use std::fs;

#[test]
fn export_rejects_case_aliases_without_publishing_a_broken_kit() {
    let temp = tempfile::tempdir().unwrap();
    let node = temp.path().join("node");
    let genesis = app::init(&node, "alias-password").unwrap();
    let name = format::display_id(&genesis);
    let alias = name.to_uppercase();
    assert_ne!(alias, name);
    fs::hard_link(
        node.join("objects").join(&name),
        node.join("objects").join(alias),
    )
    .unwrap();
    let kit = temp.path().join("backup.arc");
    assert!(
        app::export_recovery(&node, &kit, "alias-password")
            .unwrap_err()
            .to_string()
            .contains("noncanonical")
    );
    assert!(!kit.exists());
    assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".arc-recovery-")
    }));
}

#[test]
fn same_authority_foreign_policy_is_not_a_valid_local_trust_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let node = temp.path().join("node");
    let store = Store::create(&node).unwrap();
    let keys = Secrets::from_member([7; 32], [8; 32]);
    let genesis = store.put(&keys.sign_genesis([1; 32]).unwrap()).unwrap();
    store.write_new_control("genesis", &genesis).unwrap();
    store
        .write_new_control("keys", &keys.lock(&[1; 32], "binding-password").unwrap())
        .unwrap();
    let foreign = Policy::new(
        [2; 32],
        keys.root(),
        0,
        None,
        vec![Member {
            key: keys.root(),
            role: Role::Writer,
            revoked: false,
        }],
        vec![],
        &[7; 32],
    )
    .unwrap();
    let pid = store.put(&foreign.encode().unwrap()).unwrap();
    store.write_new_control("policy", &pid).unwrap();
    assert!(diagnostics::doctor(&node).unwrap().has_errors());
    let kit = temp.path().join("foreign.arc");
    assert!(
        app::export_recovery(&node, &kit, "binding-password")
            .unwrap_err()
            .to_string()
            .contains("collection")
    );
    assert!(!kit.exists());
}

#[test]
fn failed_creation_preserves_an_existing_directory_and_its_contents() {
    let temp = tempfile::tempdir().unwrap();
    let node = temp.path().join("existing");
    fs::create_dir(&node).unwrap();
    fs::write(node.join("keep"), b"preexisting").unwrap();
    assert!(Store::create(&node).is_err());
    assert_eq!(fs::read(node.join("keep")).unwrap(), b"preexisting");
}
