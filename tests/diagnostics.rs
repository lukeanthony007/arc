use arc_store::{
    app,
    diagnostics::{self, Severity},
    format::{self, Record},
    store::Store,
};
use std::fs;
use tempfile::tempdir;

const PASSWORD: &str = "diagnostic-test-password";

#[test]
fn status_without_head_is_unknown_and_read_only() {
    let tmp = tempdir().unwrap();
    let node = tmp.path().join("node");
    Store::create(&node).unwrap();
    let before = fs::read_dir(node.join("control")).unwrap().count();
    let report = diagnostics::status(&node).unwrap();
    assert!(report.selected.is_none());
    assert!(report.identity.is_none());
    assert!(report.policy_epoch.is_none());
    assert_eq!(
        report.policy_freshness,
        "unknown (no global authority queried)"
    );
    assert_eq!(fs::read_dir(node.join("control")).unwrap().count(), before);
    let doctor = diagnostics::doctor(&node).unwrap();
    assert!(
        doctor
            .findings
            .iter()
            .any(|f| f.code == "head-missing" && f.severity == Severity::Warning)
    );
}

#[test]
fn pending_marker_and_partial_progress_are_preserved() {
    let tmp = tempdir().unwrap();
    let node = tmp.path().join("node");
    Store::create(&node).unwrap();
    fs::write(
        node.join("control/membership-pending"),
        b"opaque pending transition",
    )
    .unwrap();
    fs::create_dir(node.join("incoming/fragments")).unwrap();
    fs::write(
        node.join(
            "incoming/fragments/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        b"partial",
    )
    .unwrap();
    let report = diagnostics::status(&node).unwrap();
    assert!(report.membership_pending);
    assert_eq!(report.partial_objects, 1);
    let doctor = diagnostics::doctor(&node).unwrap();
    assert!(
        doctor
            .findings
            .iter()
            .any(|f| f.code == "membership-pending")
    );
    assert!(doctor.findings.iter().any(|f| f.code == "partial-progress"));
    assert_eq!(
        fs::read(node.join("control/membership-pending")).unwrap(),
        b"opaque pending transition"
    );
    assert!(
        node.join(
            "incoming/fragments/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .exists()
    );
}

fn initialized() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempdir().unwrap();
    let node = tmp.path().join("node");
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("data"), vec![42u8; 4096]).unwrap();
    app::init(&node, PASSWORD).unwrap();
    (tmp, node, source)
}

#[test]
fn doctor_finds_missing_and_corrupt_cas_without_mutating_node() {
    let (_tmp, node, source) = initialized();
    let snapshot = app::capture(&node, &source, PASSWORD).unwrap();
    let store = Store::open(&node).unwrap();
    let Record::Snapshot(record) = format::inspect(&store.get(&snapshot).unwrap()).unwrap() else {
        panic!()
    };
    let chunk = *record
        .objects
        .iter()
        .find(|id| **id != record.manifest)
        .unwrap();
    let chunk_path = node.join("objects").join(hex::encode(chunk));
    fs::remove_file(&chunk_path).unwrap();
    let before = fs::read_dir(node.join("control")).unwrap().count();
    let report = diagnostics::doctor(&node).unwrap();
    assert!(report.has_errors());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "selected-coverage-incomplete"
                || f.code == "snapshot-coverage-incomplete")
    );
    assert_eq!(fs::read_dir(node.join("control")).unwrap().count(), before);
    fs::write(&chunk_path, b"corrupt").unwrap();
    let report = diagnostics::doctor(&node).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "selected-coverage-incomplete" || f.code == "corrupt-cas-object")
    );
}

#[test]
fn status_reports_multiple_authorized_heads_and_unknown_freshness() {
    let (_tmp, node, source) = initialized();
    let first = app::capture(&node, &source, PASSWORD).unwrap();
    Store::open(&node).unwrap().remove_control("head").unwrap();
    fs::write(source.join("data"), b"second history").unwrap();
    let second = app::capture(&node, &source, PASSWORD).unwrap();
    Store::open(&node).unwrap().set_head(&first).unwrap();
    let report = diagnostics::status(&node).unwrap();
    assert_eq!(report.selected, Some(first));
    assert!(report.competing_heads.contains(&second));
    assert_eq!(
        report.policy_freshness,
        "unknown (no global authority queried)"
    );
    assert!(
        diagnostics::doctor(&node)
            .unwrap()
            .findings
            .iter()
            .any(|f| f.code == "competing-authorized-head")
    );
}

#[test]
fn invalid_identity_and_policy_fail_doctor_even_without_a_head() {
    let (_tmp, node, _source) = initialized();
    let store = Store::open(&node).unwrap();
    let genesis: [u8; 32] = store.read_control("genesis").unwrap().try_into().unwrap();
    let object = node.join("objects").join(hex::encode(genesis));
    let original = fs::read(&object).unwrap();
    fs::remove_file(&object).unwrap();
    let report = diagnostics::doctor(&node).unwrap();
    assert!(report.has_errors());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "invalid-trust-state")
    );
    fs::write(&object, original).unwrap();
    arc_store::devices::enable(&node, PASSWORD).unwrap();
    let policy: [u8; 32] = store.read_control("policy").unwrap().try_into().unwrap();
    fs::remove_file(node.join("objects").join(hex::encode(policy))).unwrap();
    assert!(diagnostics::doctor(&node).unwrap().has_errors());
}

#[test]
fn partial_metadata_uses_receiver_bound_and_bounded_enumeration() {
    let tmp = tempdir().unwrap();
    let node = tmp.path().join("node");
    Store::create(&node).unwrap();
    let fragments = node.join("incoming/fragments");
    fs::create_dir(&fragments).unwrap();
    let partial = fragments.join(hex::encode([0u8; 32]));
    fs::File::create(&partial)
        .unwrap()
        .set_len(format::MAX_OBJECT as u64 + 1)
        .unwrap();
    assert_eq!(diagnostics::status(&node).unwrap().partial_objects, 1);
    for index in 1..=130u8 {
        fs::write(fragments.join(hex::encode([index; 32])), b"").unwrap();
    }
    assert!(
        diagnostics::status(&node)
            .unwrap_err()
            .to_string()
            .contains("bounded inspection")
    );
    assert!(partial.exists());
}
