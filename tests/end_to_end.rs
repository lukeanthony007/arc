use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use arc_store::{
    app,
    format::{self, CHUNK_SIZE, Record},
    store::Store,
};
use tempfile::tempdir;

const PASSWORD: &str = "disposable-test-password";

#[test]
fn offline_recovery_restores_exact_multichunk_snapshot_without_changing_head_on_import() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("notes/empty-directory")).unwrap();
    let bytes: Vec<u8> = (0..CHUNK_SIZE * 3 + 17)
        .map(|n| (n.wrapping_mul(71) % 251) as u8)
        .collect();
    fs::write(source.join("notes/binary"), &bytes).unwrap();
    fs::write(source.join("empty"), []).unwrap();
    let private_text = b"a private document whose plaintext must not be in a stored object";
    fs::write(source.join("notes/private.txt"), private_text).unwrap();

    let genesis = app::init(&node, PASSWORD).unwrap();
    let first = app::capture(&node, &source, PASSWORD).unwrap();
    assert!(app::verify(&node, &first, None).unwrap().objects >= 3);
    assert!(
        app::verify(&node, &first, Some(PASSWORD))
            .unwrap()
            .materialized
    );
    for file in fs::read_dir(node.join("objects")).unwrap() {
        let object = fs::read(file.unwrap().path()).unwrap();
        assert!(
            !object
                .windows(private_text.len())
                .any(|w| w == private_text)
        );
    }
    fs::write(source.join("notes/private.txt"), b"revised").unwrap();
    let second = app::capture(&node, &source, PASSWORD).unwrap();
    assert_eq!(
        app::verify(&node, &second, Some(PASSWORD))
            .unwrap()
            .ancestors,
        1
    );

    let kit = temp.path().join("keys.arc");
    app::export_recovery(&node, &kit).unwrap();
    let package = temp.path().join("data.arc");
    app::export(&node, &second, &package).unwrap();
    let recovered = temp.path().join("recovered");
    app::recover(&recovered, &kit, &genesis, PASSWORD).unwrap();
    assert!(Store::open(&recovered).unwrap().head().unwrap().is_none());
    assert!(app::verify(&recovered, &second, None).is_err());
    let count = app::import(&recovered, &package).unwrap();
    assert!(count > 0);
    assert_eq!(app::import(&recovered, &package).unwrap(), count);
    assert!(Store::open(&recovered).unwrap().head().unwrap().is_none());
    assert!(
        app::verify(&recovered, &second, Some(PASSWORD))
            .unwrap()
            .materialized
    );
    // Export carries ancestor descriptors but does not pretend to retain historic file bytes.
    assert!(app::verify(&recovered, &first, Some(PASSWORD)).is_err());
    let restored = temp.path().join("restored");
    app::restore(&recovered, &second, &restored, PASSWORD).unwrap();
    assert_eq!(fs::read(restored.join("notes/binary")).unwrap(), bytes);
    assert_eq!(
        fs::read(restored.join("notes/private.txt")).unwrap(),
        b"revised"
    );
    assert!(restored.join("notes/empty-directory").is_dir());
    assert_eq!(fs::read(restored.join("empty")).unwrap(), b"");
    assert!(app::restore(&recovered, &second, &restored, PASSWORD).is_err());
    assert_eq!(
        fs::read(restored.join("notes/private.txt")).unwrap(),
        b"revised"
    );
}

#[test]
fn corrupt_ciphertext_wrong_password_and_untrusted_root_fail_without_destination() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("data"), b"retain me").unwrap();
    let genesis = app::init(&node, PASSWORD).unwrap();
    let snapshot = app::capture(&node, &source, PASSWORD).unwrap();
    let target = temp.path().join("out");
    assert!(app::restore(&node, &snapshot, &target, "wrong password").is_err());
    assert!(!target.exists());
    let kit = temp.path().join("kit");
    app::export_recovery(&node, &kit).unwrap();
    let wrong_node = temp.path().join("wrong");
    assert!(app::recover(&wrong_node, &kit, &[7; 32], PASSWORD).is_err());
    assert!(!wrong_node.exists());
    assert_ne!(genesis, [7; 32]);

    let store = Store::open(&node).unwrap();
    let Record::Snapshot(record) = format::inspect(&store.get(&snapshot).unwrap()).unwrap() else {
        panic!()
    };
    let data_id = record
        .objects
        .iter()
        .find(|id| **id != record.manifest)
        .unwrap();
    let object_path = node.join("objects").join(hex::encode(data_id));
    let mut corrupted = fs::read(&object_path).unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    fs::write(&object_path, &corrupted).unwrap();
    assert!(app::verify(&node, &snapshot, None).is_err());
    assert!(app::restore(&node, &snapshot, &target, PASSWORD).is_err());
    assert!(!target.exists());
}

#[test]
fn capture_rejects_symlinks_special_files_and_node_recursion_preserving_head() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    app::init(&node, PASSWORD).unwrap();
    assert!(app::capture(&node, temp.path(), PASSWORD).is_err());
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("regular"), b"original").unwrap();
    let initial = app::capture(&node, &source, PASSWORD).unwrap();
    symlink("regular", source.join("link")).unwrap();
    assert!(app::capture(&node, &source, PASSWORD).is_err());
    assert_eq!(Store::open(&node).unwrap().head().unwrap(), Some(initial));
    fs::remove_file(source.join("link")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        source.join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(app::capture(&node, &source, PASSWORD).is_err());
    assert_eq!(Store::open(&node).unwrap().head().unwrap(), Some(initial));
}

#[test]
fn import_cross_collection_does_not_enroll_or_authorize() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("a");
    let other = temp.path().join("b");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"a").unwrap();
    app::init(&node, PASSWORD).unwrap();
    let other_genesis = app::init(&other, PASSWORD).unwrap();
    let snapshot = app::capture(&node, &source, PASSWORD).unwrap();
    let package = temp.path().join("transfer");
    app::export(&node, &snapshot, &package).unwrap();
    app::import(&other, &package).unwrap();
    assert!(app::verify(&other, &snapshot, None).is_err());
    assert_eq!(
        Store::open(&other)
            .unwrap()
            .read_control("genesis")
            .unwrap(),
        other_genesis
    );
}

#[test]
fn cli_requires_explicit_password_pipe_for_initialization() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let binary = env!("CARGO_BIN_EXE_arc");
    let failed = Command::new(binary)
        .arg("init")
        .arg(&node)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!node.exists());
    let mut child = Command::new(binary)
        .arg("--password-stdin")
        .arg("init")
        .arg(&node)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"cli-disposable-password\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .starts_with("genesis ")
    );
}
