//! Abrupt process-exit recovery regression; this does not simulate power loss.
use arc_store::{
    app, devices,
    format::{self, Record},
    policy::Policy,
    store::Store,
};
use std::{path::Path, process::Command};
const PASSWORD: &str = "crash-test password";

#[test]
fn failpoint_child() {
    let Ok(node) = std::env::var("ARC_CRASH_CHILD_NODE") else {
        return;
    };
    assert!(devices::enable_with_failpoint(Path::new(&node), PASSWORD, Some(3)).is_err());
    std::process::exit(77); // no unwinding or test harness teardown
}

#[test]
fn abrupt_exit_repairs_persisted_membership_journal_idempotently() {
    let tmp = tempfile::tempdir().unwrap();
    let node = tmp.path().join("child-node");
    app::init(&node, PASSWORD).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "failpoint_child", "--nocapture"])
        .env("ARC_CRASH_CHILD_NODE", &node)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    assert!(node.join("control/membership-pending").is_file());
    let store = Store::open(&node).unwrap();
    let genesis_id: format::Id = store.read_control("genesis").unwrap().try_into().unwrap();
    let Record::Genesis(genesis) = format::inspect(&store.get(&genesis_id).unwrap()).unwrap()
    else {
        panic!("invalid genesis")
    };
    devices::repair(&node, PASSWORD).unwrap();
    let first = Policy::load(&Store::open(&node).unwrap(), &genesis.root)
        .unwrap()
        .unwrap();
    devices::repair(&node, PASSWORD).unwrap();
    let second = Policy::load(&Store::open(&node).unwrap(), &genesis.root)
        .unwrap()
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.epoch, 0);
    assert!(!node.join("control/membership-pending").exists());
}
