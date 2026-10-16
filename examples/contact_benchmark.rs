//! Measured deterministic short-contact simulation; no physical carrier is used.
use anyhow::{Result, ensure};
use arc_store::{
    constrained::{self, Link},
    fragments::Receiver,
    store::Store,
};
use std::time::Instant;

fn main() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = Store::create(&temp.path().join("source"))?;
    let destination = Store::create(&temp.path().join("destination"))?;
    let mut ids = Vec::new();
    for index in 0..4u64 {
        let bytes = (0..65536u64)
            .map(|offset| index.wrapping_mul(31).wrapping_add(offset) as u8)
            .collect::<Vec<_>>();
        ids.push(source.put(&bytes)?);
    }
    let link = Link {
        mtu: 4096,
        drop_every: 5,
        reorder_window: 2,
        duplicate_every: 4,
        corrupt_every: 0,
        interrupt_after: Some(7),
    };
    let start = Instant::now();
    let mut attempts = 0;
    let mut resumed_contacts = 0;
    let mut contacts = 0;
    for contact in 1..=128 {
        let receiver = Receiver::open(&destination.path().join("incoming"))?;
        let mut retained = 0;
        for id in &ids {
            if !destination.contains(id)? {
                retained += 16 - receiver.missing(id, 65536, 4096)?.len();
            }
        }
        drop(receiver);
        if retained > 0 {
            resumed_contacts += 1;
        }
        let report = constrained::transfer(&source, &destination, &ids, &link)?;
        attempts += report.fragments_sent;
        contacts = contact;
        if ids
            .iter()
            .all(|id| destination.contains(id).unwrap_or(false))
        {
            break;
        }
    }
    ensure!(
        resumed_contacts > 0,
        "simulation did not exercise persistent partial reuse"
    );
    for id in &ids {
        ensure!(
            destination.get(id)? == source.get(id)?,
            "exact object mismatch"
        );
    }
    println!(
        "{{\"scope\":\"deterministic single-host simulation\",\"objects\":4,\"payload_bytes\":262144,\"mtu\":4096,\"contact_attempt_budget\":7,\"drop_every\":5,\"duplicate_every\":4,\"reorder_window\":2,\"contacts\":{contacts},\"fragment_attempts\":{attempts},\"contacts_reusing_partial_state\":{resumed_contacts},\"seconds\":{},\"exact_bytes_equal\":true}}",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
