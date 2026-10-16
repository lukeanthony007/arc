//! Deterministic constrained-link simulator for encrypted immutable object transfer.
//! This models payload faults, not Bluetooth/radio hardware behavior.
use crate::{format::Id, fragments::Receiver, store::Store};
use anyhow::{Result, ensure};
#[derive(Clone, Debug)]
pub struct Link {
    /// Maximum fragment payload; framing bytes are excluded.
    pub mtu: usize,
    pub drop_every: usize,
    pub reorder_window: usize,
    pub duplicate_every: usize,
    pub corrupt_every: usize,
    pub interrupt_after: Option<usize>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub objects_sent: usize,
    pub objects_received: usize,
    pub fragments_sent: usize,
    pub resumed_objects: usize,
}
/// Complete fragments survive contacts and receiver restarts. Only final digest-verified
/// objects are published. Use the same MTU for a partial object until it completes or is discarded.
pub fn transfer(source: &Store, destination: &Store, ids: &[Id], link: &Link) -> Result<Report> {
    ensure!(ids.len() <= 16_384, "too many object IDs");
    ensure!(
        link.mtu > 0 && link.mtu <= crate::format::MAX_OBJECT,
        "invalid link MTU"
    );
    let mut report = Report::default();
    let mut total = 0u64;
    let mut receiver = Receiver::open(&destination.path().join("incoming"))?;
    let mut budget = link.interrupt_after;
    'objects: for id in ids {
        if destination.contains(id)? {
            receiver.discard(id)?;
            report.resumed_objects += 1;
            continue;
        }
        let bytes = source.get(id)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("transfer size overflow"))?;
        ensure!(total <= 1 << 30, "transfer quota exceeded");
        let missing = receiver.missing(id, bytes.len() as u64, link.mtu as u32)?;
        for indices in missing.chunks(link.reorder_window.clamp(1, 16_384)) {
            let mut delivered = Vec::new();
            for &index in indices {
                if budget == Some(0) {
                    break;
                }
                if let Some(left) = budget.as_mut() {
                    *left -= 1;
                }
                report.fragments_sent += 1;
                if link.drop_every != 0 && report.fragments_sent % link.drop_every == 0 {
                    continue;
                }
                let start = index as usize * link.mtu;
                let end = (start + link.mtu).min(bytes.len());
                let mut fragment = bytes[start..end].to_vec();
                if link.corrupt_every != 0
                    && report.fragments_sent % link.corrupt_every == 0
                    && !fragment.is_empty()
                {
                    fragment[0] ^= 1;
                }
                if link.duplicate_every != 0 && report.fragments_sent % link.duplicate_every == 0 {
                    delivered.push((index, fragment.clone()));
                }
                delivered.push((index, fragment));
            }
            if link.reorder_window > 1 {
                delivered.reverse();
            }
            for (index, fragment) in delivered {
                match receiver.accept_fragment(
                    id,
                    bytes.len() as u64,
                    link.mtu as u32,
                    index,
                    &fragment,
                )? {
                    crate::fragments::Admission::Published => {
                        report.objects_sent += 1;
                        report.objects_received += 1;
                    }
                    crate::fragments::Admission::Rejected => continue 'objects,
                    _ => {}
                }
            }
            if destination.contains(id)? {
                break;
            }
            if budget == Some(0) {
                return Ok(report);
            }
        }
    }
    Ok(report)
}
