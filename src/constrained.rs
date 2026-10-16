//! Deterministic constrained-link simulator for encrypted immutable object transfer.
//! This models transport faults only; it does not claim radio or hardware behavior.
use crate::{format::Id, store::Store};
use anyhow::{Result, bail};
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
/// Object transfer is bounded. Fragment state is contact-local; only complete immutable IDs
/// persist between contacts. The MTU measures payload bytes, excluding link framing.
pub fn transfer(source: &Store, destination: &Store, ids: &[Id], link: &Link) -> Result<Report> {
    if ids.len() > 16_384 {
        bail!("too many object IDs");
    }
    if link.mtu == 0 || link.mtu > crate::format::MAX_OBJECT {
        bail!("invalid link MTU");
    }
    let mut total = 0u64;
    let mut report = Report::default();
    let mut budget = link.interrupt_after;
    for id in ids {
        if destination.contains(id)? {
            report.resumed_objects += 1;
            continue;
        }
        let bytes = source.get(id)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("transfer size overflow"))?;
        if total > 1 << 30 {
            bail!("transfer quota exceeded");
        }
        let chunks: Vec<&[u8]> = bytes.chunks(link.mtu).collect();
        let mut staged: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            if budget == Some(0) {
                return Ok(report);
            }
            if let Some(left) = budget.as_mut() {
                *left -= 1;
            }
            report.fragments_sent += 1;
            if link.drop_every != 0 && (i + 1) % link.drop_every == 0 {
                continue;
            }
            let mut fragment = chunk.to_vec();
            if link.corrupt_every != 0 && (i + 1) % link.corrupt_every == 0 && !fragment.is_empty()
            {
                fragment[0] ^= 1;
            }
            staged.push((i, fragment));
            if link.duplicate_every != 0 && (i + 1) % link.duplicate_every == 0 {
                staged.push((i, chunk.to_vec()));
            }
        }
        let window = link.reorder_window.max(1);
        for part in staged.chunks_mut(window) {
            if link.reorder_window > 1 {
                part.reverse();
            }
        }
        let mut ordered = vec![None; chunks.len()];
        for (i, part) in staged {
            if ordered[i].is_none() {
                ordered[i] = Some(part);
            }
        }
        let mut received = Vec::with_capacity(bytes.len());
        for part in ordered.into_iter().flatten() {
            received.extend_from_slice(&part);
        }
        if received.len() != bytes.len() || crate::format::id(&received) != *id {
            continue;
        }
        destination.put(&received)?;
        report.objects_sent += 1;
        report.objects_received += 1;
    }
    Ok(report)
}
