use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};

use crate::{
    app,
    format::{self, Id, Record},
    store::Store,
};

const MAX_DESCRIPTORS: usize = 4096;
const MAX_SCANNED_OBJECTS: usize = 16_384;
const MAX_SCAN_BYTES: u64 = 1 << 30;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: Id,
    pub parents: Vec<Id>,
    pub is_head: bool,
    pub is_selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
}

fn complete_ancestry(candidates: &BTreeMap<Id, crate::format::Snapshot>) -> Result<BTreeSet<Id>> {
    let mut valid = BTreeSet::new();
    let mut invalid = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut edges = 0usize;
    for root in candidates.keys() {
        if valid.contains(root) || invalid.contains(root) {
            continue;
        }
        let mut stack = vec![(*root, false)];
        while let Some((id, exiting)) = stack.pop() {
            if exiting {
                active.remove(&id);
                let record = candidates.get(&id).context("missing ancestry descriptor")?;
                if !invalid.contains(&id)
                    && record.parents.iter().all(|parent| valid.contains(parent))
                {
                    valid.insert(id);
                } else {
                    invalid.insert(id);
                }
                continue;
            }
            if valid.contains(&id) || invalid.contains(&id) {
                continue;
            }
            if !active.insert(id) {
                invalid.extend(active.iter().copied());
                continue;
            }
            let record = candidates.get(&id).context("missing ancestry descriptor")?;
            stack.push((id, true));
            for parent in record.parents.iter().rev() {
                edges += 1;
                ensure!(
                    edges <= MAX_DESCRIPTORS * 64,
                    "snapshot ancestry edge limit exceeded"
                );
                if !candidates.contains_key(parent) {
                    invalid.insert(id);
                } else if active.contains(parent) {
                    invalid.extend(active.iter().copied());
                } else if !valid.contains(parent) && !invalid.contains(parent) {
                    stack.push((*parent, false));
                }
            }
        }
    }
    Ok(valid)
}
/// Lists stored snapshots whose descriptors and ancestry verify under the pinned authority.
pub fn list(path: &Path) -> Result<Vec<SnapshotInfo>> {
    let store = Store::open(path)?;
    let (genesis_id, genesis) = app::pinned(&store)?;
    let selected = store.head()?;
    let policy = app::load_policy(&store, &genesis)?;
    let objects = store.path().join("objects");
    let mut scanned = 0usize;
    let mut scanned_bytes = 0u64;
    let mut candidates = BTreeMap::new();
    let mut attestations = BTreeMap::new();
    for entry in fs::read_dir(objects)? {
        scanned += 1;
        ensure!(scanned <= MAX_SCANNED_OBJECTS, "object scan limit exceeded");
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            continue;
        }
        scanned_bytes = scanned_bytes
            .checked_add(metadata.len())
            .context("object scan length overflow")?;
        ensure!(
            scanned_bytes <= MAX_SCAN_BYTES,
            "object scan byte limit exceeded"
        );
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 64 {
            continue;
        }
        let Ok(id) = format::parse_id(name) else {
            continue;
        };
        let Ok(raw) = store.get(&id) else { continue };
        if let Ok(Record::Snapshot(record)) = format::inspect(&raw) {
            ensure!(
                candidates.len() < MAX_DESCRIPTORS,
                "snapshot descriptor scan limit exceeded"
            );
            candidates.insert(id, record);
        } else if let Some(policy) = &policy
            && let Ok(attestation) = crate::policy::Attestation::decode(&raw)
            && attestation.verify(policy).is_ok()
        {
            attestations.insert((attestation.snapshot, attestation.writer), attestation);
        }
    }
    let mut authorized = BTreeMap::new();
    for (id, record) in candidates {
        if app::authorize_descriptor(
            &record,
            &id,
            &genesis_id,
            &genesis,
            policy.as_ref(),
            attestations.get(&(id, record.writer)),
        )
        .is_ok()
        {
            authorized.insert(id, record);
        }
    }
    let complete = complete_ancestry(&authorized)?;
    let snapshots: BTreeMap<_, _> = authorized
        .into_iter()
        .filter(|(id, _)| complete.contains(id))
        .map(|(id, record)| (id, record.parents))
        .collect();
    let mut result: Vec<_> = snapshots
        .into_iter()
        .map(|(id, parents)| SnapshotInfo {
            id,
            is_head: !parents.contains(&id),
            is_selected: Some(id) == selected,
            parents,
        })
        .collect();
    // A descriptor is a head iff no authorized descriptor names it as a parent.
    let named: BTreeSet<Id> = result
        .iter()
        .flat_map(|s| s.parents.iter().copied())
        .collect();
    for item in &mut result {
        item.is_head = !named.contains(&item.id);
    }
    result.sort_by_key(|item| item.id);
    Ok(result)
}

/// Explicitly moves the local selected head after full ancestry/closure validation.
pub fn select(path: &Path, id: &Id) -> Result<()> {
    let store = Store::open(path)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(store.path().join("control/writer.lock"))?;
    ensure!(lock.metadata()?.is_file(), "invalid writer lock");
    lock.try_lock().context("another local writer is active")?;
    app::verify(path, id, None).context("cannot select an unauthorized snapshot")?;
    store.set_head(id)
}

/// Reports path-level differences between two authenticated, decryptable snapshots.
pub fn diff(path: &Path, older: &Id, newer: &Id, password: &str) -> Result<Vec<Change>> {
    let before = app::entries_for_id(path, older, password)?;
    let after = app::entries_for_id(path, newer, password)?;
    let before: BTreeMap<_, _> = before
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let after: BTreeMap<_, _> = after
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let paths: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    Ok(paths
        .into_iter()
        .filter_map(|path| match (before.get(&path), after.get(&path)) {
            (None, Some(_)) => Some(Change {
                path,
                kind: ChangeKind::Added,
            }),
            (Some(_), None) => Some(Change {
                path,
                kind: ChangeKind::Removed,
            }),
            (Some(a), Some(b))
                if a.directory != b.directory || a.size != b.size || a.digest != b.digest =>
            {
                Some(Change {
                    path,
                    kind: ChangeKind::Modified,
                })
            }
            _ => None,
        })
        .collect())
}
