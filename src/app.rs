//! Single-root experimental collection operations; no membership or network service.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::Secrets;
use crate::format::{
    self, CHUNK_SIZE, Entry, Genesis, Id, MAX_CHUNKS, MAX_ENTRIES, Record, Snapshot,
};
use crate::store::Store;

const MAX_HISTORY: usize = 4096;
const MAX_OBJECT_SCAN: usize = 16_384;
const MAX_TOTAL_BYTES: u64 = MAX_CHUNKS as u64 * CHUNK_SIZE as u64;

/// Exact, scoped observations. `materialized` requires a key and complete plaintext validation.
#[derive(Debug)]
pub struct Verification {
    pub snapshot: Id,
    pub genesis: Id,
    pub objects: usize,
    pub bytes: u64,
    pub ancestors: usize,
    pub materialized: bool,
}

fn random_id() -> Id {
    let mut value = [0; 32];
    OsRng.fill_bytes(&mut value);
    value
}

pub(crate) fn pinned(store: &Store) -> Result<(Id, Genesis)> {
    let raw = store.read_control("genesis")?;
    let genesis_id: Id = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid genesis pin"))?;
    let Record::Genesis(genesis) = format::inspect(&store.get(&genesis_id)?)? else {
        bail!("pinned object is not a genesis record");
    };
    Ok((genesis_id, genesis))
}

pub(crate) fn secrets(store: &Store, password: &str, genesis: &Genesis) -> Result<Secrets> {
    match fs::symlink_metadata(store.path().join("control/membership-pending")) {
        Ok(_) => bail!("membership or key rotation transition is pending"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let keys = Secrets::unlock(&genesis.collection, &store.read_control("keys")?, password)?;
    match load_policy(store, genesis)? {
        Some(policy) => ensure!(
            policy.collection == genesis.collection
                && policy.members.iter().any(|member| {
                    member.key == keys.root()
                        && !member.revoked
                        && matches!(
                            member.role,
                            crate::policy::Role::Reader | crate::policy::Role::Writer
                        )
                }),
            "device is not an active collection member"
        ),
        None => ensure!(
            keys.root() == genesis.root,
            "key material does not match pinned root"
        ),
    }
    Ok(keys)
}

/// Creates a new, explicit local collection. Never reuses an existing directory.
pub fn init(path: &Path, password: &str) -> Result<Id> {
    ensure!(!password.is_empty(), "empty passwords are not allowed");
    let keys = Secrets::generate();
    let collection = random_id();
    let genesis_bytes = keys.sign_genesis(collection)?;
    let encrypted_keys = keys.lock(&collection, password)?;
    let store = Store::create(path)?;
    let genesis_id = store.put(&genesis_bytes)?;
    store.write_new_control("keys", &encrypted_keys)?;
    store.write_new_control("genesis", &genesis_id)?;
    Ok(genesis_id)
}
fn find_attestation(
    store: &Store,
    policy: &crate::policy::Policy,
    snapshot: &Snapshot,
    id: &Id,
) -> Result<Id> {
    let mut scanned = 0usize;
    for item in fs::read_dir(store.path().join("objects"))? {
        scanned += 1;
        ensure!(
            scanned <= MAX_OBJECT_SCAN,
            "attestation scan limit exceeded"
        );
        let item = item?;
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.len() != 64 {
            continue;
        }
        let Ok(object_id) = format::parse_id(&name) else {
            continue;
        };
        let Ok(raw) = store.get(&object_id) else {
            continue;
        };
        let Ok(attestation) = crate::policy::Attestation::decode(&raw) else {
            continue;
        };
        if attestation.snapshot == *id
            && policy
                .authorize_attested_snapshot(snapshot, id, &attestation)
                .is_ok()
        {
            return Ok(object_id);
        }
    }
    bail!("snapshot is outside the accepted policy frontier and has no valid writer attestation")
}

pub(crate) fn load_policy(
    store: &Store,
    genesis: &Genesis,
) -> Result<Option<crate::policy::Policy>> {
    let path = store.path().join("control/policy");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(metadata.is_file(), "invalid policy pin");
            crate::policy::Policy::load(store, &genesis.root)?
                .context("policy pin could not be read")
                .map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(crate) type AttestationIndex = BTreeMap<(Id, [u8; 32]), (Id, crate::policy::Attestation)>;

pub(crate) fn attestation_index(
    store: &Store,
    policy: &crate::policy::Policy,
) -> Result<AttestationIndex> {
    let mut index = BTreeMap::new();
    let mut scanned = 0usize;
    for item in fs::read_dir(store.path().join("objects"))? {
        scanned += 1;
        ensure!(
            scanned <= MAX_OBJECT_SCAN,
            "attestation scan limit exceeded"
        );
        let item = item?;
        let path = item.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > 256 {
            continue;
        }
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(object_id) = format::parse_id(&name) else {
            continue;
        };
        let Ok(raw) = store.get(&object_id) else {
            continue;
        };
        let Ok(attestation) = crate::policy::Attestation::decode(&raw) else {
            continue;
        };
        if attestation.verify(policy).is_ok() {
            index
                .entry((attestation.snapshot, attestation.writer))
                .or_insert((object_id, attestation));
        }
    }
    Ok(index)
}

fn snapshot_with_index(
    store: &Store,
    id: &Id,
    genesis_id: &Id,
    genesis: &Genesis,
    policy: Option<&crate::policy::Policy>,
    attestations: &AttestationIndex,
) -> Result<Snapshot> {
    let Record::Snapshot(record) = format::inspect(&store.get(id)?)? else {
        bail!("expected a snapshot record");
    };
    let attestation = attestations.get(&(*id, record.writer)).map(|(_, a)| a);
    authorize_descriptor(&record, id, genesis_id, genesis, policy, attestation)?;
    Ok(record)
}

pub(crate) fn authorize_descriptor(
    record: &Snapshot,
    id: &Id,
    genesis_id: &Id,
    genesis: &Genesis,
    policy: Option<&crate::policy::Policy>,
    attestation: Option<&crate::policy::Attestation>,
) -> Result<()> {
    ensure!(
        record.collection == genesis.collection && record.genesis == *genesis_id,
        "snapshot belongs to a different collection"
    );
    match policy {
        Some(policy) if policy.authorize_snapshot_id(record, id).is_ok() => Ok(()),
        Some(policy) => policy.authorize_attested_snapshot(
            record,
            id,
            attestation.context("snapshot outside accepted policy frontier")?,
        ),
        None => {
            ensure!(
                record.writer == genesis.root,
                "snapshot signer is not the pinned root"
            );
            Ok(())
        }
    }
}

pub(crate) fn ancestry(
    store: &Store,
    root: &Id,
    genesis_id: &Id,
    genesis: &Genesis,
) -> Result<BTreeMap<Id, Snapshot>> {
    let policy = load_policy(store, genesis)?;
    let attestations = match &policy {
        Some(policy) => attestation_index(store, policy)?,
        None => BTreeMap::new(),
    };
    let mut visited = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut stack = vec![(*root, false)];
    while let Some((id, exiting)) = stack.pop() {
        if exiting {
            active.remove(&id);
            continue;
        }
        ensure!(!active.contains(&id), "snapshot ancestry cycle");
        if visited.contains_key(&id) {
            continue;
        }
        ensure!(
            visited.len() < MAX_HISTORY,
            "snapshot history limit exceeded"
        );
        let record = snapshot_with_index(
            store,
            &id,
            genesis_id,
            genesis,
            policy.as_ref(),
            &attestations,
        )?;
        active.insert(id);
        stack.push((id, true));
        for parent in record.parents.iter().rev() {
            ensure!(!active.contains(parent), "snapshot ancestry cycle");
            stack.push((*parent, false));
        }
        visited.insert(id, record);
    }
    Ok(visited)
}

fn inspect_closure(store: &Store, record: &Snapshot) -> Result<u64> {
    ensure!(
        record.objects.contains(&record.manifest),
        "manifest is absent from closure"
    );
    let mut bytes = 0_u64;
    for id in &record.objects {
        let object = store.get(id)?;
        let Record::Encrypted { collection, kind } = format::inspect(&object)? else {
            bail!("snapshot closure contains a non-encrypted record");
        };
        ensure!(
            collection == record.collection,
            "cross-collection closure object"
        );
        ensure!(
            kind == if *id == record.manifest { 2 } else { 1 },
            "wrong encrypted object kind"
        );
        bytes = bytes
            .checked_add(object.len() as u64)
            .context("closure length overflow")?;
    }
    Ok(bytes)
}

fn entries_for(store: &Store, record: &Snapshot, keys: &Secrets) -> Result<Vec<Entry>> {
    let manifest =
        Zeroizing::new(keys.open(&record.collection, 2, &store.get(&record.manifest)?)?);
    let entries = format::decode_manifest(&manifest)?;
    let mut expected = BTreeSet::from([record.manifest]);
    let mut total_refs = 0_usize;
    let mut total_bytes = 0_u64;
    for entry in &entries {
        if entry.directory {
            continue;
        }
        total_bytes = total_bytes
            .checked_add(entry.size)
            .context("file length overflow")?;
        ensure!(
            total_bytes <= MAX_TOTAL_BYTES,
            "snapshot plaintext byte limit exceeded"
        );
        total_refs = total_refs
            .checked_add(entry.chunks.len())
            .context("reference count overflow")?;
        ensure!(
            total_refs <= MAX_CHUNKS,
            "snapshot reference limit exceeded"
        );
        let mut hash = Sha256::new();
        let mut size = 0_u64;
        for (index, id) in entry.chunks.iter().enumerate() {
            let chunk = Zeroizing::new(keys.open(&record.collection, 1, &store.get(id)?)?);
            ensure!(
                !chunk.is_empty() && chunk.len() <= CHUNK_SIZE,
                "invalid plaintext chunk size"
            );
            ensure!(
                index + 1 == entry.chunks.len() || chunk.len() == CHUNK_SIZE,
                "short nonfinal chunk"
            );
            size = size
                .checked_add(chunk.len() as u64)
                .context("file length overflow")?;
            ensure!(
                size <= entry.size,
                "chunk lengths exceed declared file size"
            );
            hash.update(&*chunk);
            expected.insert(*id);
        }
        ensure!(size == entry.size, "file length mismatch");
        let digest: Id = hash.finalize().into();
        ensure!(digest == entry.digest, "file digest mismatch");
    }
    let actual: BTreeSet<Id> = record.objects.iter().copied().collect();
    ensure!(
        expected == actual,
        "manifest and public ciphertext closure disagree"
    );
    Ok(entries)
}
fn entries_with_epoch_keys(
    store: &Store,
    genesis: &Genesis,
    record: &Snapshot,
    active: &Secrets,
    password: &str,
) -> Result<(Option<Secrets>, Vec<Entry>)> {
    if let Ok(entries) = entries_for(store, record, active) {
        return Ok((None, entries));
    }
    let Some(mut policy) = load_policy(store, genesis)? else {
        bail!("snapshot cannot be opened with the collection key");
    };
    let active_policy_id = policy.id()?;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_HISTORY {
        ensure!(seen.insert(policy.id()?), "policy chain cycle");
        let Some(previous) = policy.previous else {
            break;
        };
        let raw = store.get(&previous)?;
        ensure!(
            format::id(&raw) == previous,
            "policy history digest mismatch"
        );
        let parent = crate::policy::Policy::decode(&raw)?;
        parent.verify(&genesis.root)?;
        ensure!(
            parent.collection == genesis.collection
                && parent.epoch.checked_add(1) == Some(policy.epoch),
            "invalid policy history link"
        );
        if previous != active_policy_id
            && let Ok(keys) = crate::devices::secrets_for_policy(store, previous, password)
            && let Ok(entries) = entries_for(store, record, &keys)
        {
            return Ok((Some(keys), entries));
        }
        policy = parent;
    }
    bail!("no retained epoch key can decrypt this snapshot")
}

pub fn verify(path: &Path, selected: &Id, password: Option<&str>) -> Result<Verification> {
    let store = Store::open(path)?;
    let (genesis_id, genesis) = pinned(&store)?;
    let graph = ancestry(&store, selected, &genesis_id, &genesis)?;
    let record = graph.get(selected).context("missing selected snapshot")?;
    let bytes = inspect_closure(&store, record)?;
    if let Some(password) = password {
        let active = secrets(&store, password, &genesis)?;
        entries_with_epoch_keys(&store, &genesis, record, &active, password)?;
    }
    Ok(Verification {
        snapshot: *selected,
        genesis: genesis_id,
        objects: record.objects.len(),
        bytes,
        ancestors: graph.len() - 1,
        materialized: password.is_some(),
    })
}

pub(crate) fn entries_for_id(path: &Path, selected: &Id, password: &str) -> Result<Vec<Entry>> {
    let store = Store::open(path)?;
    let (genesis_id, genesis) = pinned(&store)?;
    let graph = ancestry(&store, selected, &genesis_id, &genesis)?;
    let record = graph.get(selected).context("missing selected snapshot")?;
    let active = secrets(&store, password, &genesis)?;
    inspect_closure(&store, record)?;
    let (_, entries) = entries_with_epoch_keys(&store, &genesis, record, &active, password)?;
    Ok(entries)
}

struct Capture<'a> {
    store: &'a Store,
    keys: &'a Secrets,
    reuse_keys: &'a Secrets,
    collection: &'a Id,
    entries: Vec<Entry>,
    previous: BTreeMap<String, Entry>,
    objects: BTreeSet<Id>,
    chunks: usize,
    bytes: u64,
}

impl Capture<'_> {
    fn directory(&mut self, anchored: &Path, relative: &str) -> Result<()> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(
                rustix::fs::OFlags::NOFOLLOW.bits() as i32
                    | rustix::fs::OFlags::DIRECTORY.bits() as i32,
            )
            .open(anchored)
            .context("cannot open source directory safely")?;
        // Linux descriptor anchoring prevents a renamed directory being replaced with a symlink.
        use std::os::fd::AsRawFd;
        let fd_path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        let before = dir.metadata()?;
        let mut names = Vec::new();
        for item in fs::read_dir(&fd_path)? {
            ensure!(
                self.entries.len() + names.len() < MAX_ENTRIES,
                "entry limit exceeded"
            );
            names.push(
                item?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF8 source name"))?,
            );
        }
        names.sort();
        for name in names {
            ensure!(
                !name.contains(['/', '\\']) && name != "." && name != "..",
                "unsupported source name"
            );
            ensure!(name.len() <= 255, "name length limit exceeded");
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            ensure!(
                path.len() <= 4096 && path.split('/').count() <= 64,
                "path limit exceeded"
            );
            ensure!(self.entries.len() < MAX_ENTRIES, "entry limit exceeded");
            let child_name = path.rsplit('/').next().context("missing source name")?;
            let child = fd_path.join(child_name);
            let metadata = fs::symlink_metadata(&child)?;
            let previous_entry = self.previous.get(&path);
            let entry_id = previous_entry
                .map(|entry| entry.entry_id)
                .unwrap_or_else(random_id);
            if metadata.is_dir() {
                self.entries.push(Entry {
                    entry_id,
                    path: path.clone(),
                    directory: true,
                    size: 0,
                    digest: Sha256::digest([]).into(),
                    chunks: Vec::new(),
                });
                self.directory(&child, &path)?;
            } else if metadata.is_file() {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        rustix::fs::OFlags::NOFOLLOW.bits() as i32
                            | rustix::fs::OFlags::NONBLOCK.bits() as i32,
                    )
                    .open(&child)?;
                let start = file.metadata()?;
                ensure!(
                    start.is_file()
                        && start.dev() == metadata.dev()
                        && start.ino() == metadata.ino(),
                    "source file changed while opening"
                );
                ensure!(
                    start.len() <= MAX_TOTAL_BYTES.saturating_sub(self.bytes),
                    "snapshot byte limit exceeded"
                );
                let mut chunks = Vec::new();
                let mut hash = Sha256::new();
                let mut size = 0_u64;
                loop {
                    let mut buffer = Zeroizing::new(vec![0; CHUNK_SIZE]);
                    let mut used = 0;
                    while used < CHUNK_SIZE {
                        let count = file.read(&mut buffer[used..])?;
                        if count == 0 {
                            break;
                        }
                        used += count;
                    }
                    if used == 0 {
                        break;
                    }
                    self.chunks += 1;
                    // One public closure slot is reserved for the encrypted manifest.
                    ensure!(
                        self.chunks < MAX_CHUNKS,
                        "snapshot chunk limit exceeded (manifest slot reserved)"
                    );
                    self.bytes += used as u64;
                    ensure!(
                        self.bytes <= MAX_TOTAL_BYTES,
                        "snapshot byte limit exceeded"
                    );
                    hash.update(&buffer[..used]);
                    size += used as u64;
                    let reused_id = if self.keys.epoch_key() == self.reuse_keys.epoch_key() {
                        previous_entry
                            .and_then(|entry| entry.chunks.get(chunks.len()))
                            .copied()
                    } else {
                        None
                    };
                    let id = if let Some(id) = reused_id {
                        let raw = self.store.get(&id)?;
                        let plain =
                            Zeroizing::new(self.reuse_keys.open(self.collection, 1, &raw)?);
                        if plain.as_slice() == &buffer[..used] {
                            id
                        } else {
                            self.store.put(&self.keys.seal(
                                self.collection,
                                1,
                                &buffer[..used],
                            )?)?
                        }
                    } else {
                        self.store
                            .put(&self.keys.seal(self.collection, 1, &buffer[..used])?)?
                    };
                    chunks.push(id);
                    self.objects.insert(id);
                    if used < CHUNK_SIZE {
                        break;
                    }
                }
                let finish = file.metadata()?;
                let after_path = fs::symlink_metadata(&child)?;
                ensure!(
                    same_file(&start, &finish)
                        && same_file(&start, &after_path)
                        && size == start.len(),
                    "source file changed during capture"
                );
                self.entries.push(Entry {
                    entry_id,
                    path,
                    directory: false,
                    size,
                    digest: hash.finalize().into(),
                    chunks,
                });
            } else {
                bail!("symlinks and special source files are unsupported");
            }
        }
        ensure!(
            same_file(&before, &dir.metadata()?),
            "source directory changed during capture"
        );
        Ok(())
    }
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.file_type() == b.file_type()
}

pub fn capture(path: &Path, source: &Path, password: &str) -> Result<Id> {
    capture_impl(path, source, password, None, None)
}

pub fn merge_capture(path: &Path, source: &Path, parents: &[Id], password: &str) -> Result<Id> {
    ensure!(
        parents.len() >= 2,
        "explicit merge requires at least two parents"
    );
    let mut unique = parents.to_vec();
    unique.sort();
    unique.dedup();
    ensure!(
        unique.len() >= 2,
        "explicit merge requires two distinct parents"
    );
    capture_impl(path, source, password, Some(parents[0]), Some(unique))
}

fn capture_impl(
    path: &Path,
    source: &Path,
    password: &str,
    base: Option<Id>,
    merge_parents: Option<Vec<Id>>,
) -> Result<Id> {
    let store = Store::open(path)?;
    let writer_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(store.path().join("control/writer.lock"))?;
    ensure!(writer_lock.metadata()?.is_file(), "invalid writer lock");
    writer_lock
        .try_lock()
        .context("another local writer is active")?;
    let (genesis_id, genesis) = pinned(&store)?;
    let keys = secrets(&store, password, &genesis)?;
    if let Some(policy) = load_policy(&store, &genesis)? {
        ensure!(
            policy.allows_writer(&keys.root()),
            "device is not an active writer in policy"
        );
    }
    ensure!(
        !fs::symlink_metadata(source)?.file_type().is_symlink(),
        "source may not be a symlink"
    );
    let source = source.canonicalize()?;
    let node = store.path().canonicalize()?;
    ensure!(
        !node.starts_with(&source),
        "node storage may not be inside capture source"
    );
    let root_directory = rustix::fs::openat2(
        rustix::fs::CWD,
        &source,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot safely anchor capture root (Linux openat2 required)")?;
    let head = store.head()?;
    let selected_base = base.or(head);
    let mut parents = merge_parents.unwrap_or_else(|| selected_base.into_iter().collect());
    parents.sort();
    parents.dedup();
    ensure!(parents.len() <= 64, "snapshot parent limit exceeded");
    let mut previous = BTreeMap::new();
    let mut baseline_keys = None;
    if let Some(base_id) = selected_base {
        let graph = ancestry(&store, &base_id, &genesis_id, &genesis)?;
        let parent = graph
            .get(&base_id)
            .context("missing selected base snapshot")?;
        inspect_closure(&store, parent)?;
        let (old_keys, entries) =
            entries_with_epoch_keys(&store, &genesis, parent, &keys, password)?;
        baseline_keys = old_keys;
        previous = entries
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
    }
    for parent in &parents {
        ancestry(&store, parent, &genesis_id, &genesis)?;
    }
    let reuse_keys = baseline_keys.as_ref().unwrap_or(&keys);
    let mut state = Capture {
        store: &store,
        reuse_keys,
        keys: &keys,
        collection: &genesis.collection,
        entries: Vec::new(),
        previous,
        objects: BTreeSet::new(),
        chunks: 0,
        bytes: 0,
    };
    use std::os::fd::AsRawFd;
    let anchored_root = PathBuf::from(format!("/proc/self/fd/{}/.", root_directory.as_raw_fd()));
    state.directory(&anchored_root, "")?;
    state
        .entries
        .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let manifest_plain = Zeroizing::new(format::encode_manifest(&state.entries)?);
    let manifest = store.put(&keys.seal(&genesis.collection, 2, &manifest_plain)?)?;
    state.objects.insert(manifest);
    ensure!(
        state.objects.len() <= MAX_CHUNKS,
        "snapshot closure limit exceeded"
    );
    let snapshot = Snapshot {
        collection: genesis.collection,
        genesis: genesis_id,
        writer: keys.root(),
        parents,
        manifest,
        objects: state.objects.into_iter().collect(),
    };
    let bytes = keys.sign_snapshot(&snapshot)?;
    // Publishing the pointer follows complete local validation and durable object writes.
    let id = store.put(&bytes)?;
    inspect_closure(&store, &snapshot)?;
    entries_for(&store, &snapshot, &keys)?;
    if let Some(policy) = load_policy(&store, &genesis)? {
        ensure!(
            policy.allows_writer(&keys.root()),
            "device is not an active writer in policy"
        );
        let signing_seed = Zeroizing::new(keys.signing_seed());
        let signer = crate::crypto::DeviceSecrets::from_seed(*signing_seed);
        let attestation = policy.attest(id, &signer)?;
        store.put(&attestation.encode()?)?;
    }
    ensure!(
        store.head()? == head,
        "local head changed during capture; snapshot retained, head not updated"
    );
    store.set_head(&id)?;
    Ok(id)
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn restore(path: &Path, selected: &Id, destination: &Path, password: &str) -> Result<()> {
    let store = Store::open(path)?;
    let (genesis_id, genesis) = pinned(&store)?;
    let active_keys = secrets(&store, password, &genesis)?;
    let graph = ancestry(&store, selected, &genesis_id, &genesis)?;
    let record = graph.get(selected).context("missing selected snapshot")?;
    inspect_closure(&store, record)?;
    let (old_keys, entries) =
        entries_with_epoch_keys(&store, &genesis, record, &active_keys, password)?;
    let keys = old_keys.as_ref().unwrap_or(&active_keys);
    ensure!(
        destination.file_name().is_some(),
        "restore destination must name a new directory"
    );
    ensure!(
        !destination.try_exists()?,
        "restore destination already exists"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let destination = parent.join(destination.file_name().context("invalid destination")?);
    let stage = Staging(parent.join(format!(".arc-restore-{}", hex::encode(random_id()))));
    fs::DirBuilder::new().mode(0o700).create(&stage.0)?;
    for entry in &entries {
        let output = stage.0.join(&entry.path);
        if entry.directory {
            fs::DirBuilder::new().mode(0o700).create(&output)?;
        } else {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&output)?;
            let mut hash = Sha256::new();
            let mut size = 0_u64;
            for id in &entry.chunks {
                let plain = Zeroizing::new(keys.open(&genesis.collection, 1, &store.get(id)?)?);
                file.write_all(&plain)?;
                hash.update(&*plain);
                size += plain.len() as u64;
            }
            let digest: Id = hash.finalize().into();
            ensure!(
                size == entry.size && digest == entry.digest,
                "restore content changed"
            );
            file.sync_all()?;
        }
    }
    // Flush nested directories before publishing the new destination.
    for entry in entries.iter().rev().filter(|e| e.directory) {
        File::open(stage.0.join(&entry.path))?.sync_all()?;
    }
    File::open(&stage.0)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &stage.0,
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("cannot publish restore without overwriting destination")?;
    File::open(&parent)?.sync_all()?;
    Ok(())
}

fn add_policy_bundle_objects(
    store: &Store,
    genesis: &Genesis,
    graph: &BTreeMap<Id, Snapshot>,
    ids: &mut BTreeSet<Id>,
) -> Result<()> {
    let Some(mut policy) = load_policy(store, genesis)? else {
        return Ok(());
    };
    for (id, snapshot) in graph {
        if policy.authorize_snapshot_id(snapshot, id).is_err() {
            ids.insert(find_attestation(store, &policy, snapshot, id)?);
        }
    }
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_HISTORY {
        let id = policy.id()?;
        ensure!(seen.insert(id), "policy chain cycle");
        let bytes = store.get(&id)?;
        ensure!(format::id(&bytes) == id, "policy digest mismatch");
        ids.insert(id);
        let Some(previous) = policy.previous else {
            ensure!(
                policy.epoch == 0,
                "policy chain does not start at epoch zero"
            );
            return Ok(());
        };
        let raw = store.get(&previous)?;
        ensure!(
            format::id(&raw) == previous,
            "previous policy digest mismatch"
        );
        let parent = crate::policy::Policy::decode(&raw)?;
        parent.verify(&genesis.root)?;
        ensure!(
            parent.collection == genesis.collection
                && parent.epoch.checked_add(1) == Some(policy.epoch),
            "invalid policy chain link"
        );
        policy = parent;
    }
    bail!("policy chain exceeds history limit")
}
/// Exports pinned genesis, ancestry descriptors, and the selected snapshot's ciphertext closure.
pub fn export(path: &Path, selected: &Id, destination: &Path) -> Result<()> {
    let store = Store::open(path)?;
    let (genesis_id, genesis) = pinned(&store)?;
    let graph = ancestry(&store, selected, &genesis_id, &genesis)?;
    let record = graph.get(selected).context("missing selected snapshot")?;
    inspect_closure(&store, record)?;
    let mut ids: BTreeSet<Id> = graph.keys().copied().collect();
    add_policy_bundle_objects(&store, &genesis, &graph, &mut ids)?;
    ids.insert(genesis_id);
    ids.extend(record.objects.iter().copied());
    crate::bundle::export(&store, &ids.into_iter().collect::<Vec<_>>(), destination)
}

/// Imports bytes without changing the trusted genesis, keys or current head.
pub fn import(path: &Path, source: &Path) -> Result<usize> {
    let store = Store::open(path)?;
    pinned(&store)?;
    Ok(crate::bundle::import(&store, source)?.len())
}

/// Exports a password-authenticated kit of all locally stored immutable objects
/// (64 MiB maximum), pinned policy/key controls and any member device key.
/// Foreign, incomplete, or opaque local CAS objects are preserved verbatim; absent remote data is not included.
/// Snapshot-head selection is not included or inferred during recovery.
pub fn export_recovery(path: &Path, destination: &Path, password: &str) -> Result<()> {
    let store = Store::open(path)?;
    let writer_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(store.path().join("control/writer.lock"))?;
    ensure!(writer_lock.metadata()?.is_file(), "invalid writer lock");
    writer_lock
        .try_lock()
        .context("another local writer is active")?;
    let (genesis_id, genesis) = pinned(&store)?;
    match fs::symlink_metadata(store.path().join("control/membership-pending")) {
        Ok(_) => bail!("membership or key rotation transition is pending"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let locked_keys = store.read_control("keys")?;
    if let Some(policy) = load_policy(&store, &genesis)? {
        let policy_id: Id = store
            .read_control("policy")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid policy pin"))?;
        let keys = crate::devices::secrets_for_policy(&store, policy_id, password)?;
        ensure!(
            policy
                .members
                .iter()
                .any(|m| m.key == keys.root() && !m.revoked),
            "node key is not active in current policy"
        );
        if keys.root() != genesis.root {
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(
                    rustix::fs::OFlags::NOFOLLOW.bits() as i32
                        | rustix::fs::OFlags::NONBLOCK.bits() as i32,
                )
                .open(store.path().join("device-key"))?;
            ensure!(
                f.metadata()?.is_file() && f.metadata()?.len() <= 256,
                "invalid device key file"
            );
            let mut raw = Vec::new();
            f.take(257).read_to_end(&mut raw)?;
            let device = crate::crypto::DeviceSecrets::unlock(&raw, password)?;
            ensure!(
                device.public() == keys.root(),
                "device key does not match member keys"
            );
        } else {
            ensure!(
                !store.path().join("device-key").exists(),
                "admin recovery must not carry a member device key"
            );
        }
    } else {
        let unlocked = Secrets::unlock(&genesis.collection, &locked_keys, password)?;
        ensure!(
            unlocked.root() == genesis.root,
            "recovery key/root mismatch"
        );
    }
    crate::recovery::export(&store, &genesis_id, destination, password)
}

/// Reconstructs a fresh node using a separately supplied trusted genesis ID.
/// The restored node retains the same identity: retire the original before reuse.
/// The pin authenticates collection identity only, not global policy freshness.
pub fn recover(path: &Path, kit: &Path, expected_genesis: &Id, password: &str) -> Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(kit)?;
    ensure!(input.metadata()?.is_file(), "invalid recovery kit file");
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic == b"ARCRCV2\n" {
        drop(input);
        return crate::recovery::recover(path, kit, expected_genesis, password);
    }
    ensure!(&magic == b"ARCKEY1\n", "unsupported recovery kit");
    ensure!(
        input.metadata()?.len() <= 2 * format::MAX_OBJECT as u64 + 48,
        "invalid legacy recovery kit"
    );
    let mut genesis_id = [0; 32];
    input.read_exact(&mut genesis_id)?;
    ensure!(
        &genesis_id == expected_genesis,
        "recovery identity pin mismatch"
    );
    let mut read_record = || -> Result<Vec<u8>> {
        let mut raw = [0; 4];
        input.read_exact(&mut raw)?;
        let size = u32::from_be_bytes(raw) as usize;
        ensure!(
            size > 0 && size <= format::MAX_OBJECT,
            "recovery record size out of bounds"
        );
        let mut data = vec![0; size];
        input.read_exact(&mut data)?;
        Ok(data)
    };
    let genesis_bytes = read_record()?;
    let locked_keys = read_record()?;
    let mut trailing = [0];
    ensure!(
        input.read(&mut trailing)? == 0,
        "trailing recovery kit bytes"
    );
    ensure!(
        format::id(&genesis_bytes) == genesis_id,
        "recovery genesis digest mismatch"
    );
    let Record::Genesis(genesis) = format::inspect(&genesis_bytes)? else {
        bail!("invalid recovery genesis")
    };
    let keys = Secrets::unlock(&genesis.collection, &locked_keys, password)?;
    ensure!(keys.root() == genesis.root, "recovery key/root mismatch");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = parent.join(format!(".arc-legacy-recover-{}", hex::encode(random_id())));
    let mut created = false;
    let result = (|| -> Result<()> {
        let store = Store::create(&stage)?;
        created = true;
        store.put(&genesis_bytes)?;
        store.write_new_control("keys", &locked_keys)?;
        store.write_new_control("genesis", &genesis_id)?;
        File::open(&stage)?.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &stage,
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if created && result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}
