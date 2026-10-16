//! Persistent, bounded staging for immutable ciphertext objects.
//! Fragment checksums detect accidental disk damage, not malicious senders. Only the
//! complete object's expected content ID authenticates the assembled bytes.
use crate::{
    format::{self, Id, MAX_OBJECT},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use minicbor::{Decoder, Encoder};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_PARTIALS: usize = 128;
pub const MAX_STAGED: u64 = 32 * 1024 * 1024;
pub const MAX_FRAGMENTS: u32 = 16_384;
pub(crate) const MAX_STATE: usize = MAX_OBJECT + MAX_FRAGMENTS as usize * 48 + 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Pending,
    Published,
    AlreadyPresent,
    Rejected,
}

pub struct Receiver {
    store: Store,
    root: PathBuf,
    _lock: File,
}
struct State {
    size: u64,
    fragment_size: u32,
    parts: BTreeMap<u32, Vec<u8>>,
}
impl Receiver {
    /// The incoming directory must belong to a valid, private Arc node.
    /// The exclusive advisory lock serializes receivers across processes.
    pub fn open(incoming: &Path) -> Result<Self> {
        let store = Store::open(incoming.parent().context("incoming has no node parent")?)?;
        ensure!(
            incoming.file_name().is_some_and(|n| n == "incoming"),
            "expected node incoming directory"
        );
        let root = incoming.join("fragments");
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => File::open(incoming)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        check_dir(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(no_follow())
            .open(root.join("lock"))?;
        ensure!(lock.metadata()?.is_file(), "invalid fragment lock");
        lock.try_lock()
            .context("another fragment receiver is active")?;
        // A fixed scratch name prevents crash leftovers accumulating without a bound.
        let scratch = root.join("write.tmp");
        match fs::symlink_metadata(&scratch) {
            Ok(m) => {
                ensure!(
                    m.is_file() && m.len() <= MAX_STATE as u64,
                    "unsafe fragment scratch file"
                );
                fs::remove_file(&scratch)?;
                File::open(&root)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let receiver = Self {
            store,
            root,
            _lock: lock,
        };
        receiver.usage()?;
        receiver.prune_complete()?;
        Ok(receiver)
    }
    fn path(&self, id: &Id) -> PathBuf {
        self.root.join(hex::encode(id))
    }
    fn usage(&self) -> Result<(usize, u64)> {
        check_dir(&self.root)?;
        let mut count = 0;
        let mut total = 0u64;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_name() == "lock" {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_str().context("invalid fragment filename")?;
            ensure!(
                name.len() == 64
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "unexpected fragment file"
            );
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(
                meta.is_file() && meta.mode() & 0o077 == 0 && meta.len() <= MAX_STATE as u64,
                "unsafe fragment state file"
            );
            count += 1;
            total = total
                .checked_add(meta.len())
                .context("fragment quota overflow")?;
            ensure!(
                count <= MAX_PARTIALS && total <= MAX_STAGED,
                "fragment staging quota exceeded"
            );
        }
        Ok((count, total))
    }
    fn prune_complete(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "lock" {
                continue;
            }
            let id: Id = hex::decode(name.to_str().context("invalid fragment filename")?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid fragment ID"))?;
            if self.store.contains(&id)? {
                self.discard(&id)?;
            }
        }
        Ok(())
    }
    /// Explicitly discard one partial object, without changing the immutable store.
    pub fn discard(&self, id: &Id) -> Result<()> {
        let path = self.path(id);
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                ensure!(m.is_file(), "unsafe fragment state file");
                fs::remove_file(path)?;
                File::open(&self.root)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
    fn load(&self, id: &Id) -> Result<Option<State>> {
        let path = self.path(id);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(no_follow())
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= MAX_STATE as u64 && meta.mode() & 0o077 == 0,
            "unsafe fragment state"
        );
        let mut raw = Vec::new();
        file.take((MAX_STATE + 1) as u64).read_to_end(&mut raw)?;
        ensure!(raw.len() <= MAX_STATE, "fragment state exceeds limit");
        let mut d = Decoder::new(&raw);
        ensure!(
            d.array()? == Some(5) && d.u8()? == 1 && d.bytes()? == id,
            "invalid fragment state identity"
        );
        let size = d.u64()?;
        let fragment_size = d.u32()?;
        validate(size, fragment_size)?;
        let n = d.array()?.context("indefinite fragment array")?;
        ensure!(
            n <= u64::from(count(size, fragment_size)),
            "too many stored fragments"
        );
        let mut parts = BTreeMap::new();
        let mut previous = None;
        for _ in 0..n {
            ensure!(d.array()? == Some(3), "invalid stored fragment");
            let index = d.u32()?;
            ensure!(
                index < count(size, fragment_size) && previous.is_none_or(|p| p < index),
                "invalid fragment index order"
            );
            previous = Some(index);
            let payload = d.bytes()?;
            let digest = d.bytes()?;
            ensure!(
                payload.len() == fragment_length(size, fragment_size, index) && digest.len() == 32,
                "invalid stored fragment length"
            );
            // Bad checksums become missing fragments; none are published until final verification.
            if format::id(payload).as_slice() == digest {
                parts.insert(index, payload.to_vec());
            }
        }
        ensure!(d.position() == raw.len(), "trailing fragment state data");
        Ok(Some(State {
            size,
            fragment_size,
            parts,
        }))
    }
    pub fn missing(&self, id: &Id, size: u64, fragment_size: u32) -> Result<Vec<u32>> {
        validate(size, fragment_size)?;
        if self.store.contains(id)? {
            self.discard(id)?;
            return Ok(Vec::new());
        }
        let state = self.load(id)?;
        if let Some(s) = &state {
            ensure!(
                (s.size, s.fragment_size) == (size, fragment_size),
                "conflicting fragment metadata; discard partial before changing MTU"
            );
        }
        Ok((0..count(size, fragment_size))
            .filter(|i| state.as_ref().is_none_or(|s| !s.parts.contains_key(i)))
            .collect())
    }
    pub fn accept(
        &mut self,
        id: &Id,
        size: u64,
        fragment_size: u32,
        index: u32,
        bytes: &[u8],
    ) -> Result<bool> {
        Ok(self.accept_fragment(id, size, fragment_size, index, bytes)? == Admission::Published)
    }
    /// Callers handling batches must stop an object's batch after a rejected assembly.
    pub fn accept_fragment(
        &mut self,
        id: &Id,
        size: u64,
        fragment_size: u32,
        index: u32,
        bytes: &[u8],
    ) -> Result<Admission> {
        validate(size, fragment_size)?;
        ensure!(
            index < count(size, fragment_size)
                && bytes.len() == fragment_length(size, fragment_size, index),
            "invalid fragment index or length"
        );
        if self.store.contains(id)? {
            self.discard(id)?;
            return Ok(Admission::AlreadyPresent);
        }
        let mut state = self.load(id)?.unwrap_or_else(|| State {
            size,
            fragment_size,
            parts: BTreeMap::new(),
        });
        ensure!(
            (state.size, state.fragment_size) == (size, fragment_size),
            "conflicting fragment metadata"
        );
        state.parts.insert(index, bytes.to_vec());
        if state.parts.len() == count(size, fragment_size) as usize {
            let mut complete = Vec::with_capacity(size as usize);
            for part in state.parts.values() {
                complete.extend_from_slice(part);
            }
            if format::id(&complete) == *id {
                self.store.put(&complete)?;
                self.discard(id)?;
                return Ok(Admission::Published);
            }
            // Unauthenticated bad bytes cannot poison future clean attempts indefinitely.
            self.discard(id)?;
            return Ok(Admission::Rejected);
        }
        self.save(id, &state)?;
        Ok(Admission::Pending)
    }
    fn save(&self, id: &Id, state: &State) -> Result<()> {
        let mut bytes = Vec::new();
        let mut e = Encoder::new(&mut bytes);
        e.array(5)?
            .u8(1)?
            .bytes(id)?
            .u64(state.size)?
            .u32(state.fragment_size)?
            .array(state.parts.len() as u64)?;
        for (index, data) in &state.parts {
            e.array(3)?
                .u32(*index)?
                .bytes(data)?
                .bytes(&format::id(data))?;
        }
        ensure!(bytes.len() <= MAX_STATE, "fragment state too large");
        let (entries, total) = self.usage()?;
        let old_size = match fs::symlink_metadata(self.path(id)) {
            Ok(m) => {
                ensure!(m.is_file(), "unsafe fragment state");
                Some(m.len())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            old_size.is_some() || entries < MAX_PARTIALS,
            "partial object quota exceeded"
        );
        ensure!(
            total - old_size.unwrap_or(0) + bytes.len() as u64 <= MAX_STAGED,
            "partial byte quota exceeded"
        );
        let temp = self.root.join("write.tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow())
            .open(&temp)?;
        let result = (|| -> Result<()> {
            f.write_all(&bytes)?;
            f.sync_all()?;
            fs::rename(&temp, self.path(id))?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}
fn validate(size: u64, fragment: u32) -> Result<()> {
    ensure!(
        size <= MAX_OBJECT as u64 && fragment > 0 && fragment as usize <= MAX_OBJECT,
        "invalid fragment metadata"
    );
    ensure!(
        count(size, fragment) <= MAX_FRAGMENTS,
        "too many fragments for object; increase MTU"
    );
    Ok(())
}
fn count(size: u64, fragment: u32) -> u32 {
    size.max(1).div_ceil(u64::from(fragment)) as u32
}
fn fragment_length(size: u64, fragment: u32, index: u32) -> usize {
    (size - u64::from(index) * u64::from(fragment)).min(u64::from(fragment)) as usize
}
fn no_follow() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32
}
fn check_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.mode() & 0o077 == 0,
        "fragment directory must be private and non-symlink"
    );
    Ok(())
}
