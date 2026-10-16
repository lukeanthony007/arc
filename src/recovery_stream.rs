//! ARCRCV3: independently authenticated bounded records with a mandatory final commitment.
use super::{CONTROLS, key};
use crate::{
    format::{self, Id, MAX_OBJECT, Record},
    store::Store,
};
use anyhow::{Result, bail, ensure};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use minicbor::Decoder;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use zeroize::Zeroizing;

pub(super) const MAGIC: &[u8; 8] = b"ARCRCV3\n";
const MAX_COUNT: u64 = 1_000_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_FRAME: usize = MAX_OBJECT + 64;
const CONTROL: u8 = 1;
const DEVICE: u8 = 2;
const OBJECT: u8 = 3;
const FINAL: u8 = 255;

fn open_read(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "recovery input must be a regular file"
    );
    Ok(file)
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn nonce(header: &[u8; 40], sequence: u64) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&header[24..40]);
    nonce[16..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}
fn aad(header: &[u8; 40], sequence: u64, kind: u8, size: u32) -> Vec<u8> {
    [
        header.as_slice(),
        &sequence.to_be_bytes(),
        &[kind],
        &size.to_be_bytes(),
    ]
    .concat()
}
struct Writer<'a> {
    file: &'a mut File,
    cipher: XChaCha20Poly1305,
    header: [u8; 40],
    sequence: u64,
    bytes: u64,
    transcript: Sha256,
}
impl Writer<'_> {
    fn record(&mut self, kind: u8, plain: &[u8]) -> Result<()> {
        let size = u32::try_from(
            plain
                .len()
                .checked_add(16)
                .ok_or_else(|| anyhow::anyhow!("frame overflow"))?,
        )?;
        ensure!(size as usize <= MAX_FRAME, "recovery frame too large");
        let context = aad(&self.header, self.sequence, kind, size);
        let ct = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce(&self.header, self.sequence)),
                Payload {
                    msg: plain,
                    aad: &context,
                },
            )
            .map_err(|_| anyhow::anyhow!("recovery encryption failed"))?;
        self.bytes = self
            .bytes
            .checked_add(5 + ct.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("recovery size overflow"))?;
        ensure!(
            self.bytes <= MAX_BYTES,
            "recovery exceeds 16 GiB encoded limit"
        );
        self.file.write_all(&[kind])?;
        self.file.write_all(&size.to_be_bytes())?;
        self.file.write_all(&ct)?;
        if kind != FINAL {
            self.transcript.update(&context);
            self.transcript.update(&ct);
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("recovery sequence overflow"))?;
        Ok(())
    }
}

pub(super) fn export(
    store: &Store,
    genesis: &Id,
    destination: &Path,
    password: &str,
) -> Result<()> {
    validate(store, genesis, password)?;
    let parent = parent(destination);
    let tmp = parent.join(format!(
        ".arc-recovery-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&tmp)?;
        created = true;
        let mut header = [0; 40];
        header[..8].copy_from_slice(MAGIC);
        OsRng.fill_bytes(&mut header[8..]);
        let salt: &[u8; 16] = header[8..24].try_into()?;
        let derived = key(password, salt)?;
        file.write_all(&header)?;
        let mut writer = Writer {
            file: &mut file,
            cipher: XChaCha20Poly1305::new((&*derived).into()),
            header,
            sequence: 0,
            bytes: 40,
            transcript: Sha256::new(),
        };
        for (index, name) in CONTROLS.iter().enumerate() {
            match store.read_control(name) {
                Ok(bytes) => {
                    let mut plain = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
                    plain.push(index as u8);
                    plain.extend_from_slice(&bytes);
                    writer.record(CONTROL, &plain)?;
                }
                Err(error) if missing(&error) => {}
                Err(error) => return Err(error),
            }
        }
        match open_read(&store.path().join("device-key")) {
            Ok(file) => {
                ensure!(file.metadata()?.len() <= 256, "device key too large");
                let mut bytes = Zeroizing::new(Vec::new());
                file.take(257).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 256, "device key too large");
                writer.record(DEVICE, &bytes)?;
            }
            Err(error) if missing(&error) => {}
            Err(error) => return Err(error),
        }
        let mut count = 0u64;
        let mut total = 0u64;
        let mut seen_genesis = false;
        for (scanned, item) in fs::read_dir(store.path().join("objects"))?.enumerate() {
            ensure!(
                (scanned as u64) < MAX_COUNT * 4,
                "inventory scan limit exceeded"
            );
            let item = item?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid object filename"))?;
            if let Some(suffix) = name.strip_prefix(".tmp-")
                && suffix.len() == 32
                && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            {
                continue;
            }
            let id = format::parse_id(name)?;
            ensure!(
                name == format::display_id(&id),
                "noncanonical object inventory filename"
            );
            let bytes = store.get(&id)?;
            count += 1;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("inventory overflow"))?;
            ensure!(
                count <= MAX_COUNT && total <= MAX_BYTES,
                "recovery inventory exceeds limits"
            );
            seen_genesis |= &id == genesis;
            let mut plain = Zeroizing::new(Vec::with_capacity(32 + bytes.len()));
            plain.extend_from_slice(&id);
            plain.extend_from_slice(&bytes);
            writer.record(OBJECT, &plain)?;
        }
        ensure!(seen_genesis, "pinned genesis missing from inventory");
        let digest = writer.transcript.clone().finalize();
        let final_record = [
            count.to_be_bytes().as_slice(),
            total.to_be_bytes().as_slice(),
            digest.as_slice(),
        ]
        .concat();
        writer.record(FINAL, &final_record)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&tmp, destination)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if created {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub(super) fn recover(path: &Path, kit: &Path, expected: &Id, password: &str) -> Result<()> {
    let mut input = open_read(kit)?;
    ensure!(
        input.metadata()?.len() <= MAX_BYTES,
        "recovery exceeds 16 GiB encoded limit"
    );
    let mut header = [0; 40];
    input.read_exact(&mut header)?;
    ensure!(&header[..8] == MAGIC, "unsupported recovery kit");
    let salt: &[u8; 16] = header[8..24].try_into()?;
    let derived = key(password, salt)?;
    let cipher = XChaCha20Poly1305::new((&*derived).into());
    let parent = parent(path);
    let stage = parent.join(format!(
        ".arc-recover-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let mut created = false;
    let result = (|| -> Result<()> {
        let store = Store::create(&stage)?;
        created = true;
        let mut sequence = 0u64;
        let mut encoded = 40u64;
        let mut transcript = Sha256::new();
        let mut count = 0u64;
        let mut total = 0u64;
        let mut controls = [false; 4];
        let mut device = false;
        let mut objects_started = false;
        loop {
            let mut framing = [0; 5];
            input.read_exact(&mut framing)?;
            let kind = framing[0];
            ensure!(
                [CONTROL, DEVICE, OBJECT, FINAL].contains(&kind),
                "invalid recovery frame kind"
            );
            let size = u32::from_be_bytes(framing[1..].try_into()?) as usize;
            ensure!(
                (16..=MAX_FRAME).contains(&size),
                "invalid recovery frame length"
            );
            encoded = encoded
                .checked_add(5 + size as u64)
                .ok_or_else(|| anyhow::anyhow!("recovery length overflow"))?;
            ensure!(encoded <= MAX_BYTES, "recovery exceeds encoded limit");
            let mut ct = vec![0; size];
            input.read_exact(&mut ct)?;
            let context = aad(&header, sequence, kind, size as u32);
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(&nonce(&header, sequence)),
                        Payload {
                            msg: &ct,
                            aad: &context,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("wrong password or modified recovery stream"))?,
            );
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("recovery sequence overflow"))?;
            if kind == FINAL {
                ensure!(
                    plain.len() == 48 && count > 0,
                    "invalid recovery completion record"
                );
                ensure!(
                    u64::from_be_bytes(plain[..8].try_into()?) == count
                        && u64::from_be_bytes(plain[8..16].try_into()?) == total,
                    "recovery completion count mismatch"
                );
                ensure!(
                    transcript.finalize().as_slice() == &plain[16..],
                    "recovery transcript mismatch"
                );
                let mut trailing = [0];
                ensure!(input.read(&mut trailing)? == 0, "trailing recovery bytes");
                break;
            }
            transcript.update(&context);
            transcript.update(&ct);
            match kind {
                CONTROL => {
                    ensure!(
                        !objects_started && !plain.is_empty(),
                        "invalid control ordering"
                    );
                    let index = plain[0] as usize;
                    ensure!(
                        index < CONTROLS.len() && !controls[index] && plain.len() - 1 <= MAX_OBJECT,
                        "invalid or duplicate recovery control"
                    );
                    controls[index] = true;
                    store.write_new_control(CONTROLS[index], &plain[1..])?;
                }
                DEVICE => {
                    ensure!(
                        !objects_started && !device && plain.len() <= 256,
                        "invalid device key record"
                    );
                    device = true;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(stage.join("device-key"))?;
                    file.write_all(&plain)?;
                    file.sync_all()?;
                }
                OBJECT => {
                    objects_started = true;
                    ensure!(
                        plain.len() >= 32 && plain.len() - 32 <= MAX_OBJECT,
                        "invalid object record"
                    );
                    let id: Id = plain[..32].try_into()?;
                    ensure!(
                        format::id(&plain[32..]) == id && !store.contains(&id)?,
                        "invalid or duplicate recovery object"
                    );
                    count += 1;
                    total = total
                        .checked_add((plain.len() - 32) as u64)
                        .ok_or_else(|| anyhow::anyhow!("inventory overflow"))?;
                    ensure!(
                        count <= MAX_COUNT && total <= MAX_BYTES,
                        "recovery inventory exceeds limits"
                    );
                    store.put(&plain[32..])?;
                }
                _ => unreachable!(),
            }
        }
        validate(&store, expected, password)?;
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
fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// Validate secret custody and the complete signed local policy chain from the staged store.
/// Opaque inventory objects are retained without granting them snapshot authority.
fn validate(store: &Store, expected: &Id, password: &str) -> Result<()> {
    let (gid, genesis) = crate::app::pinned(store)?;
    ensure!(&gid == expected, "recovery identity pin mismatch");
    let current = crate::crypto::Secrets::unlock(
        &genesis.collection,
        &store.read_control("keys")?,
        password,
    )?;
    let device = match open_read(&store.path().join("device-key")) {
        Ok(file) => {
            ensure!(file.metadata()?.len() <= 256, "device key input too large");
            let mut bytes = Zeroizing::new(Vec::new());
            file.take(257).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 256, "device key input too large");
            Some(bytes)
        }
        Err(error) if missing(&error) => None,
        Err(error) => return Err(error),
    };
    match crate::app::load_policy(store, &genesis)? {
        Some(policy) => {
            ensure!(
                policy
                    .members
                    .iter()
                    .any(|m| m.key == current.root() && !m.revoked),
                "recovered key is not active"
            );
            if current.root() == genesis.root {
                ensure!(
                    device.is_none(),
                    "admin recovery must not contain a member device key"
                );
            } else {
                let bytes = device
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("member recovery requires device key"))?;
                let unlocked = crate::crypto::DeviceSecrets::unlock(bytes, password)?;
                ensure!(
                    unlocked.public() == current.root(),
                    "device identity/key mismatch"
                );
            }
            let mut chain = std::collections::BTreeMap::new();
            let mut child = policy.clone();
            loop {
                ensure!(chain.len() < 256, "policy chain too long");
                ensure!(
                    chain.insert(child.id()?, child.clone()).is_none(),
                    "policy chain cycle"
                );
                if let Some(previous) = child.previous {
                    let parent = crate::policy::Policy::decode(&store.get(&previous)?)?;
                    parent.verify(&genesis.root)?;
                    ensure!(
                        parent.collection == genesis.collection
                            && parent.epoch.checked_add(1) == Some(child.epoch),
                        "invalid policy chain link"
                    );
                    child = parent;
                } else {
                    ensure!(child.epoch == 0, "policy chain missing epoch zero");
                    break;
                }
            }
            match store.read_control("keys-history") {
                Ok(history) => {
                    let mut d = Decoder::new(&history);
                    ensure!(
                        d.array()? == Some(2) && d.u8()? == 1,
                        "invalid policy key history"
                    );
                    let count = d
                        .array()?
                        .ok_or_else(|| anyhow::anyhow!("indefinite key history"))?;
                    ensure!(count <= 256, "policy key history too large");
                    let mut seen = std::collections::BTreeSet::new();
                    for _ in 0..count {
                        ensure!(d.array()? == Some(2), "invalid policy key history entry");
                        let id: Id = d.bytes()?.try_into()?;
                        let locked = d.bytes()?;
                        ensure!(
                            seen.insert(id) && chain.contains_key(&id),
                            "unknown or duplicate historic policy"
                        );
                        let old =
                            crate::crypto::Secrets::unlock(&genesis.collection, locked, password)?;
                        ensure!(
                            old.root() == current.root()
                                && chain[&id].members.iter().any(|m| m.key == old.root()),
                            "historic key identity mismatch"
                        );
                    }
                    ensure!(d.position() == history.len(), "trailing key history");
                }
                Err(error) if missing(&error) => {}
                Err(error) => return Err(error),
            }
        }
        None => {
            ensure!(
                current.root() == genesis.root && device.is_none(),
                "root recovery identity mismatch"
            );
            match store.read_control("keys-history") {
                Ok(_) => bail!("historical keys require policy"),
                Err(e) if missing(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }
    let Record::Genesis(_) = format::inspect(&store.get(&gid)?)? else {
        bail!("invalid recovery genesis")
    };
    Ok(())
}
