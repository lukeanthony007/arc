//! Password-authenticated bounded backup of a node's local immutable-object inventory.
use crate::{
    format::{self, Id, MAX_OBJECT, Record},
    store::Store,
};
use anyhow::{Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use minicbor::Decoder;
#[cfg(test)]
use minicbor::Encoder;
#[cfg(test)]
use rand::{RngCore, rngs::OsRng};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use zeroize::Zeroizing;

#[path = "recovery_stream.rs"]
mod stream;

/// New backups use independently authenticated streaming ARCRCV3 records.
pub(crate) fn export(
    store: &Store,
    genesis: &Id,
    destination: &Path,
    password: &str,
) -> Result<()> {
    stream::export(store, genesis, destination, password)
}

const MAGIC: &[u8; 8] = b"ARCRCV2\n";
const MAX_COUNT: usize = 16_384;
const MAX_TOTAL: usize = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_OBJECT_SCAN: usize = MAX_COUNT * 4;
const CONTROLS: &[&str] = &["genesis", "keys", "policy", "keys-history"];

fn key(password: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "invalid recovery password"
    );
    let params = Params::new(65536, 3, 1, Some(32))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut result = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), salt, &mut *result)?;
    Ok(result)
}

/// Legacy writer retained only to exercise ARCRCV2 read compatibility.
#[cfg(test)]
fn export_v2(store: &Store, genesis: &Id, destination: &Path, password: &str) -> Result<()> {
    let mut controls: Vec<(&str, Vec<u8>)> = Vec::new();
    for name in CONTROLS {
        let path = store.path().join("control").join(name);
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                ensure!(m.is_file(), "invalid recovery control");
                controls.push((name, store.read_control(name)?));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let device_path = store.path().join("device-key");
    let device = match fs::symlink_metadata(&device_path) {
        Ok(m) => {
            ensure!(m.is_file() && m.len() <= 256, "invalid device key file");
            let f = fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                )
                .open(&device_path)?;
            ensure!(
                f.metadata()?.is_file() && f.metadata()?.len() <= 256,
                "invalid device key file"
            );
            let mut b = Vec::new();
            f.take(257).read_to_end(&mut b)?;
            ensure!(b.len() <= 256, "device key file too large");
            Some(b)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let mut objects = Vec::new();
    let mut total = 0usize;
    let mut scanned = 0usize;
    for item in fs::read_dir(store.path().join("objects"))? {
        scanned += 1;
        ensure!(
            scanned <= MAX_OBJECT_SCAN,
            "object inventory scan limit exceeded"
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
        let meta = fs::symlink_metadata(item.path())?;
        ensure!(
            meta.is_file() && meta.len() <= MAX_OBJECT as u64,
            "invalid object inventory entry"
        );
        let bytes = store.get(&id)?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("inventory overflow"))?;
        ensure!(
            total <= MAX_TOTAL && objects.len() < MAX_COUNT,
            "recovery inventory exceeds limits"
        );
        objects.push((id, bytes));
    }
    ensure!(
        objects.iter().any(|(id, _)| id == genesis),
        "pinned genesis missing from inventory"
    );
    let mut plain = Zeroizing::new(Vec::new());
    let mut e = Encoder::new(&mut *plain);
    e.array(4)?.u8(1)?.array(controls.len() as u64)?;
    for (name, bytes) in &controls {
        e.array(2)?.str(name)?.bytes(bytes)?;
    }
    match &device {
        Some(b) => {
            e.bytes(b)?;
        }
        None => {
            e.null()?;
        }
    }
    e.array(objects.len() as u64)?;
    for (id, bytes) in &objects {
        e.array(2)?.bytes(id)?.bytes(bytes)?;
    }
    ensure!(plain.len() <= MAX_TOTAL, "recovery payload too large");
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let k = key(password, &salt)?;
    let aad = [MAGIC.as_slice(), salt.as_slice(), nonce.as_slice()].concat();
    let cipher = XChaCha20Poly1305::new((&*k).into());
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("recovery encryption failed"))?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = parent.join(format!(
        ".arc-recovery-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let mut tmp_created = false;
    let result = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&tmp)?;
        tmp_created = true;
        f.write_all(MAGIC)?;
        f.write_all(&salt)?;
        f.write_all(&nonce)?;
        f.write_all(&(encrypted.len() as u64).to_be_bytes())?;
        f.write_all(&encrypted)?;
        f.sync_all()?;
        drop(f);
        fs::hard_link(&tmp, destination)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if tmp_created {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// Validate the complete encrypted package before staging a fresh destination.
pub fn recover(path: &Path, kit: &Path, expected: &Id, password: &str) -> Result<()> {
    let mut probe = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(kit)?;
    ensure!(
        probe.metadata()?.is_file(),
        "recovery kit must be a regular file"
    );
    let mut probe_magic = [0; 8];
    probe.read_exact(&mut probe_magic)?;
    if &probe_magic == stream::MAGIC {
        drop(probe);
        return stream::recover(path, kit, expected, password);
    }
    drop(probe);
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(kit)?;
    let size = f.metadata()?.len();
    ensure!(
        f.metadata()?.is_file() && size >= 56 && size <= (MAX_TOTAL as u64 + 128),
        "invalid recovery kit size"
    );
    let mut magic = [0; 8];
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    let mut n = [0; 8];
    f.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported recovery kit");
    f.read_exact(&mut salt)?;
    f.read_exact(&mut nonce)?;
    f.read_exact(&mut n)?;
    let n = u64::from_be_bytes(n);
    ensure!(
        n == size - 56 && n <= MAX_TOTAL as u64 + 16,
        "invalid recovery ciphertext length"
    );
    let mut ct = vec![0; n as usize];
    f.read_exact(&mut ct)?;
    let k = key(password, &salt)?;
    let aad = [MAGIC.as_slice(), salt.as_slice(), nonce.as_slice()].concat();
    let cipher = XChaCha20Poly1305::new((&*k).into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("wrong password or modified recovery kit"))?,
    );
    let mut d = Decoder::new(&plain[..]);
    ensure!(
        d.array()? == Some(4) && d.u8()? == 1,
        "unsupported recovery payload"
    );
    let nc = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite controls"))? as usize;
    ensure!(nc <= CONTROLS.len(), "too many controls");
    let mut controls = std::collections::BTreeMap::new();
    for _ in 0..nc {
        ensure!(d.array()? == Some(2), "invalid control entry");
        let name = d.str()?.to_owned();
        let bytes = d.bytes()?;
        ensure!(
            bytes.len() <= MAX_OBJECT && CONTROLS.contains(&name.as_str()),
            "invalid recovery control"
        );
        ensure!(
            controls.insert(name, bytes.to_vec()).is_none(),
            "duplicate recovery control"
        );
    }
    let device = if d.datatype()? == minicbor::data::Type::Null {
        d.null()?;
        None
    } else {
        let bytes = d.bytes()?;
        ensure!(bytes.len() <= 256, "device key input too large");
        Some(bytes.to_vec())
    };
    let no = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite objects"))? as usize;
    ensure!(no > 0 && no <= MAX_COUNT, "invalid object count");
    let mut objects = Vec::with_capacity(no);
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0usize;
    for _ in 0..no {
        ensure!(d.array()? == Some(2), "invalid object entry");
        let id: Id = d.bytes()?.try_into()?;
        let raw = d.bytes()?;
        ensure!(raw.len() <= MAX_OBJECT, "recovery object too large");
        let b = raw.to_vec();
        ensure!(
            format::id(&b) == id && seen.insert(id),
            "invalid recovery object"
        );
        total = total
            .checked_add(b.len())
            .ok_or_else(|| anyhow::anyhow!("object size overflow"))?;
        ensure!(total <= MAX_TOTAL, "object inventory too large");
        objects.push((id, b));
    }
    ensure!(d.position() == plain.len(), "trailing recovery payload");
    let gid: Id = controls
        .get("genesis")
        .ok_or_else(|| anyhow::anyhow!("missing genesis pin"))?
        .as_slice()
        .try_into()?;
    ensure!(&gid == expected, "recovery identity pin mismatch");
    let genesis_bytes = objects
        .iter()
        .find(|(id, _)| *id == gid)
        .map(|(_, b)| b)
        .ok_or_else(|| anyhow::anyhow!("pinned genesis missing"))?;
    let Record::Genesis(genesis) = format::inspect(genesis_bytes)? else {
        bail!("invalid recovery genesis")
    };
    let policy = if let Some(raw) = controls.get("policy") {
        let pid: Id = raw.as_slice().try_into()?;
        let bytes = objects
            .iter()
            .find(|(id, _)| *id == pid)
            .map(|(_, b)| b)
            .ok_or_else(|| anyhow::anyhow!("policy object missing"))?;
        let p = crate::policy::Policy::decode(bytes)?;
        p.verify(&genesis.root)?;
        ensure!(
            p.collection == genesis.collection && format::id(bytes) == pid,
            "policy identity mismatch"
        );
        let mut chain = std::collections::BTreeMap::new();
        let mut child = p.clone();
        loop {
            let child_id = child.id()?;
            ensure!(
                chain.insert(child_id, child.clone()).is_none(),
                "policy chain cycle"
            );
            ensure!(chain.len() <= 256, "policy chain too long");
            match child.previous {
                Some(previous) => {
                    let prev = objects
                        .iter()
                        .find(|(id, _)| *id == previous)
                        .map(|(_, b)| b)
                        .ok_or_else(|| anyhow::anyhow!("policy predecessor missing"))?;
                    let parent = crate::policy::Policy::decode(prev)?;
                    parent.verify(&genesis.root)?;
                    ensure!(
                        parent.collection == p.collection
                            && parent.epoch.checked_add(1) == Some(child.epoch),
                        "invalid policy chain link"
                    );
                    child = parent;
                }
                None => {
                    ensure!(child.epoch == 0, "policy chain does not reach epoch zero");
                    break;
                }
            }
        }
        Some((pid, p, chain))
    } else {
        None
    };
    ensure!(controls.contains_key("keys"), "missing key material");
    if let Some((_, p, chain)) = &policy {
        let secrets = crate::crypto::Secrets::unlock(
            &genesis.collection,
            controls.get("keys").unwrap(),
            password,
        )?;
        let hist = controls
            .get("keys-history")
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !hist.is_empty() {
            let mut hd = Decoder::new(hist);
            ensure!(
                hd.array()? == Some(2) && hd.u8()? == 1,
                "invalid policy key history"
            );
            let count = hd
                .array()?
                .ok_or_else(|| anyhow::anyhow!("indefinite key history"))?
                as usize;
            ensure!(count <= 256, "policy key history too large");
            let mut historic = std::collections::BTreeSet::new();
            for _ in 0..count {
                ensure!(hd.array()? == Some(2), "invalid policy key history entry");
                let id: Id = hd.bytes()?.try_into()?;
                let locked = hd.bytes()?;
                ensure!(
                    historic.insert(id) && chain.contains_key(&id),
                    "key history references unknown policy"
                );
                let old = crate::crypto::Secrets::unlock(&genesis.collection, locked, password)?;
                ensure!(
                    old.root() == secrets.root()
                        && chain[&id].members.iter().any(|m| m.key == old.root()),
                    "historical key does not match policy"
                );
            }
            ensure!(hd.position() == hist.len(), "trailing policy key history");
        }
        ensure!(
            p.members
                .iter()
                .any(|m| m.key == secrets.root() && !m.revoked),
            "recovered key is not active"
        );
        if secrets.root() == genesis.root {
            ensure!(
                device.is_none(),
                "admin recovery must not contain a member device key"
            );
        } else {
            let device_bytes = device
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("member recovery requires device key"))?;
            let ds = crate::crypto::DeviceSecrets::unlock(device_bytes, password)?;
            ensure!(
                ds.public() == secrets.root()
                    && p.members.iter().any(|m| m.key == ds.public() && !m.revoked),
                "device is not active in pinned policy"
            );
        }
    } else {
        ensure!(
            !controls.contains_key("keys-history"),
            "historical keys require a membership policy"
        );
        ensure!(
            device.is_none(),
            "unexpected device identity without policy"
        );
        let secrets = crate::crypto::Secrets::unlock(
            &genesis.collection,
            controls.get("keys").unwrap(),
            password,
        )?;
        ensure!(secrets.root() == genesis.root, "recovery key/root mismatch");
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = parent.join(format!(
        ".arc-recover-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let mut stage_created = false;
    let result = (|| -> Result<()> {
        let s = Store::create(&stage)?;
        stage_created = true;
        for (_, b) in &objects {
            s.put(b)?;
        }
        for (name, b) in &controls {
            s.write_new_control(name, b)?;
        }
        if let Some(b) = device {
            let p = stage.join("device-key");
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                )
                .open(&p)?;
            f.write_all(&b)?;
            f.sync_all()?;
        }
        let staged = Store::open(&stage)?;
        let (staged_gid, staged_genesis) = crate::app::pinned(&staged)?;
        ensure!(
            staged_gid == gid && staged_genesis.collection == genesis.collection,
            "staged identity mismatch"
        );
        if let Some((pid, policy, _)) = &policy {
            let loaded = crate::app::load_policy(&staged, &staged_genesis)?
                .ok_or_else(|| anyhow::anyhow!("missing staged policy"))?;
            ensure!(
                loaded.id()? == *pid && loaded == *policy,
                "staged policy mismatch"
            );
            let keys = crate::devices::secrets_for_policy(&staged, *pid, password)?;
            if keys.root() != staged_genesis.root {
                let staged_device = crate::crypto::DeviceSecrets::unlock(
                    &fs::read(stage.join("device-key"))?,
                    password,
                )?;
                ensure!(
                    staged_device.public() == keys.root()
                        && loaded
                            .members
                            .iter()
                            .any(|m| m.key == staged_device.public() && !m.revoked),
                    "staged device is not active"
                );
            }
        }
        fs::File::open(&stage)?.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &stage,
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if stage_created && result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

#[cfg(test)]
mod compatibility {
    use super::*;
    #[test]
    fn v2_backup_remains_readable() {
        let temp = tempfile::tempdir().unwrap();
        let node = temp.path().join("node");
        let genesis = crate::app::init(&node, "legacy-v2-password").unwrap();
        let store = Store::open(&node).unwrap();
        let kit = temp.path().join("v2.arc");
        export_v2(&store, &genesis, &kit, "legacy-v2-password").unwrap();
        let destination = temp.path().join("recovered");
        recover(&destination, &kit, &genesis, "legacy-v2-password").unwrap();
        assert_eq!(
            crate::app::pinned(&Store::open(&destination).unwrap())
                .unwrap()
                .0,
            genesis
        );
        assert!(Store::open(&destination).unwrap().head().unwrap().is_none());
    }
    #[test]
    fn v2_rejects_mixed_historical_signing_identities() {
        use crate::{
            crypto::{DeviceSecrets, Secrets},
            policy::{Member, Policy, Role},
        };
        let temp = tempfile::tempdir().unwrap();
        let node = temp.path().join("mixed");
        let store = Store::create(&node).unwrap();
        let collection = [1; 32];
        let root = Secrets::from_member([7; 32], [9; 32]);
        let reader = Secrets::from_member([8; 32], [9; 32]);
        let genesis = store.put(&root.sign_genesis(collection).unwrap()).unwrap();
        let policy = Policy::new(
            collection,
            root.root(),
            0,
            None,
            vec![
                Member {
                    key: root.root(),
                    role: Role::Writer,
                    revoked: false,
                },
                Member {
                    key: reader.root(),
                    role: Role::Reader,
                    revoked: false,
                },
            ],
            vec![],
            &[7; 32],
        )
        .unwrap();
        let pid = store.put(&policy.encode().unwrap()).unwrap();
        store.write_new_control("genesis", &genesis).unwrap();
        store.write_new_control("policy", &pid).unwrap();
        store
            .write_new_control("keys", &reader.lock(&collection, "mixed-password").unwrap())
            .unwrap();
        let mut history = Vec::new();
        Encoder::new(&mut history)
            .array(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(1)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&pid)
            .unwrap()
            .bytes(&root.lock(&collection, "mixed-password").unwrap())
            .unwrap();
        store.write_new_control("keys-history", &history).unwrap();
        fs::write(
            node.join("device-key"),
            DeviceSecrets::from_seed([8; 32])
                .lock("mixed-password")
                .unwrap(),
        )
        .unwrap();
        let kit = temp.path().join("mixed-v2.arc");
        export_v2(&store, &genesis, &kit, "mixed-password").unwrap();
        let destination = temp.path().join("recovered");
        let error = recover(&destination, &kit, &genesis, "mixed-password").unwrap_err();
        assert!(error.to_string().contains("historical key"));
        assert!(!destination.exists());
    }
}
