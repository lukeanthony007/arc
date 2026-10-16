use crate::{
    app,
    crypto::{DeviceSecrets, Secrets},
    enrollment::{self, Invitation, KeyEnvelope, Request},
    format::{self, Id, Record},
    policy::{Policy, Role},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use minicbor::{Decoder, Encoder};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_PACKAGE: usize = 8 * 1024 * 1024;
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let mut b = Vec::new();
    f.take((max + 1) as u64).read_to_end(&mut b)?;
    ensure!(b.len() <= max, "input too large");
    Ok(b)
}
fn write_new(path: &Path, b: &[u8]) -> Result<()> {
    ensure!(b.len() <= MAX_PACKAGE, "output too large");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn writer_lock(store: &Store) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(store.path().join("control/writer.lock"))?;
    ensure!(file.metadata()?.is_file(), "invalid writer lock");
    file.try_lock().context("another local writer is active")?;
    Ok(file)
}
fn chain(store: &Store, head: &Policy, authority: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut p = head.clone();
    loop {
        p.verify(authority)?;
        let bytes = p.encode()?;
        out.push(bytes);
        ensure!(out.len() <= 256, "policy chain too long");
        let Some(prev) = p.previous else {
            ensure!(p.epoch == 0, "policy chain missing genesis");
            break;
        };
        let child_epoch = p.epoch;
        let raw = store.get(&prev)?;
        ensure!(format::id(&raw) == prev, "policy chain content ID mismatch");
        p = Policy::decode(&raw)?;
        ensure!(
            p.epoch.checked_add(1) == Some(child_epoch),
            "policy chain epoch fork"
        );
    }
    out.reverse();
    Ok(out)
}
#[derive(Clone)]
struct InvitePackage {
    genesis: Vec<u8>,
    policies: Vec<Vec<u8>>,
    invitation: Vec<u8>,
}
impl InvitePackage {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        let mut e = Encoder::new(&mut b);
        e.array(4)?
            .u8(1)?
            .bytes(&self.genesis)?
            .array(self.policies.len() as u64)?;
        for p in &self.policies {
            e.bytes(p)?;
        }
        e.bytes(&self.invitation)?;
        ensure!(b.len() <= MAX_PACKAGE, "invitation package too large");
        Ok(b)
    }
    fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() <= MAX_PACKAGE, "invitation package too large");
        let mut d = Decoder::new(b);
        ensure!(
            d.array()? == Some(4) && d.u8()? == 1,
            "unsupported invitation package"
        );
        let genesis = d.bytes()?.to_vec();
        let n = d
            .array()?
            .ok_or_else(|| anyhow::anyhow!("indefinite policy chain"))? as usize;
        ensure!(n > 0 && n <= 256, "invalid policy chain length");
        let mut policies = Vec::with_capacity(n);
        for _ in 0..n {
            policies.push(d.bytes()?.to_vec());
        }
        let invitation = d.bytes()?.to_vec();
        ensure!(d.position() == b.len(), "trailing invitation package data");
        Ok(Self {
            genesis,
            policies,
            invitation,
        })
    }
}
fn encode_rotation_package(
    policies: &[Vec<u8>],
    envelopes: &[KeyEnvelope],
    genesis: Id,
) -> Result<Vec<u8>> {
    ensure!(
        !policies.is_empty() && policies.len() <= 256 && envelopes.len() <= 256,
        "rotation package limit exceeded"
    );
    let mut b = Vec::new();
    let mut e = Encoder::new(&mut b);
    e.array(4)?.u8(2)?.array(policies.len() as u64)?;
    for p in policies {
        e.bytes(p)?;
    }
    e.array(envelopes.len() as u64)?;
    for v in envelopes {
        e.array(9)?
            .bytes(&v.collection)?
            .bytes(&v.genesis)?
            .bytes(&v.policy)?
            .u64(v.epoch)?
            .bytes(&v.recipient)?
            .u8(v.role as u8)?
            .bytes(&v.enc)?
            .bytes(&v.ciphertext)?
            .bytes(&v.signature)?;
    }
    e.bytes(&genesis)?;
    ensure!(b.len() <= MAX_PACKAGE, "rotation package too large");
    Ok(b)
}

fn archive_key(store: &Store, policy: &Policy, authority: &[u8; 32]) -> Result<()> {
    let mut records: Vec<(Id, Vec<u8>)> =
        if std::fs::symlink_metadata(store.path().join("control/keys-history")).is_ok() {
            let b = store.read_control("keys-history")?;
            let mut d = Decoder::new(&b);
            ensure!(d.array()? == Some(2) && d.u8()? == 1, "invalid key history");
            let n = d
                .array()?
                .ok_or_else(|| anyhow::anyhow!("indefinite key history"))?
                as usize;
            ensure!(n <= 4096, "key history too large");
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                ensure!(d.array()? == Some(2), "invalid key history entry");
                v.push((d.bytes()?.try_into()?, d.bytes()?.to_vec()));
            }
            ensure!(d.position() == b.len(), "trailing key history data");
            v
        } else {
            Vec::new()
        };
    let current = store.read_control("keys")?;
    policy.verify(authority)?;
    let id = policy.id()?;
    if let Some((_, old)) = records.iter().find(|(existing, _)| *existing == id) {
        ensure!(old == &current, "conflicting archived key for policy");
    } else {
        records.push((id, current));
    }
    ensure!(records.len() <= 4096, "key history limit exceeded");
    let mut b = Vec::new();
    let mut e = Encoder::new(&mut b);
    e.array(2)?.u8(1)?.array(records.len() as u64)?;
    for (id, key) in records {
        e.array(2)?.bytes(&id)?.bytes(&key)?;
    }
    store.set_control("keys-history", &b)
}
pub fn secrets_for_policy(store: &Store, policy_id: Id, password: &str) -> Result<Secrets> {
    match std::fs::symlink_metadata(store.path().join("control/membership-pending")) {
        Ok(_) => anyhow::bail!("membership or key rotation transition is pending"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let (_, genesis) = app::pinned(store)?;
    let raw = store.get(&policy_id)?;
    ensure!(format::id(&raw) == policy_id, "policy ID mismatch");
    let policy = Policy::decode(&raw)?;
    policy.verify(&genesis.root)?;
    ensure!(policy.id()? == policy_id, "policy identity mismatch");
    let locked = if let Some(current) = Policy::load(store, &genesis.root)? {
        if current.id()? == policy_id {
            store.read_control("keys")?
        } else {
            let b = store.read_control("keys-history")?;
            let mut d = Decoder::new(&b);
            ensure!(d.array()? == Some(2) && d.u8()? == 1, "invalid key history");
            let n = d
                .array()?
                .ok_or_else(|| anyhow::anyhow!("indefinite key history"))?
                as usize;
            ensure!(n <= 4096, "key history too large");
            let mut found = None;
            for _ in 0..n {
                ensure!(d.array()? == Some(2), "invalid key history entry");
                let id: Id = d.bytes()?.try_into()?;
                let key = d.bytes()?.to_vec();
                if id == policy_id {
                    found = Some(key);
                }
            }
            ensure!(d.position() == b.len(), "trailing key history data");
            found.ok_or_else(|| anyhow::anyhow!("no key for policy epoch"))?
        }
    } else {
        anyhow::bail!("membership policy is not enabled")
    };
    let keys = Secrets::unlock(&genesis.collection, &locked, password)?;
    ensure!(
        policy.members.iter().any(|m| m.key == keys.root()),
        "policy key identity mismatch"
    );
    Ok(keys)
}
pub fn enable(node: &Path, password: &str) -> Result<()> {
    let store = Store::open(node)?;
    let _writer_lock = writer_lock(&store)?;
    let (_, genesis) = app::pinned(&store)?;
    let keys = app::secrets(&store, password, &genesis)?;
    ensure!(
        keys.root() == genesis.root,
        "only genesis authority can enable membership"
    );
    let accepted = crate::history::list(node)?
        .into_iter()
        .map(|x| x.id)
        .collect();
    store.write_new_control("membership-pending", b"enable")?;
    let policy = enrollment::enable(&store, genesis.collection, &keys, accepted)?;
    archive_key(&store, &policy, &genesis.root)?;
    store.clear_membership_pending()?;
    Ok(())
}
/// Create a new independently keyed device; private key material is password encrypted.
pub fn create_request(private_path: &Path, request_path: &Path, password: &str) -> Result<Request> {
    let device = DeviceSecrets::generate();
    let request = Request::create(&device);
    write_new(private_path, &device.lock(password)?)?;
    write_new(request_path, &request.encode()?)?;
    Ok(request)
}
/// Grant access and write a self-contained package with genesis and the signed policy chain.
pub fn grant(
    admin_node: &Path,
    request_path: &Path,
    invitation_path: &Path,
    role: Role,
    password: &str,
) -> Result<()> {
    let store = Store::open(admin_node)?;
    let _writer_lock = writer_lock(&store)?;
    let (genesis_id, genesis) = app::pinned(&store)?;
    let admin = app::secrets(&store, password, &genesis)?;
    let authority = genesis.root;
    let previous = Policy::load(&store, &authority)?
        .ok_or_else(|| anyhow::anyhow!("membership policy is not enabled"))?;
    store.write_new_control("membership-pending", b"grant")?;
    archive_key(&store, &previous, &authority)?;
    let request = Request::decode(&read(request_path, 256)?)?;
    let invitation = Invitation::grant(
        &store,
        genesis.collection,
        genesis_id,
        &previous,
        &request,
        role,
        &admin,
    )?;
    let current =
        Policy::load(&store, &authority)?.ok_or_else(|| anyhow::anyhow!("policy disappeared"))?;
    let package = InvitePackage {
        genesis: store.get(&genesis_id)?,
        policies: chain(&store, &current, &authority)?,
        invitation: invitation.encode()?,
    };
    write_new(invitation_path, &package.encode()?)?;
    store.clear_membership_pending()?;
    Ok(())
}
pub fn refresh(
    admin_node: &Path,
    requests: &[Request],
    package_path: &Path,
    password: &str,
) -> Result<()> {
    let store = Store::open(admin_node)?;
    let _writer_lock = writer_lock(&store)?;
    let (genesis_id, genesis) = app::pinned(&store)?;
    let admin = app::secrets(&store, password, &genesis)?;
    let policy = Policy::load(&store, &genesis.root)?
        .ok_or_else(|| anyhow::anyhow!("membership policy is not enabled"))?;
    for member in policy
        .members
        .iter()
        .filter(|m| !m.revoked && m.key != genesis.root)
    {
        ensure!(
            requests.iter().filter(|r| r.signing == member.key).count() == 1,
            "missing or duplicate active member request"
        );
    }
    let envelopes = enrollment::refresh_envelopes(genesis_id, &policy, &admin, requests)?;
    let policies = chain(&store, &policy, &genesis.root)?;
    let package = encode_rotation_package(&policies, &envelopes, genesis_id)?;
    write_new(package_path, &package)
}
/// Join only after matching the supplied trusted genesis ID; create a fresh local node.
pub fn join_node(
    node: &Path,
    private_path: &Path,
    invitation_path: &Path,
    trusted_genesis: Id,
    password: &str,
) -> Result<()> {
    let pkg = InvitePackage::decode(&read(invitation_path, MAX_PACKAGE)?)?;
    let genesis_id = format::id(&pkg.genesis);
    ensure!(genesis_id == trusted_genesis, "trusted genesis mismatch");
    let Record::Genesis(genesis) = format::inspect(&pkg.genesis)? else {
        anyhow::bail!("package genesis is not a genesis record")
    };
    let mut prev = None;
    let mut latest = None;
    for (epoch, b) in pkg.policies.iter().enumerate() {
        let p = Policy::decode(b)?;
        p.verify(&genesis.root)?;
        ensure!(
            p.collection == genesis.collection && p.epoch == epoch as u64 && p.previous == prev,
            "policy chain fork or wrong epoch"
        );
        prev = Some(p.id()?);
        latest = Some(p);
    }
    let policy = latest.ok_or_else(|| anyhow::anyhow!("missing policy"))?;
    let invite = Invitation::decode(&pkg.invitation)?;
    invite.verify(&genesis.root)?;
    ensure!(
        invite.policy == policy.id()?
            && invite.collection == genesis.collection
            && invite.epoch == policy.epoch,
        "invitation policy mismatch"
    );
    let device = DeviceSecrets::unlock(&read(private_path, 256)?, password)?;
    ensure!(
        policy
            .members
            .iter()
            .any(|m| m.key == device.public() && m.role == invite.role && !m.revoked),
        "invitation role is not in signed policy"
    );
    let request = Request::create(&device);
    let keys = enrollment::join(&invite, &request, &device, trusted_genesis, genesis.root)?;
    let store = Store::create(node)?;
    let id = store.put(&pkg.genesis)?;
    ensure!(id == trusted_genesis, "genesis object ID mismatch");
    for b in &pkg.policies {
        let id = store.put(b)?;
        ensure!(id == format::id(b), "policy object ID mismatch");
    }
    store.write_new_control("genesis", &id)?;
    store.write_new_control("keys", &keys.lock(&genesis.collection, password)?)?;
    store.set_control("policy", &policy.id()?)?;
    write_new(&node.join("device-key"), &device.lock(password)?)?;
    Ok(())
}

/// Build a root-signed key rotation package, revoking the requested signing key.
pub fn revoke(
    admin_node: &Path,
    revoked: [u8; 32],
    requests: &[Request],
    package_path: &Path,
    password: &str,
) -> Result<()> {
    let store = Store::open(admin_node)?;
    let _writer_lock = writer_lock(&store)?;
    let (genesis_id, genesis) = app::pinned(&store)?;
    let mut admin = app::secrets(&store, password, &genesis)?;
    store.write_new_control("membership-pending", b"rotation")?;
    let old = Policy::load(&store, &genesis.root)?
        .ok_or_else(|| anyhow::anyhow!("membership policy is not enabled"))?;
    let mut members = old.members.clone();
    members
        .iter_mut()
        .find(|m| m.key == revoked)
        .ok_or_else(|| anyhow::anyhow!("member not found"))?
        .revoked = true;
    let active: Vec<_> = requests
        .iter()
        .filter(|r| r.signing != revoked)
        .cloned()
        .collect();
    archive_key(&store, &old, &genesis.root)?;
    let rotation = enrollment::rotate(
        &store,
        genesis_id,
        &old,
        &admin,
        old.accepted.clone(),
        members,
        &active,
    )?;
    let policies = chain(&store, &rotation.policy, &genesis.root)?;
    let package = encode_rotation_package(&policies, &rotation.envelopes, genesis_id)?;
    write_new(package_path, &package)?;
    admin.replace_epoch_key(*rotation.key);
    store.set_control("keys", &admin.lock(&genesis.collection, password)?)?;
    store.clear_membership_pending()?;
    Ok(())
}
/// Apply a root-signed rotation envelope and persist its new epoch key.
pub fn apply(node: &Path, private_path: &Path, package_path: &Path, password: &str) -> Result<()> {
    let store = Store::open(node)?;
    let _writer_lock = writer_lock(&store)?;
    let (genesis_id, genesis) = app::pinned(&store)?;
    let device = DeviceSecrets::unlock(&read(private_path, 256)?, password)?;
    let bytes = read(package_path, MAX_PACKAGE)?;
    let mut d = Decoder::new(&bytes);
    ensure!(
        d.array()? == Some(4) && d.u8()? == 2,
        "invalid rotation package"
    );
    let chain_len = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite policy chain"))? as usize;
    ensure!(
        chain_len > 0 && chain_len <= 256,
        "invalid policy chain length"
    );
    let mut policy_bytes = Vec::with_capacity(chain_len);
    let mut policies = Vec::with_capacity(chain_len);
    let mut previous = None;
    for index in 0..chain_len {
        let raw = d.bytes()?.to_vec();
        let p = Policy::decode(&raw)?;
        p.verify(&genesis.root)?;
        ensure!(
            p.collection == genesis.collection && p.epoch == index as u64 && p.previous == previous,
            "invalid policy chain"
        );
        previous = Some(p.id()?);
        policy_bytes.push(raw);
        policies.push(p);
    }
    let policy = policies.last().expect("nonempty policy chain").clone();
    let n = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite envelope list"))? as usize;
    ensure!(n <= 256, "too many key envelopes");
    let mut selected = None;
    for _ in 0..n {
        ensure!(d.array()? == Some(9), "invalid key envelope");
        let collection = d.bytes()?.try_into()?;
        let genesis_in = d.bytes()?.try_into()?;
        let pid = d.bytes()?.try_into()?;
        let epoch = d.u64()?;
        let recipient = d.bytes()?.try_into()?;
        let role = match d.u8()? {
            1 => Role::Reader,
            2 => Role::Writer,
            _ => anyhow::bail!("invalid envelope role"),
        };
        let enc = d.bytes()?.to_vec();
        let ciphertext = d.bytes()?.to_vec();
        let signature = d.bytes()?.try_into()?;
        let env = KeyEnvelope {
            collection,
            genesis: genesis_in,
            policy: pid,
            epoch,
            recipient,
            role,
            enc,
            ciphertext,
            signature,
        };
        env.verify(&genesis.root)?;
        if env.recipient == device.public() {
            selected = Some(env);
        }
    }
    let package_genesis: Id = d.bytes()?.try_into()?;
    ensure!(
        d.position() == bytes.len() && package_genesis == genesis_id,
        "rotation genesis mismatch"
    );
    let env = selected.ok_or_else(|| anyhow::anyhow!("no envelope for this device"))?;
    ensure!(
        env.policy == policy.id()?
            && env.epoch == policy.epoch
            && env.collection == genesis.collection
            && env.genesis == genesis_id,
        "envelope policy or collection binding mismatch"
    );
    ensure!(
        policy
            .members
            .iter()
            .any(|m| m.key == env.recipient && m.role == env.role && !m.revoked),
        "envelope recipient not active in signed policy"
    );
    let old = Policy::load(&store, &genesis.root)?
        .ok_or_else(|| anyhow::anyhow!("membership policy is not enabled"))?;
    let current_id = old.id()?;
    let incoming_id = policy.id()?;
    if incoming_id == current_id {
        return Ok(());
    }
    let active_bytes = chain(&store, &old, &genesis.root)?;
    let active_ids: Vec<Id> = active_bytes
        .iter()
        .map(|b| Policy::decode(b)?.id())
        .collect::<Result<_>>()?;
    let incoming_ids: Vec<Id> = policies.iter().map(Policy::id).collect::<Result<_>>()?;
    let common = active_ids.len().min(incoming_ids.len());
    if active_ids[..common] != incoming_ids[..common] {
        for raw in &policy_bytes {
            let id = store.put(raw)?;
            ensure!(
                Policy::decode(raw)?.id()? == id,
                "fork evidence ID mismatch"
            );
        }
        store.write_new_control("membership-pending", b"signed-policy-fork")?;
        anyhow::bail!("root-signed policy fork detected; evidence retained and node quarantined");
    }
    if incoming_ids.len() <= active_ids.len() {
        anyhow::bail!("stale replay of an already applied policy");
    }
    ensure!(
        incoming_ids[..active_ids.len()] == active_ids[..],
        "policy chain does not descend from current trusted policy"
    );
    let key = enrollment::apply_rotation(&env, &device, genesis.root)?;
    let mut keys = app::secrets(&store, password, &genesis)?;
    archive_key(&store, &old, &genesis.root)?;
    store.write_new_control("membership-pending", b"rotation")?;
    let mut policy_id = None;
    for raw in &policy_bytes {
        let id = store.put(raw)?;
        ensure!(
            Policy::decode(raw)?.id()? == id,
            "policy object ID mismatch"
        );
        policy_id = Some(id);
    }
    let policy_id = policy_id.expect("nonempty policy chain");
    keys.replace_epoch_key(key);
    store.set_control("keys", &keys.lock(&genesis.collection, password)?)?;
    store.set_control("policy", &policy_id)?;
    store.clear_membership_pending()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_writer_revoke_and_epoch_rotation_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let pass = "root password";
        crate::app::init(&root, pass).unwrap();
        enable(&root, pass).unwrap();
        let reader_priv = tmp.path().join("reader.key");
        let reader_req = tmp.path().join("reader.req");
        let reader = create_request(&reader_priv, &reader_req, "reader password").unwrap();
        let reader_node = tmp.path().join("reader-node");
        let reader_inv = tmp.path().join("reader.inv");
        grant(&root, &reader_req, &reader_inv, Role::Reader, pass).unwrap();
        let trusted = crate::app::pinned(&Store::open(&root).unwrap()).unwrap().0;
        join_node(
            &reader_node,
            &reader_priv,
            &reader_inv,
            trusted,
            "reader password",
        )
        .unwrap();
        let reader_store = Store::open(&reader_node).unwrap();
        let (_, reader_genesis) = app::pinned(&reader_store).unwrap();
        let reader_policy = Policy::load(&reader_store, &reader_genesis.root)
            .unwrap()
            .unwrap();
        let signed_chain = chain(&reader_store, &reader_policy, &reader_genesis.root).unwrap();
        let mut malformed = Vec::new();
        let mut encoder = Encoder::new(&mut malformed);
        encoder
            .array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .array(signed_chain.len() as u64)
            .unwrap();
        for record in signed_chain {
            encoder.bytes(&record).unwrap();
        }
        encoder.array(257).unwrap();
        let oversized = tmp.path().join("oversized-envelopes.pkg");
        write_new(&oversized, &malformed).unwrap();
        let error = apply(&reader_node, &reader_priv, &oversized, "reader password").unwrap_err();
        assert!(error.to_string().contains("too many key envelopes"));
        assert!(!reader_node.join("control/membership-pending").exists());
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"snapshot bytes").unwrap();
        assert!(crate::app::capture(&reader_node, &source, "reader password").is_err());
        let writer_priv = tmp.path().join("writer.key");
        let writer_req_path = tmp.path().join("writer.req");
        let writer = create_request(&writer_priv, &writer_req_path, "writer password").unwrap();
        let writer_node = tmp.path().join("writer-node");
        let writer_inv = tmp.path().join("writer.inv");
        let root_store = Store::open(&root).unwrap();
        let before_policy = root_store.read_control("policy").unwrap();
        let before_keys = root_store.read_control("keys").unwrap();
        let held = writer_lock(&root_store).unwrap();
        assert!(grant(&root, &writer_req_path, &writer_inv, Role::Writer, pass).is_err());
        assert_eq!(root_store.read_control("keys").unwrap(), before_keys);
        assert_eq!(root_store.read_control("policy").unwrap(), before_policy);
        drop(held);
        grant(&root, &writer_req_path, &writer_inv, Role::Writer, pass).unwrap();
        join_node(
            &writer_node,
            &writer_priv,
            &writer_inv,
            trusted,
            "writer password",
        )
        .unwrap();
        let second_priv = tmp.path().join("writer2.key");
        let second_req_path = tmp.path().join("writer2.req");
        let second = create_request(&second_priv, &second_req_path, "writer2 password").unwrap();
        let second_node = tmp.path().join("writer2-node");
        let second_inv = tmp.path().join("writer2.inv");
        grant(&root, &second_req_path, &second_inv, Role::Writer, pass).unwrap();
        join_node(
            &second_node,
            &second_priv,
            &second_inv,
            trusted,
            "writer2 password",
        )
        .unwrap();
        let refresh_pkg = tmp.path().join("refresh.pkg");
        refresh(
            &root,
            &[reader.clone(), writer.clone(), second.clone()],
            &refresh_pkg,
            pass,
        )
        .unwrap();
        apply(&writer_node, &writer_priv, &refresh_pkg, "writer password").unwrap();
        crate::app::capture(&writer_node, &source, "writer password").unwrap();
        crate::app::capture(&second_node, &source, "writer2 password").unwrap();
        let writer_store = Store::open(&writer_node).unwrap();
        let (_, writer_genesis) = crate::app::pinned(&writer_store).unwrap();
        let historical_policy: Id = writer_store
            .read_control("policy")
            .unwrap()
            .try_into()
            .unwrap();
        let old = crate::app::secrets(&writer_store, "writer password", &writer_genesis).unwrap();
        let rotation = tmp.path().join("rotation.pkg");
        revoke(
            &root,
            writer.signing,
            &[reader.clone(), writer.clone(), second.clone()],
            &rotation,
            pass,
        )
        .unwrap();
        apply(&reader_node, &reader_priv, &rotation, "reader password").unwrap();
        assert!(crate::app::capture(&reader_node, &source, "reader password").is_err());
        let root_store = Store::open(&root).unwrap();
        let (_, genesis) = crate::app::pinned(&root_store).unwrap();
        let current = crate::policy::Policy::load(&root_store, &genesis.root)
            .unwrap()
            .unwrap();
        let archived = secrets_for_policy(&root_store, historical_policy, pass).unwrap();
        assert_eq!(archived.epoch_key(), old.epoch_key());
        let second_rotation = tmp.path().join("rotation2.pkg");
        revoke(
            &root,
            second.signing,
            std::slice::from_ref(&reader),
            &second_rotation,
            pass,
        )
        .unwrap();
        let after_second = Store::open(&root).unwrap();
        let still_archived = secrets_for_policy(&after_second, historical_policy, pass).unwrap();
        assert_eq!(still_archived.epoch_key(), old.epoch_key());
        apply(
            &reader_node,
            &reader_priv,
            &second_rotation,
            "reader password",
        )
        .unwrap();
        assert!(apply(&reader_node, &reader_priv, &rotation, "reader password").is_err());
        assert!(std::fs::symlink_metadata(reader_node.join("control/membership-pending")).is_err());
        assert!(!current.allows_writer(&writer.signing));
        let writer_device =
            DeviceSecrets::unlock(&read(&writer_priv, 256).unwrap(), "writer password").unwrap();
        assert!(current.attest([9; 32], &writer_device).is_err());
        let fresh = crate::app::secrets(&root_store, pass, &genesis).unwrap();
        let encrypted = fresh
            .seal(&genesis.collection, 1, b"new epoch data")
            .unwrap();
        assert!(old.open(&genesis.collection, 1, &encrypted).is_err());
    }
}
