use crate::{
    crypto,
    format::{self, Id, Snapshot},
};
use anyhow::{Result, ensure};
use ed25519_dalek::{Signer, SigningKey};
use minicbor::{Decoder, Encoder};

const DOMAIN: &[u8] = b"arc-exp-1/policy\0";
const MAX_MEMBERS: usize = 256;
const MAX_ACCEPTED: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Reader = 1,
    Writer = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: [u8; 32],
    pub role: Role,
    pub revoked: bool,
}

/// Root-authority-signed membership and accepted-snapshot frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub collection: Id,
    pub authority: [u8; 32],
    pub epoch: u64,
    pub previous: Option<Id>,
    pub members: Vec<Member>,
    pub accepted: Vec<Id>,
    pub signature: [u8; 64],
}
impl Policy {
    pub fn new(
        collection: Id,
        authority: [u8; 32],
        epoch: u64,
        previous: Option<Id>,
        mut members: Vec<Member>,
        mut accepted: Vec<Id>,
        seed: &[u8; 32],
    ) -> Result<Self> {
        members.sort_by_key(|m| m.key);
        accepted.sort();
        let mut p = Self {
            collection,
            authority,
            epoch,
            previous,
            members,
            accepted,
            signature: [0; 64],
        };
        p.validate()?;
        ensure!(
            SigningKey::from_bytes(seed).verifying_key().to_bytes() == authority,
            "authority key mismatch"
        );
        p.signature = SigningKey::from_bytes(seed)
            .sign(&p.signing_bytes()?)
            .to_bytes();
        Ok(p)
    }
    pub fn new_with_secrets(
        collection: Id,
        epoch: u64,
        previous: Option<Id>,
        members: Vec<Member>,
        accepted: Vec<Id>,
        secrets: &crypto::Secrets,
    ) -> Result<Self> {
        let authority = secrets.root();
        let mut p = Self {
            collection,
            authority,
            epoch,
            previous,
            members,
            accepted,
            signature: [0; 64],
        };
        p.members.sort_by_key(|m| m.key);
        p.accepted.sort();
        p.validate()?;
        p.signature = secrets.sign_authority(&p.signing_bytes()?);
        Ok(p)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.array(9)?
            .u8(1)?
            .bytes(&self.collection)?
            .bytes(&self.authority)?
            .u64(self.epoch)?;
        match self.previous {
            Some(id) => {
                e.bytes(&id)?;
            }
            None => {
                e.null()?;
            }
        }
        e.array(self.members.len() as u64)?;
        for m in &self.members {
            e.array(3)?
                .bytes(&m.key)?
                .u8(m.role as u8)?
                .bool(m.revoked)?;
        }
        e.array(self.accepted.len() as u64)?;
        for id in &self.accepted {
            e.bytes(id)?;
        }
        e.bytes(&self.signature)?.u8(1)?;
        ensure!(out.len() <= format::MAX_OBJECT, "policy too large");
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= format::MAX_OBJECT, "policy too large");
        let mut d = Decoder::new(bytes);
        ensure!(d.array()? == Some(9) && d.u8()? == 1, "unsupported policy");
        let collection = fixed32(&mut d)?;
        let authority = fixed32(&mut d)?;
        let epoch = d.u64()?;
        let previous = if d.datatype()? == minicbor::data::Type::Null {
            d.null()?;
            None
        } else {
            Some(fixed32(&mut d)?)
        };
        let n = d
            .array()?
            .ok_or_else(|| anyhow::anyhow!("indefinite policy members"))? as usize;
        ensure!(n <= MAX_MEMBERS, "too many policy members");
        let mut members = Vec::with_capacity(n);
        for _ in 0..n {
            ensure!(d.array()? == Some(3), "invalid member");
            let key = fixed32(&mut d)?;
            let role = match d.u8()? {
                1 => Role::Reader,
                2 => Role::Writer,
                _ => anyhow::bail!("invalid member role"),
            };
            let revoked = d.bool()?;
            members.push(Member { key, role, revoked });
        }
        let n = d
            .array()?
            .ok_or_else(|| anyhow::anyhow!("indefinite accepted set"))? as usize;
        ensure!(n <= MAX_ACCEPTED, "too many accepted snapshots");
        let mut accepted = Vec::with_capacity(n);
        for _ in 0..n {
            accepted.push(fixed32(&mut d)?);
        }
        let signature = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid policy signature"))?;
        ensure!(
            d.u8()? == 1 && d.position() == bytes.len(),
            "trailing policy bytes"
        );
        let p = Self {
            collection,
            authority,
            epoch,
            previous,
            members,
            accepted,
            signature,
        };
        p.validate()?;
        ensure!(p.encode()? == bytes, "noncanonical policy");
        Ok(p)
    }
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut b = DOMAIN.to_vec();
        let mut e = Encoder::new(&mut b);
        e.array(7)?
            .u8(1)?
            .bytes(&self.collection)?
            .bytes(&self.authority)?
            .u64(self.epoch)?;
        match self.previous {
            Some(id) => {
                e.bytes(&id)?;
            }
            None => {
                e.null()?;
            }
        }
        e.array(self.members.len() as u64)?;
        for m in &self.members {
            e.array(3)?
                .bytes(&m.key)?
                .u8(m.role as u8)?
                .bool(m.revoked)?;
        }
        e.array(self.accepted.len() as u64)?;
        for id in &self.accepted {
            e.bytes(id)?;
        }
        Ok(b)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.members.len() <= MAX_MEMBERS && self.accepted.len() <= MAX_ACCEPTED,
            "policy limits exceeded"
        );
        ensure!(
            self.members.windows(2).all(|w| w[0].key < w[1].key),
            "members not sorted unique"
        );
        ensure!(
            self.accepted.windows(2).all(|w| w[0] < w[1]),
            "accepted IDs not sorted unique"
        );
        ensure!(
            (self.epoch == 0) == self.previous.is_none(),
            "invalid policy chain"
        );
        Ok(())
    }
    pub fn verify(&self, authority: &[u8; 32]) -> Result<()> {
        self.validate()?;
        ensure!(&self.authority == authority, "unexpected policy authority");
        crypto::verify(authority, &self.signing_bytes()?, &self.signature)
    }
    pub fn allows_writer(&self, key: &[u8; 32]) -> bool {
        self.members
            .binary_search_by_key(key, |m| m.key)
            .ok()
            .is_some_and(|i| self.members[i].role == Role::Writer && !self.members[i].revoked)
    }
    pub fn authorize_snapshot_id(&self, s: &Snapshot, id: &Id) -> Result<()> {
        ensure!(
            s.collection == self.collection,
            "snapshot collection mismatch"
        );
        ensure!(
            self.accepted.binary_search(id).is_ok(),
            "snapshot outside accepted policy frontier"
        );
        Ok(())
    }
    pub fn authorize_attested_snapshot(
        &self,
        snapshot: &Snapshot,
        snapshot_id: &Id,
        attestation: &Attestation,
    ) -> Result<()> {
        ensure!(
            snapshot.collection == self.collection
                && snapshot.writer == attestation.writer
                && attestation.snapshot == *snapshot_id,
            "snapshot attestation binding mismatch"
        );
        attestation.verify(self)
    }
    pub fn id(&self) -> Result<Id> {
        Ok(format::id(&self.encode()?))
    }
    pub fn attest(
        &self,
        snapshot_id: Id,
        writer: &crate::crypto::DeviceSecrets,
    ) -> Result<Attestation> {
        ensure!(
            self.allows_writer(&writer.public()),
            "device is not an active writer"
        );
        let mut a = Attestation {
            policy: self.id()?,
            snapshot: snapshot_id,
            writer: writer.public(),
            epoch: self.epoch,
            signature: [0; 64],
        };
        a.signature = writer.sign(&a.message()?);
        Ok(a)
    }
    pub fn publish(&self, store: &crate::store::Store) -> Result<Id> {
        let bytes = self.encode()?;
        let id = store.put(&bytes)?;
        store.set_control("policy", &id)?;
        Ok(id)
    }
    pub fn load(store: &crate::store::Store, authority: &[u8; 32]) -> Result<Option<Self>> {
        let pin_path = store.path().join("control").join("policy");
        match std::fs::symlink_metadata(&pin_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let id = store.read_control("policy")?;
        ensure!(id.len() == 32, "invalid policy pin");
        let id: Id = id
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid policy pin"))?;
        let bytes = store.get(&id)?;
        ensure!(format::id(&bytes) == id, "policy content ID mismatch");
        let p = Self::decode(&bytes)?;
        p.verify(authority)?;
        let mut child = p.clone();
        let mut links = 0usize;
        while let Some(previous) = child.previous {
            links += 1;
            ensure!(
                links <= 256 && child.epoch > 0,
                "policy chain limit or epoch invalid"
            );
            let raw = store.get(&previous)?;
            ensure!(
                format::id(&raw) == previous,
                "policy predecessor ID mismatch"
            );
            let parent = Self::decode(&raw)?;
            parent.verify(authority)?;
            ensure!(
                parent.collection == p.collection
                    && parent.epoch.checked_add(1) == Some(child.epoch),
                "policy chain fork or stale epoch"
            );
            child = parent;
        }
        ensure!(
            child.epoch == 0,
            "policy chain does not reach genesis policy"
        );
        Ok(Some(p))
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub policy: Id,
    pub snapshot: Id,
    pub writer: [u8; 32],
    pub epoch: u64,
    pub signature: [u8; 64],
}
impl Attestation {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = b"arc-exp-1/snapshot-attestation\0".to_vec();
        Encoder::new(&mut b)
            .array(5)?
            .u8(1)?
            .bytes(&self.policy)?
            .bytes(&self.snapshot)?
            .bytes(&self.writer)?
            .u64(self.epoch)?;
        Ok(b)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        Encoder::new(&mut b)
            .array(6)?
            .u8(1)?
            .bytes(&self.policy)?
            .bytes(&self.snapshot)?
            .bytes(&self.writer)?
            .u64(self.epoch)?
            .bytes(&self.signature)?;
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 256, "attestation too large");
        let mut d = Decoder::new(bytes);
        ensure!(d.array()? == Some(6) && d.u8()? == 1, "invalid attestation");
        let a = Self {
            policy: fixed32(&mut d)?,
            snapshot: fixed32(&mut d)?,
            writer: fixed32(&mut d)?,
            epoch: d.u64()?,
            signature: d
                .bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid attestation signature"))?,
        };
        ensure!(
            d.position() == bytes.len() && a.encode()? == bytes,
            "noncanonical attestation"
        );
        Ok(a)
    }
    pub fn verify(&self, policy: &Policy) -> Result<()> {
        ensure!(
            self.policy == policy.id()?
                && self.epoch == policy.epoch
                && policy.allows_writer(&self.writer),
            "attestation policy mismatch"
        );
        crypto::verify(&self.writer, &self.message()?, &self.signature)
    }
}
fn fixed32(d: &mut Decoder<'_>) -> Result<[u8; 32]> {
    d.bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fixed-width field"))
}
