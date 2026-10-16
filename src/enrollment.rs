use crate::{
    crypto::{self, DeviceSecrets, Secrets},
    format::{self, Id, Record},
    policy::{Member, Policy, Role},
    store::Store,
};
use anyhow::{Result, ensure};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use minicbor::{Decoder, Encoder};
use rand_core::{OsRng, TryRngCore};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
const REQ: &[u8] = b"arc-exp-1/enrollment-request\0";
const INV: &[u8] = b"arc-exp-1/enrollment-invite\0";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
    pub signature: [u8; 64],
}
impl Request {
    pub fn create(d: &DeviceSecrets) -> Self {
        let mut r = Self {
            signing: d.public(),
            encryption: d.encryption_public(),
            signature: [0; 64],
        };
        r.signature = d.sign(&r.message());
        r
    }
    fn message(&self) -> Vec<u8> {
        let mut b = REQ.to_vec();
        b.extend_from_slice(&self.signing);
        b.extend_from_slice(&self.encryption);
        b
    }
    pub fn verify(&self) -> Result<()> {
        crypto::verify(&self.signing, &self.message(), &self.signature)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        Encoder::new(&mut b)
            .array(4)?
            .u8(1)?
            .bytes(&self.signing)?
            .bytes(&self.encryption)?
            .bytes(&self.signature)?;
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() <= 256, "request too large");
        let mut d = Decoder::new(b);
        ensure!(d.array()? == Some(4) && d.u8()? == 1, "invalid request");
        let r = Self {
            signing: d.bytes()?.try_into()?,
            encryption: d.bytes()?.try_into()?,
            signature: d.bytes()?.try_into()?,
        };
        ensure!(
            d.position() == b.len() && r.encode()? == b,
            "noncanonical request"
        );
        r.verify()?;
        Ok(r)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    pub collection: Id,
    pub genesis: Id,
    pub policy: Id,
    pub epoch: u64,
    pub recipient: [u8; 32],
    pub role: Role,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}
impl Invitation {
    fn wire(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        Encoder::new(&mut b)
            .array(10)?
            .u8(1)?
            .bytes(&self.collection)?
            .bytes(&self.genesis)?
            .bytes(&self.policy)?
            .u64(self.epoch)?
            .bytes(&self.recipient)?
            .u8(self.role as u8)?
            .bytes(&self.enc)?
            .bytes(&self.ciphertext)?
            .bytes(&self.signature)?;
        Ok(b)
    }
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = INV.to_vec();
        b.extend_from_slice(&self.wire()?);
        Ok(b)
    }
    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut x = self.clone();
        x.signature = [0; 64];
        x.message()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.wire()
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() <= 1024, "invitation too large");
        let mut d = Decoder::new(b);
        ensure!(d.array()? == Some(10) && d.u8()? == 1, "invalid invitation");
        let x = Self {
            collection: d.bytes()?.try_into()?,
            genesis: d.bytes()?.try_into()?,
            policy: d.bytes()?.try_into()?,
            epoch: d.u64()?,
            recipient: d.bytes()?.try_into()?,
            role: match d.u8()? {
                1 => Role::Reader,
                2 => Role::Writer,
                _ => anyhow::bail!("invalid role"),
            },
            enc: d.bytes()?.to_vec(),
            ciphertext: d.bytes()?.to_vec(),
            signature: d.bytes()?.try_into()?,
        };
        ensure!(
            d.position() == b.len() && x.encode()? == b,
            "noncanonical invitation"
        );
        Ok(x)
    }
    fn frontier(store: &Store, policy: &Policy) -> Result<Vec<Id>> {
        let mut ids = policy.accepted.clone();
        let mut scanned = 0;
        for entry in std::fs::read_dir(store.path().join("objects"))? {
            scanned += 1;
            ensure!(
                scanned <= 16_384,
                "object inventory exceeds policy scan limit"
            );
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(id) = format::parse_id(name) else {
                continue;
            };
            let Ok(bytes) = store.get(&id) else { continue };
            let Ok(att) = crate::policy::Attestation::decode(&bytes) else {
                continue;
            };
            if att.verify(policy).is_err() {
                continue;
            }
            let Ok(record_bytes) = store.get(&att.snapshot) else {
                continue;
            };
            if format::id(&record_bytes) != att.snapshot {
                continue;
            }
            let Ok(Record::Snapshot(snapshot)) = format::inspect(&record_bytes) else {
                continue;
            };
            if snapshot.collection == policy.collection && snapshot.writer == att.writer {
                ids.push(att.snapshot);
            }
        }
        ids.sort();
        ids.dedup();
        ensure!(ids.len() <= 4096, "accepted frontier exceeds policy limit");
        Ok(ids)
    }
    pub fn grant(
        store: &Store,
        collection: Id,
        genesis: Id,
        policy: &Policy,
        request: &Request,
        role: Role,
        admin: &Secrets,
    ) -> Result<Self> {
        let (invitation, successor) =
            Self::prepare_grant(store, collection, genesis, policy, request, role, admin)?;
        successor.publish(store)?;
        Ok(invitation)
    }
    pub fn prepare_grant(
        store: &Store,
        collection: Id,
        genesis: Id,
        policy: &Policy,
        request: &Request,
        role: Role,
        admin: &Secrets,
    ) -> Result<(Self, Policy)> {
        request.verify()?;
        ensure!(
            policy.collection == collection && policy.authority == admin.root(),
            "policy authority mismatch"
        );
        let epoch = policy
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?;
        let mut members = policy.members.clone();
        members.retain(|m| m.key != request.signing);
        members.push(Member {
            key: request.signing,
            role,
            revoked: false,
        });
        let successor = Policy::new_with_secrets(
            collection,
            epoch,
            Some(policy.id()?),
            members,
            Invitation::frontier(store, policy)?,
            admin,
        )?;
        let id = successor.id()?;
        let aad = aad(&collection, &genesis, &id, epoch, &request.signing, role);
        let pk = <Kem as KemTrait>::PublicKey::from_bytes(&request.encryption)?;
        let (enc, mut ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &pk,
            INV,
            &mut OsRng.unwrap_err(),
        )
        .map_err(|e| anyhow::anyhow!("HPKE setup failed: {e:?}"))?;
        let mut payload = Zeroizing::new([0; 64]);
        payload[..32].copy_from_slice(&admin.epoch_key());
        payload[32..].copy_from_slice(&id);
        let ciphertext = ctx
            .seal(&*payload, &aad)
            .map_err(|e| anyhow::anyhow!("HPKE seal failed: {e:?}"))?;
        let mut x = Self {
            collection,
            genesis,
            policy: id,
            epoch,
            recipient: request.signing,
            role,
            enc: enc.to_bytes().to_vec(),
            ciphertext,
            signature: [0; 64],
        };
        x.signature = admin.sign_authority(&x.signing_message()?);
        Ok((x, successor))
    }
    pub fn verify(&self, authority: &[u8; 32]) -> Result<()> {
        ensure!(
            self.enc.len() == 32 && self.ciphertext.len() == 80,
            "invalid invitation bounds"
        );
        crypto::verify(authority, &self.signing_message()?, &self.signature)
    }
}
fn aad(
    collection: &Id,
    genesis: &Id,
    policy: &Id,
    epoch: u64,
    recipient: &[u8; 32],
    role: Role,
) -> Vec<u8> {
    let mut bytes = INV.to_vec();
    let _ = Encoder::new(&mut bytes)
        .array(6)
        .and_then(|e| e.bytes(collection))
        .and_then(|e| e.bytes(genesis))
        .and_then(|e| e.bytes(policy))
        .and_then(|e| e.u64(epoch))
        .and_then(|e| e.bytes(recipient))
        .and_then(|e| e.u8(role as u8));
    bytes
}
pub fn join(
    i: &Invitation,
    request: &Request,
    d: &DeviceSecrets,
    trusted_genesis: Id,
    authority: [u8; 32],
) -> Result<Secrets> {
    i.verify(&authority)?;
    request.verify()?;
    ensure!(
        i.genesis == trusted_genesis
            && i.recipient == d.public()
            && request.signing == d.public()
            && request.encryption == d.encryption_public(),
        "invitation recipient/genesis mismatch"
    );
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&i.enc)?;
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&d.envelope_seed())?;
    let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, INV)?;
    let plain = Zeroizing::new(ctx.open(
        &i.ciphertext,
        &aad(
            &i.collection,
            &i.genesis,
            &i.policy,
            i.epoch,
            &i.recipient,
            i.role,
        ),
    )?);
    ensure!(
        plain.len() == 64 && plain[32..] == i.policy,
        "invitation payload mismatch"
    );
    let mut key = [0; 32];
    key.copy_from_slice(&plain[..32]);
    Ok(Secrets::from_member(d.signing_seed(), key))
}
pub struct KeyEnvelope {
    pub collection: Id,
    pub genesis: Id,
    pub policy: Id,
    pub epoch: u64,
    pub recipient: [u8; 32],
    pub role: Role,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}
impl KeyEnvelope {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = b"arc-exp-1/epoch-envelope\0".to_vec();
        Encoder::new(&mut b)
            .array(9)?
            .u8(1)?
            .bytes(&self.collection)?
            .bytes(&self.genesis)?
            .bytes(&self.policy)?
            .u64(self.epoch)?
            .bytes(&self.recipient)?
            .u8(self.role as u8)?
            .bytes(&self.enc)?
            .bytes(&self.ciphertext)?;
        Ok(b)
    }
    pub fn verify(&self, authority: &[u8; 32]) -> Result<()> {
        ensure!(
            self.enc.len() == 32 && self.ciphertext.len() == 48,
            "invalid epoch envelope bounds"
        );
        crypto::verify(authority, &self.message()?, &self.signature)
    }
}
pub struct Rotation {
    pub policy: Policy,
    pub key: Zeroizing<[u8; 32]>,
    pub envelopes: Vec<KeyEnvelope>,
}
pub fn rotate(
    store: &Store,
    genesis: Id,
    policy: &Policy,
    admin: &Secrets,
    accepted: Vec<Id>,
    members: Vec<Member>,
    devices: &[Request],
) -> Result<Rotation> {
    let rotation = prepare_rotate(store, genesis, policy, admin, accepted, members, devices)?;
    rotation.policy.publish(store)?;
    Ok(rotation)
}
pub fn prepare_rotate(
    store: &Store,
    genesis: Id,
    policy: &Policy,
    admin: &Secrets,
    mut accepted: Vec<Id>,
    members: Vec<Member>,
    devices: &[Request],
) -> Result<Rotation> {
    ensure!(policy.authority == admin.root(), "not policy authority");
    accepted.extend(Invitation::frontier(store, policy)?);
    accepted.sort();
    accepted.dedup();
    let next = Policy::new_with_secrets(
        policy.collection,
        policy
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?,
        Some(policy.id()?),
        members,
        accepted,
        admin,
    )?;
    ensure!(
        next.allows_writer(&admin.root()),
        "root authority must remain an active writer"
    );
    for member in next
        .members
        .iter()
        .filter(|m| !m.revoked && m.key != admin.root())
    {
        ensure!(
            devices.iter().filter(|d| d.signing == member.key).count() == 1,
            "missing or duplicate encryption request for active member"
        );
    }
    for request in devices {
        request.verify()?;
        ensure!(
            next.members
                .iter()
                .any(|m| m.key == request.signing && !m.revoked),
            "envelope requested for inactive member"
        );
    }
    let pid = next.id()?;
    let mut key = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut key)
        .map_err(|e| anyhow::anyhow!("OS randomness failed: {e}"))?;
    let mut envelopes = Vec::new();
    for d in devices {
        d.verify()?;
        let member = next
            .members
            .iter()
            .find(|m| m.key == d.signing && !m.revoked)
            .ok_or_else(|| anyhow::anyhow!("device not active"))?;
        let pk = <Kem as KemTrait>::PublicKey::from_bytes(&d.encryption)?;
        let associated = aad(
            &policy.collection,
            &genesis,
            &pid,
            next.epoch,
            &d.signing,
            member.role,
        );
        let (enc, mut ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &pk,
            INV,
            &mut rand_core::OsRng.unwrap_err(),
        )
        .map_err(|e| anyhow::anyhow!("HPKE setup failed: {e:?}"))?;
        let ct = ctx
            .seal(&key, &associated)
            .map_err(|e| anyhow::anyhow!("HPKE seal failed: {e:?}"))?;
        let mut envelope = KeyEnvelope {
            collection: policy.collection,
            genesis,
            policy: pid,
            epoch: next.epoch,
            recipient: d.signing,
            role: member.role,
            enc: enc.to_bytes().to_vec(),
            ciphertext: ct,
            signature: [0; 64],
        };
        envelope.signature = admin.sign_authority(&envelope.message()?);
        envelopes.push(envelope);
    }
    Ok(Rotation {
        policy: next,
        key: key.into(),
        envelopes,
    })
}
pub fn enable(
    store: &Store,
    collection: Id,
    secrets: &Secrets,
    accepted: Vec<Id>,
) -> Result<Policy> {
    let policy = prepare_enable(collection, secrets, accepted)?;
    policy.publish(store)?;
    Ok(policy)
}
pub fn prepare_enable(collection: Id, secrets: &Secrets, accepted: Vec<Id>) -> Result<Policy> {
    let policy = Policy::new_with_secrets(
        collection,
        0,
        None,
        vec![Member {
            key: secrets.root(),
            role: Role::Writer,
            revoked: false,
        }],
        accepted,
        secrets,
    )?;
    Ok(policy)
}
pub fn refresh_envelopes(
    genesis: Id,
    policy: &Policy,
    admin: &Secrets,
    devices: &[Request],
) -> Result<Vec<KeyEnvelope>> {
    ensure!(policy.authority == admin.root(), "not policy authority");
    let mut out = Vec::new();
    for d in devices {
        d.verify()?;
        let member = policy
            .members
            .iter()
            .find(|m| m.key == d.signing && !m.revoked)
            .ok_or_else(|| anyhow::anyhow!("device not active"))?;
        let pk = <Kem as KemTrait>::PublicKey::from_bytes(&d.encryption)?;
        let pid = policy.id()?;
        let associated = aad(
            &policy.collection,
            &genesis,
            &pid,
            policy.epoch,
            &d.signing,
            member.role,
        );
        let (enc, mut ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &pk,
            INV,
            &mut rand_core::OsRng.unwrap_err(),
        )
        .map_err(|e| anyhow::anyhow!("HPKE setup failed: {e:?}"))?;
        let ct = ctx
            .seal(&admin.epoch_key(), &associated)
            .map_err(|e| anyhow::anyhow!("HPKE seal failed: {e:?}"))?;
        let mut env = KeyEnvelope {
            collection: policy.collection,
            genesis,
            policy: pid,
            epoch: policy.epoch,
            recipient: d.signing,
            role: member.role,
            enc: enc.to_bytes().to_vec(),
            ciphertext: ct,
            signature: [0; 64],
        };
        env.signature = admin.sign_authority(&env.message()?);
        out.push(env);
    }
    ensure!(
        out.iter()
            .map(|x| x.recipient)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == out.len(),
        "duplicate refresh recipients"
    );
    Ok(out)
}
pub fn apply_rotation(
    envelope: &KeyEnvelope,
    device: &DeviceSecrets,
    authority: [u8; 32],
) -> Result<[u8; 32]> {
    envelope.verify(&authority)?;
    ensure!(
        envelope.recipient == device.public(),
        "wrong rotation recipient"
    );
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.enc)?;
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&device.envelope_seed())?;
    let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, INV)
        .map_err(|e| anyhow::anyhow!("HPKE setup failed: {e:?}"))?;
    let aad = aad(
        &envelope.collection,
        &envelope.genesis,
        &envelope.policy,
        envelope.epoch,
        &envelope.recipient,
        envelope.role,
    );
    let plain = ctx
        .open(&envelope.ciphertext, &aad)
        .map_err(|e| anyhow::anyhow!("HPKE open failed: {e:?}"))?;
    plain
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid epoch key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hpke_reader_grant_is_recipient_bound_and_excludes_authority_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::create(&tmp.path().join("node")).unwrap();
        let admin = Secrets::generate();
        let genesis = [3u8; 32];
        let collection = [4u8; 32];
        let policy = enable(&store, collection, &admin, Vec::new()).unwrap();
        let device = DeviceSecrets::generate();
        let request = Request::create(&device);
        let invitation = Invitation::grant(
            &store,
            collection,
            genesis,
            &policy,
            &request,
            Role::Reader,
            &admin,
        )
        .unwrap();
        let encoded = invitation.encode().unwrap();
        assert!(!encoded.windows(32).any(|w| w == admin.signing_seed()));
        let decoded = Invitation::decode(&encoded).unwrap();
        decoded.verify(&admin.root()).unwrap();
        let joined = join(&decoded, &request, &device, genesis, admin.root()).unwrap();
        assert_eq!(joined.epoch_key(), admin.epoch_key());
        assert_ne!(joined.root(), admin.root());
        let another = DeviceSecrets::generate();
        assert!(
            join(
                &decoded,
                &Request::create(&another),
                &another,
                genesis,
                admin.root()
            )
            .is_err()
        );
        assert!(
            Policy::load(&store, &admin.root())
                .unwrap()
                .unwrap()
                .attest([8; 32], &DeviceSecrets::from_seed(joined.signing_seed()))
                .is_err()
        );
    }
}
