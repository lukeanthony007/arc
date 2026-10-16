use crate::format::{self, Id, MAX_OBJECT, PROFILE, Snapshot};
use anyhow::{Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, Zeroizing};

const AAD_DOMAIN: &[u8] = b"arc-exp-1/object-aad\0";
const ROOT_DOMAIN: &[u8] = b"arc-exp-1/genesis-signature\0";
const SNAP_DOMAIN: &[u8] = b"arc-exp-1/snapshot-signature\0";
const KEY_DOMAIN: &[u8] = b"arc-exp-1/keystore-aad\0";

pub struct Secrets {
    root_seed: [u8; 32],
    epoch_key: [u8; 32],
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.root_seed.zeroize();
        self.epoch_key.zeroize();
    }
}
impl Secrets {
    pub fn generate() -> Self {
        let mut root_seed = [0; 32];
        let mut epoch_key = [0; 32];
        OsRng.fill_bytes(&mut root_seed);
        OsRng.fill_bytes(&mut epoch_key);
        Self {
            root_seed,
            epoch_key,
        }
    }
    pub fn root(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.root_seed)
            .verifying_key()
            .to_bytes()
    }
    /// Construct member keys without granting genesis authority.
    pub fn from_member(signing_seed: [u8; 32], epoch_key: [u8; 32]) -> Self {
        Self {
            root_seed: signing_seed,
            epoch_key,
        }
    }
    pub fn epoch_key(&self) -> [u8; 32] {
        self.epoch_key
    }
    pub fn replace_epoch_key(&mut self, key: [u8; 32]) {
        self.epoch_key.zeroize();
        self.epoch_key = key;
    }
    pub(crate) fn signing_seed(&self) -> [u8; 32] {
        self.root_seed
    }
    pub fn seal(&self, collection: &Id, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (kind == 1 || kind == 2) && plaintext.len() <= MAX_OBJECT,
            "invalid encrypted object"
        );
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&self.epoch_key).into());
        let aad = object_aad(collection, kind);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.array(5)?
            .u8(3)?
            .bytes(collection)?
            .u8(kind)?
            .bytes(&nonce)?
            .bytes(&ciphertext)?;
        ensure!(out.len() <= MAX_OBJECT, "encrypted object too large");
        Ok(out)
    }
    pub fn open(&self, collection: &Id, kind: u8, object: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            object.len() <= MAX_OBJECT && kind > 0 && kind < 3,
            "invalid encrypted object"
        );
        let mut d = Decoder::new(object);
        ensure!(
            d.array()? == Some(5) && d.u8()? == 3,
            "invalid encrypted object framing"
        );
        let c: Id = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("collection length"))?;
        let k = d.u8()?;
        let nonce: [u8; 24] = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce length"))?;
        let ct = d.bytes()?;
        ensure!(
            d.position() == object.len() && c == *collection && k == kind && ct.len() >= 16,
            "encrypted object binding mismatch"
        );
        let mut canonical = Vec::new();
        let mut e = Encoder::new(&mut canonical);
        e.array(5)?
            .u8(3)?
            .bytes(&c)?
            .u8(k)?
            .bytes(&nonce)?
            .bytes(ct)?;
        ensure!(canonical == object, "noncanonical encrypted object");
        let cipher = XChaCha20Poly1305::new((&self.epoch_key).into());
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ct,
                    aad: &object_aad(collection, kind),
                },
            )
            .map_err(|_| anyhow::anyhow!("authentication failed"))
    }
    pub fn sign_genesis(&self, collection: Id) -> Result<Vec<u8>> {
        let key = SigningKey::from_bytes(&self.root_seed);
        let mut m = ROOT_DOMAIN.to_vec();
        m.extend_from_slice(&collection);
        m.extend_from_slice(&key.verifying_key().to_bytes());
        let sig = key.sign(&m).to_bytes();
        format::encode_genesis(&collection, &key.verifying_key().to_bytes(), &sig)
    }
    pub fn sign_snapshot(&self, snapshot: &Snapshot) -> Result<Vec<u8>> {
        ensure!(
            snapshot.writer == self.root(),
            "snapshot writer does not match signing key"
        );
        let msg = snapshot_signing_bytes(snapshot)?;
        let sig = SigningKey::from_bytes(&self.root_seed)
            .sign(&msg)
            .to_bytes();
        format::encode_snapshot(snapshot, &sig)
    }
    pub(crate) fn sign_authority(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.root_seed)
            .sign(message)
            .to_bytes()
    }
    pub fn lock(&self, collection: &Id, password: &str) -> Result<Vec<u8>> {
        ensure!(
            !password.is_empty() && password.len() <= 4096,
            "invalid password length"
        );
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let params = Params::new(65536, 3, 1, Some(32))?;
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        a.hash_password_into(password.as_bytes(), &salt, &mut *key)?;
        let mut plain = Zeroizing::new([0u8; 64]);
        plain[..32].copy_from_slice(&self.root_seed);
        plain[32..].copy_from_slice(&self.epoch_key);
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let aad = keystore_aad(collection);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &*plain,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("keystore encryption failed"))?;
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.array(7)?
            .u8(1)?
            .str(PROFILE)?
            .bytes(collection)?
            .u8(1)?
            .bytes(&salt)?
            .bytes(&nonce)?
            .bytes(&ct)?;
        ensure!(out.len() <= 256, "keystore too large");
        Ok(out)
    }
    pub fn unlock(collection: &Id, bytes: &[u8], password: &str) -> Result<Self> {
        ensure!(
            !password.is_empty() && password.len() <= 4096,
            "invalid password length"
        );
        ensure!(bytes.len() <= 256, "keystore too large");
        let mut d = Decoder::new(bytes);
        ensure!(d.array()? == Some(7) && d.u8()? == 1, "invalid keystore");
        ensure!(d.str()? == PROFILE, "profile mismatch");
        let col: Id = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("collection length"))?;
        ensure!(col == *collection, "collection mismatch");
        ensure!(d.u8()? == 1, "unsupported KDF profile");
        let salt: [u8; 16] = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("salt length"))?;
        let nonce: [u8; 24] = d
            .bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce length"))?;
        let ct = d.bytes()?.to_vec();
        ensure!(
            d.position() == bytes.len() && ct.len() == 80,
            "invalid keystore ciphertext"
        );
        let mut canon = Vec::new();
        let mut e = Encoder::new(&mut canon);
        e.array(7)?
            .u8(1)?
            .str(PROFILE)?
            .bytes(&col)?
            .u8(1)?
            .bytes(&salt)?
            .bytes(&nonce)?
            .bytes(&ct)?;
        ensure!(canon == bytes, "noncanonical keystore");
        let params = Params::new(65536, 3, 1, Some(32))?;
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        a.hash_password_into(password.as_bytes(), &salt, &mut *key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &keystore_aad(collection),
                    },
                )
                .map_err(|_| anyhow::anyhow!("wrong password or damaged keystore"))?,
        );
        ensure!(plain.len() == 64, "invalid key material");
        let mut root_seed = [0; 32];
        let mut epoch_key = [0; 32];
        root_seed.copy_from_slice(&plain[..32]);
        epoch_key.copy_from_slice(&plain[32..]);
        Ok(Self {
            root_seed,
            epoch_key,
        })
    }
}
/// Independently provisioned device signing identity; it contains no collection authority or data key.
pub struct DeviceSecrets {
    seed: [u8; 32],
    envelope_seed: [u8; 32],
}
impl Drop for DeviceSecrets {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.envelope_seed.zeroize();
    }
}
impl DeviceSecrets {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        let mut envelope_seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        OsRng.fill_bytes(&mut envelope_seed);
        Self {
            seed,
            envelope_seed,
        }
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut envelope_seed = [0u8; 32];
        OsRng.fill_bytes(&mut envelope_seed);
        Self {
            seed,
            envelope_seed,
        }
    }
    pub fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }
    pub fn encryption_public(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey, StaticSecret};
        *PublicKey::from(&StaticSecret::from(self.envelope_seed)).as_bytes()
    }
    pub(crate) fn envelope_seed(&self) -> [u8; 32] {
        self.envelope_seed
    }
    pub(crate) fn signing_seed(&self) -> [u8; 32] {
        self.seed
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }
    pub fn sign_snapshot(&self, snapshot: &Snapshot) -> Result<Vec<u8>> {
        ensure!(
            snapshot.writer == self.public(),
            "snapshot writer does not match device"
        );
        let message = snapshot_signing_bytes(snapshot)?;
        format::encode_snapshot(snapshot, &self.sign(&message))
    }
    /// Store both independent private keys under password-based authenticated encryption.
    pub fn lock(&self, password: &str) -> Result<Vec<u8>> {
        ensure!(
            !password.is_empty() && password.len() <= 4096,
            "invalid password length"
        );
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let params = Params::new(65536, 3, 1, Some(32))?;
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        a.hash_password_into(password.as_bytes(), &salt, &mut *key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let mut material = Zeroizing::new([0u8; 64]);
        material[..32].copy_from_slice(&self.seed);
        material[32..].copy_from_slice(&self.envelope_seed);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &*material,
                    aad: b"arc-exp-1/device-key-v2\0",
                },
            )
            .map_err(|_| anyhow::anyhow!("device key encryption failed"))?;
        let mut out = Vec::new();
        Encoder::new(&mut out)
            .array(4)?
            .u8(2)?
            .bytes(&salt)?
            .bytes(&nonce)?
            .bytes(&ct)?;
        Ok(out)
    }
    pub fn unlock(bytes: &[u8], password: &str) -> Result<Self> {
        ensure!(
            !password.is_empty() && password.len() <= 4096 && bytes.len() <= 256,
            "invalid device key input"
        );
        let mut d = Decoder::new(bytes);
        ensure!(
            d.array()? == Some(4) && d.u8()? == 2,
            "unsupported device key format"
        );
        let salt: [u8; 16] = d.bytes()?.try_into()?;
        let nonce: [u8; 24] = d.bytes()?.try_into()?;
        let ct = d.bytes()?;
        ensure!(d.position() == bytes.len(), "trailing device key bytes");
        let params = Params::new(65536, 3, 1, Some(32))?;
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        a.hash_password_into(password.as_bytes(), &salt, &mut *key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: ct,
                        aad: b"arc-exp-1/device-key-v2\0",
                    },
                )
                .map_err(|_| anyhow::anyhow!("device key authentication failed"))?,
        );
        ensure!(plain.len() == 64, "invalid device key plaintext");
        let mut seed = [0u8; 32];
        let mut envelope_seed = [0u8; 32];
        seed.copy_from_slice(&plain[..32]);
        envelope_seed.copy_from_slice(&plain[32..]);
        Ok(Self {
            seed,
            envelope_seed,
        })
    }
}
fn object_aad(c: &Id, k: u8) -> Vec<u8> {
    let mut a = AAD_DOMAIN.to_vec();
    a.extend_from_slice(PROFILE.as_bytes());
    a.extend_from_slice(c);
    a.push(k);
    a
}
fn keystore_aad(c: &Id) -> Vec<u8> {
    let mut a = KEY_DOMAIN.to_vec();
    a.extend_from_slice(PROFILE.as_bytes());
    a.extend_from_slice(c);
    a
}
pub(crate) fn snapshot_signing_bytes(s: &Snapshot) -> Result<Vec<u8>> {
    ensure!(
        s.parents.len() <= 64 && s.objects.len() <= format::MAX_CHUNKS,
        "snapshot limits exceeded"
    );
    ensure!(
        s.parents.windows(2).all(|w| w[0] < w[1]) && s.objects.windows(2).all(|w| w[0] < w[1]),
        "snapshot IDs must be sorted unique"
    );
    ensure!(
        s.objects.binary_search(&s.manifest).is_ok(),
        "manifest missing from snapshot closure"
    );
    let mut b = Vec::new();
    b.extend_from_slice(SNAP_DOMAIN);
    let mut e = Encoder::new(&mut b);
    e.array(7)?
        .u8(1)?
        .bytes(&s.collection)?
        .bytes(&s.genesis)?
        .bytes(&s.writer)?
        .array(s.parents.len() as u64)?;
    for x in &s.parents {
        e.bytes(x)?;
    }
    e.bytes(&s.manifest)?.array(s.objects.len() as u64)?;
    for x in &s.objects {
        e.bytes(x)?;
    }
    ensure!(b.len() <= MAX_OBJECT, "snapshot too large");
    Ok(b)
}
pub(crate) fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key =
        VerifyingKey::from_bytes(public).map_err(|_| anyhow::anyhow!("invalid signing key"))?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| anyhow::anyhow!("signature verification failed"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encryption_binds_collection_kind_and_ciphertext() {
        let s = Secrets::generate();
        let c = [9; 32];
        let o = s.seal(&c, 1, b"plaintext").unwrap();
        assert_eq!(s.open(&c, 1, &o).unwrap(), b"plaintext");
        assert!(s.open(&[8; 32], 1, &o).is_err());
        assert!(s.open(&c, 2, &o).is_err());
        let mut t = o;
        t[15] ^= 1;
        assert!(s.open(&c, 1, &t).is_err());
    }
    #[test]
    fn locked_keys_authenticate_password_and_collection() {
        let s = Secrets::generate();
        let c = [4; 32];
        let b = s.lock(&c, "correct").unwrap();
        assert_eq!(Secrets::unlock(&c, &b, "correct").unwrap().root(), s.root());
        assert!(Secrets::unlock(&c, &b, "wrong").is_err());
        assert!(Secrets::unlock(&[5; 32], &b, "correct").is_err());
    }
    #[test]
    fn signatures_are_strict() {
        let s = Secrets::generate();
        let c = [7; 32];
        let raw = s.sign_genesis(c).unwrap();
        assert!(format::inspect(&raw).is_ok());
        let mut changed = raw;
        let n = changed.len();
        changed[n - 3] ^= 1;
        assert!(format::inspect(&changed).is_err());
        let snap = Snapshot {
            collection: c,
            genesis: [2; 32],
            writer: s.root(),
            parents: vec![],
            manifest: [3; 32],
            objects: vec![[3; 32]],
        };
        let signed = s.sign_snapshot(&snap).unwrap();
        assert!(format::inspect(&signed).is_ok());
        let mut changed = signed;
        let n = changed.len();
        changed[n - 1] ^= 1;
        assert!(format::inspect(&changed).is_err());
    }
}
