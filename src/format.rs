use anyhow::{Result, bail, ensure};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

pub type Id = [u8; 32];
pub const MAX_OBJECT: usize = 1_048_576;
pub const MAX_MANIFEST: usize = MAX_OBJECT - 128;
pub const CHUNK_SIZE: usize = 65_536;
pub const MAX_CHUNKS: usize = 4096;
pub const MAX_ENTRIES: usize = 4096;
pub const PROFILE: &str = "arc-exp-1";
const DOMAIN: &[u8] = b"arc-exp-1/id\0";

pub fn id(bytes: &[u8]) -> Id {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(bytes);
    h.finalize().into()
}
pub fn parse_id(text: &str) -> Result<Id> {
    ensure!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid id"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid id"))
}
pub fn display_id(id: &Id) -> String {
    hex::encode(id)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Genesis {
    pub collection: Id,
    pub root: [u8; 32],
}
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub collection: Id,
    pub genesis: Id,
    pub writer: [u8; 32],
    pub parents: Vec<Id>,
    pub manifest: Id,
    pub objects: Vec<Id>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    Genesis(Genesis),
    Snapshot(Snapshot),
    Encrypted { collection: Id, kind: u8 },
}
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub entry_id: Id,
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub digest: Id,
    pub chunks: Vec<Id>,
}

pub(crate) fn encode_genesis(collection: &Id, root: &[u8; 32], sig: &[u8; 64]) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(160);
    let mut e = Encoder::new(&mut v);
    e.array(5)?
        .u8(1)?
        .bytes(collection)?
        .bytes(root)?
        .bytes(sig)?
        .u8(1)?;
    Ok(v)
}
pub(crate) fn encode_snapshot(s: &Snapshot, sig: &[u8; 64]) -> Result<Vec<u8>> {
    validate_ids(&s.parents, 64, "parents")?;
    validate_ids(&s.objects, MAX_CHUNKS, "objects")?;
    ensure!(
        s.objects.binary_search(&s.manifest).is_ok(),
        "manifest missing from object closure"
    );
    let mut v = Vec::new();
    let mut e = Encoder::new(&mut v);
    e.array(8)?
        .u8(2)?
        .bytes(&s.collection)?
        .bytes(&s.genesis)?
        .bytes(&s.writer)?;
    e.array(s.parents.len() as u64)?;
    for x in &s.parents {
        e.bytes(x)?;
    }
    e.bytes(&s.manifest)?;
    e.array(s.objects.len() as u64)?;
    for x in &s.objects {
        e.bytes(x)?;
    }
    e.bytes(sig)?;
    ensure!(v.len() <= MAX_OBJECT, "snapshot too large");
    Ok(v)
}
fn fixed(d: &mut Decoder<'_>) -> Result<Id> {
    d.bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("id length"))
}
fn fixed64(d: &mut Decoder<'_>) -> Result<[u8; 64]> {
    d.bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature length"))
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    ensure!(d.array()? == Some(n), "invalid record array");
    Ok(())
}
fn read_ids(d: &mut Decoder<'_>, max: usize, label: &str, sorted: bool) -> Result<Vec<Id>> {
    let n = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite {label}"))? as usize;
    ensure!(n <= max, "too many {label}");
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(fixed(d)?);
    }
    if sorted {
        validate_ids(&v, max, label)?;
    }
    Ok(v)
}
fn validate_ids(xs: &[Id], max: usize, label: &str) -> Result<()> {
    ensure!(xs.len() <= max, "too many {label}");
    ensure!(
        xs.windows(2).all(|w| w[0] < w[1]),
        "{label} must be sorted unique"
    );
    Ok(())
}
pub fn inspect(bytes: &[u8]) -> Result<Record> {
    ensure!(bytes.len() <= MAX_OBJECT, "record too large");
    let mut d = Decoder::new(bytes);
    let n = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite record"))?;
    let rec = match d.u8()? {
        1 => {
            ensure!(n == 5, "genesis array length");
            let collection = fixed(&mut d)?;
            let root: [u8; 32] = d
                .bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("root length"))?;
            let sig = fixed64(&mut d)?;
            ensure!(d.u8()? == 1, "unsupported genesis version");
            let mut msg = b"arc-exp-1/genesis-signature\0".to_vec();
            msg.extend_from_slice(&collection);
            msg.extend_from_slice(&root);
            crate::crypto::verify(&root, &msg, &sig)?;
            ensure!(
                encode_genesis(&collection, &root, &sig)? == bytes,
                "noncanonical genesis"
            );
            Record::Genesis(Genesis { collection, root })
        }
        2 => {
            ensure!(n == 8, "snapshot array length");
            let collection = fixed(&mut d)?;
            let genesis = fixed(&mut d)?;
            let writer: [u8; 32] = d
                .bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("writer length"))?;
            let parents = read_ids(&mut d, 64, "parents", true)?;
            let manifest = fixed(&mut d)?;
            let objects = read_ids(&mut d, MAX_CHUNKS, "objects", true)?;
            ensure!(
                objects.binary_search(&manifest).is_ok(),
                "manifest missing from closure"
            );
            let sig = fixed64(&mut d)?;
            let s = Snapshot {
                collection,
                genesis,
                writer,
                parents,
                manifest,
                objects,
            };
            let msg = crate::crypto::snapshot_signing_bytes(&s)?;
            crate::crypto::verify(&writer, &msg, &sig)?;
            ensure!(encode_snapshot(&s, &sig)? == bytes, "noncanonical snapshot");
            Record::Snapshot(s)
        }
        3 => {
            ensure!(n == 5, "encrypted object array length");
            let collection = fixed(&mut d)?;
            let kind = d.u8()?;
            ensure!(kind == 1 || kind == 2, "invalid encrypted kind");
            let nonce: [u8; 24] = d
                .bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("nonce length"))?;
            let ct = d.bytes()?;
            ensure!(ct.len() >= 16, "encrypted ciphertext too short");
            let mut canonical = Vec::new();
            let mut e = Encoder::new(&mut canonical);
            e.array(5)?
                .u8(3)?
                .bytes(&collection)?
                .u8(kind)?
                .bytes(&nonce)?
                .bytes(ct)?;
            ensure!(canonical == bytes, "noncanonical encrypted object");
            Record::Encrypted { collection, kind }
        }
        _ => bail!("unknown record type"),
    };
    ensure!(d.position() == bytes.len(), "trailing record bytes");
    Ok(rec)
}
fn empty_digest() -> Id {
    Sha256::digest([]).into()
}
fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 4096,
        "invalid path length"
    );
    ensure!(
        !path.starts_with('/') && !path.contains('\\') && !path.contains('\0'),
        "absolute, backslash or NUL path"
    );
    let mut count = 0;
    for c in path.split('/') {
        count += 1;
        ensure!(
            count <= 64 && !c.is_empty() && c.len() <= 255 && c != "." && c != "..",
            "invalid path component"
        );
    }
    Ok(())
}
pub fn encode_manifest(entries: &[Entry]) -> Result<Vec<u8>> {
    ensure!(entries.len() <= MAX_ENTRIES, "too many entries");
    let mut total = 0usize;
    for (i, x) in entries.iter().enumerate() {
        validate_path(&x.path)?;
        if i > 0 {
            ensure!(entries[i - 1].path < x.path, "paths must be sorted unique");
        }
        ensure!(
            entries[..i].iter().all(|y| y.entry_id != x.entry_id),
            "duplicate entry id"
        );
        ensure!(x.chunks.len() <= MAX_CHUNKS, "too many chunks");
        total += x.chunks.len();
        ensure!(total <= MAX_CHUNKS, "too many total chunks");
        if x.directory {
            ensure!(
                x.size == 0 && x.digest == empty_digest() && x.chunks.is_empty(),
                "invalid directory"
            );
        } else {
            ensure!(
                x.chunks.len() as u64 == x.size.div_ceil(CHUNK_SIZE as u64),
                "invalid file chunk count"
            );
        }
    }
    validate_parents(entries)?;
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.array(2)?.u8(1)?.array(entries.len() as u64)?;
    for x in entries {
        e.array(6)?
            .bytes(&x.entry_id)?
            .str(&x.path)?
            .bool(x.directory)?
            .u64(x.size)?
            .bytes(&x.digest)?
            .array(x.chunks.len() as u64)?;
        for c in &x.chunks {
            e.bytes(c)?;
        }
    }
    ensure!(out.len() <= MAX_MANIFEST, "manifest too large");
    Ok(out)
}
pub fn decode_manifest(bytes: &[u8]) -> Result<Vec<Entry>> {
    ensure!(bytes.len() <= MAX_MANIFEST, "manifest too large");
    let mut d = Decoder::new(bytes);
    array(&mut d, 2)?;
    ensure!(d.u8()? == 1, "unsupported manifest version");
    let n = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite entries"))? as usize;
    ensure!(n <= MAX_ENTRIES, "too many entries");
    let mut out = Vec::with_capacity(n);
    let mut total = 0;
    for _ in 0..n {
        array(&mut d, 6)?;
        let entry_id = fixed(&mut d)?;
        let path = d.str()?;
        ensure!(path.len() <= 4096, "invalid path length");
        let path = path.to_owned();
        let directory = d.bool()?;
        let size = d.u64()?;
        let digest = fixed(&mut d)?;
        let chunks = read_ids(&mut d, MAX_CHUNKS, "chunks", false)?;
        total += chunks.len();
        ensure!(total <= MAX_CHUNKS, "too many total chunks");
        out.push(Entry {
            entry_id,
            path,
            directory,
            size,
            digest,
            chunks,
        });
    }
    ensure!(d.position() == bytes.len(), "trailing manifest bytes");
    validate_manifest(&out)?;
    ensure!(encode_manifest(&out)? == bytes, "noncanonical manifest");
    Ok(out)
}
fn validate_manifest(es: &[Entry]) -> Result<()> {
    for (i, x) in es.iter().enumerate() {
        validate_path(&x.path)?;
        if i > 0 {
            ensure!(es[i - 1].path < x.path, "paths must be sorted unique");
        }
        ensure!(
            es[..i].iter().all(|y| y.entry_id != x.entry_id),
            "duplicate entry id"
        );
        if x.directory {
            ensure!(
                x.size == 0 && x.digest == empty_digest() && x.chunks.is_empty(),
                "invalid directory"
            );
        } else {
            ensure!(
                x.chunks.len() as u64 == x.size.div_ceil(CHUNK_SIZE as u64),
                "invalid file chunks"
            );
        }
    }
    validate_parents(es)
}
fn validate_parents(es: &[Entry]) -> Result<()> {
    for x in es {
        let mut p = x.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            ensure!(
                es.iter().any(|e| e.path == parent && e.directory),
                "missing parent directory"
            );
            p = parent;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn id_roundtrip() {
        let x = id(b"x");
        assert_eq!(parse_id(&display_id(&x)).unwrap(), x);
    }
    #[test]
    fn manifest_rejects_trailing_and_noncanonical() {
        let es = vec![];
        assert_eq!(encode_manifest(&es).unwrap(), [0x82, 0x01, 0x80]);
        // Same value with a nonminimal integer representation is not canonical.
        assert!(decode_manifest(&[0x82, 0x18, 0x01, 0x80]).is_err());
        let mut b = encode_manifest(&es).unwrap();
        b.push(0);
        assert!(decode_manifest(&b).is_err());
        assert!(decode_manifest(&[0x9f, 1, 0x80, 0xff]).is_err());
    }
    #[test]
    fn manifest_paths_and_parent_constraints() {
        let e = Entry {
            entry_id: [1; 32],
            path: "../x".into(),
            directory: false,
            size: 0,
            digest: Sha256::digest([]).into(),
            chunks: vec![],
        };
        assert!(encode_manifest(&[e]).is_err());
    }
    #[test]
    fn chunks_preserve_order_and_repetition() {
        let e = Entry {
            entry_id: [1; 32],
            path: "f".into(),
            directory: false,
            size: 3 * CHUNK_SIZE as u64,
            digest: [8; 32],
            chunks: vec![[9; 32], [2; 32], [9; 32]],
        };
        let b = encode_manifest(std::slice::from_ref(&e)).unwrap();
        assert_eq!(decode_manifest(&b).unwrap(), vec![e]);
    }
}
