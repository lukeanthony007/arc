use crate::{
    format::{self, Id, MAX_OBJECT},
    store::Store,
};
use anyhow::{Context, Result, bail};
use rustix::fs::OFlags;
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAGIC: &[u8; 8] = b"ARCEXP1\n";
const FOOTER: &[u8; 8] = b"ARCEND1\n";
const MAX_COUNT: u32 = 16_384;
const MAX_TOTAL: u64 = 1 << 30;

pub fn export(store: &Store, ids: &[Id], destination: &Path) -> Result<()> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() > MAX_COUNT as usize {
        bail!("too many bundle objects");
    }
    let mut total = 0u64;
    for id in &sorted {
        let b = store.get(id)?;
        total = total
            .checked_add(b.len() as u64)
            .context("bundle size overflow")?;
        if total > MAX_TOTAL {
            bail!("bundle exceeds total size limit");
        }
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (tmp, mut f) = create_temp(parent)?;
    let result = (|| -> Result<()> {
        f.write_all(MAGIC)?;
        f.write_all(&(sorted.len() as u32).to_be_bytes())?;
        for id in &sorted {
            let b = store.get(id)?;
            if format::id(&b) != *id {
                bail!("object changed during export");
            }
            f.write_all(id)?;
            f.write_all(&(b.len() as u32).to_be_bytes())?;
            f.write_all(&b)?;
        }
        f.write_all(FOOTER)?;
        f.sync_all()?;
        drop(f);
        fs::hard_link(&tmp, destination)
            .with_context(|| format!("publish bundle {}", destination.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result
}

pub fn import(store: &Store, source: &Path) -> Result<Vec<Id>> {
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(no_follow());
    let mut f = opts.open(source)?;
    if !f.metadata()?.is_file() {
        bail!("bundle source is not regular");
    }
    let mut magic = [0; 8];
    f.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("invalid bundle magic");
    }
    let mut n = [0; 4];
    f.read_exact(&mut n)?;
    let count = u32::from_be_bytes(n);
    if count > MAX_COUNT {
        bail!("bundle count exceeds limit");
    }
    let mut total = 0u64;
    let mut seen = HashSet::with_capacity(count as usize);
    let mut imported = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut id = [0; 32];
        f.read_exact(&mut id)?;
        f.read_exact(&mut n)?;
        let len = u32::from_be_bytes(n) as usize;
        if len > MAX_OBJECT {
            bail!("bundle object exceeds limit");
        }
        total = total
            .checked_add(len as u64)
            .context("bundle size overflow")?;
        if total > MAX_TOTAL {
            bail!("bundle exceeds total size limit");
        }
        let mut b = vec![0; len];
        f.read_exact(&mut b)?;
        if format::id(&b) != id {
            bail!("bundle object id mismatch");
        }
        if !seen.insert(id) {
            bail!("duplicate object id in bundle");
        }
        store.put(&b)?;
        imported.push(id);
    }
    let mut footer = [0; 8];
    f.read_exact(&mut footer)?;
    if &footer != FOOTER {
        bail!("invalid bundle footer");
    }
    let mut extra = [0; 1];
    if f.read(&mut extra)? != 0 {
        bail!("trailing bundle data");
    }
    Ok(imported)
}

fn no_follow() -> i32 {
    (OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32
}
fn create_temp(parent: &Path) -> Result<(std::path::PathBuf, File)> {
    for _ in 0..64 {
        let p = parent.join(format!(
            ".arc-export-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow())
            .open(&p)
        {
            Ok(f) => return Ok((p, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not allocate export temporary file")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_refuse_overwrite() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::create(&t.path().join("node")).unwrap();
        let id = s.put(b"payload").unwrap();
        let out = t.path().join("x.arc");
        export(&s, &[id, id], &out).unwrap();
        assert!(export(&s, &[id], &out).is_err());
        let s2 = Store::create(&t.path().join("other")).unwrap();
        assert_eq!(import(&s2, &out).unwrap(), vec![id]);
        assert_eq!(s2.get(&id).unwrap(), b"payload");
    }
    #[test]
    fn rejects_truncation_and_trailing_data() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::create(&t.path().join("node")).unwrap();
        for (n, b) in [
            ("truncated", b"ARCEXP1\n\0\0\0\0ARCEND".as_slice()),
            ("trailing", b"ARCEXP1\n\0\0\0\0ARCEND1\n!".as_slice()),
        ] {
            let p = t.path().join(n);
            fs::write(&p, b).unwrap();
            assert!(import(&s, &p).is_err());
        }
    }
    #[test]
    fn missing_export_object_does_not_publish() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::create(&t.path().join("node")).unwrap();
        let p = t.path().join("missing.arc");
        assert!(export(&s, &[[7; 32]], &p).is_err());
        assert!(!p.exists());
    }
}
