use crate::format::{self, Id, MAX_OBJECT};
use anyhow::{Context, Result, bail};
use rustix::fs::OFlags;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const DIRS: [&str; 3] = ["objects", "control", "incoming"];

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn create(path: &Path) -> Result<Self> {
        ensure_no_symlink_components(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create store {}", path.display()))?;
        for name in DIRS {
            let p = path.join(name);
            fs::DirBuilder::new().mode(0o700).create(&p)?;
            sync_dir(path)?;
        }
        sync_dir(parent)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        ensure_no_symlink_components(path)?;
        check_dir(path)?;
        for name in DIRS {
            check_dir(&path.join(name))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn put(&self, bytes: &[u8]) -> Result<Id> {
        if bytes.len() > MAX_OBJECT {
            bail!("object exceeds maximum size");
        }
        let id = format::id(bytes);
        let dir = self.path.join("objects");
        check_dir(&dir)?;
        let dest = object_path(&dir, &id);
        let tmp = temporary(&dir, bytes)?;
        let result = (|| -> Result<()> {
            match fs::hard_link(&tmp, &dest) {
                Ok(()) => sync_dir(&dir)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = read_bounded(&dest, MAX_OBJECT)?;
                    if format::id(&existing) != id {
                        bail!("existing object digest mismatch");
                    }
                    OpenOptions::new()
                        .write(true)
                        .custom_flags(no_follow())
                        .open(&dest)?
                        .sync_all()?;
                    sync_dir(&dir)?;
                }
                Err(e) => return Err(e).context("publish object"),
            }
            Ok(())
        })();
        let _ = fs::remove_file(tmp);
        result?;
        Ok(id)
    }
    pub fn get(&self, id: &Id) -> Result<Vec<u8>> {
        let p = object_path(&self.path.join("objects"), id);
        let b = read_bounded(&p, MAX_OBJECT)?;
        if format::id(&b) != *id {
            bail!("object digest mismatch");
        }
        Ok(b)
    }
    pub fn contains(&self, id: &Id) -> Result<bool> {
        let p = object_path(&self.path.join("objects"), id);
        match read_bounded(&p, MAX_OBJECT) {
            Ok(b) => {
                if format::id(&b) != *id {
                    bail!("object digest mismatch")
                }
                Ok(true)
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    pub fn write_new_control(&self, name: &str, bytes: &[u8]) -> Result<()> {
        check_control_name(name)?;
        if bytes.len() > MAX_OBJECT {
            bail!("control exceeds maximum size");
        }
        let dir = self.path.join("control");
        check_dir(&dir)?;
        let dest = dir.join(name);
        let tmp = temporary(&dir, bytes)?;
        let result = (|| -> Result<()> {
            fs::hard_link(&tmp, &dest)?;
            sync_dir(&dir)
        })();
        let _ = fs::remove_file(tmp);
        result
    }
    pub fn read_control(&self, name: &str) -> Result<Vec<u8>> {
        check_control_name(name)?;
        read_bounded(&self.path.join("control").join(name), MAX_OBJECT)
    }
    pub fn set_head(&self, id: &Id) -> Result<()> {
        let dir = self.path.join("control");
        check_dir(&dir)?;
        let temp = temporary(&dir, id)?;
        let dest = dir.join("head");
        // Pilot serializes head updates; rename is atomic to readers.
        let result = fs::rename(&temp, &dest)
            .map_err(anyhow::Error::from)
            .and_then(|()| sync_dir(&dir));
        let _ = fs::remove_file(temp);
        result
    }
    pub fn head(&self) -> Result<Option<Id>> {
        match read_bounded(&self.path.join("control/head"), 32) {
            Ok(b) => {
                let id: Id = b
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid head length"))?;
                Ok(Some(id))
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

fn object_path(dir: &Path, id: &Id) -> PathBuf {
    dir.join(hex::encode(id))
}
fn check_control_name(n: &str) -> Result<()> {
    if !matches!(n, "genesis" | "keys" | "head") {
        bail!("invalid control name");
    }
    Ok(())
}
fn no_follow() -> i32 {
    (OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32
}
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut o = OpenOptions::new();
    o.read(true).custom_flags(no_follow());
    let f = o.open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max as u64 {
        bail!("not a bounded regular file: {}", path.display());
    }
    let mut b = Vec::with_capacity(m.len() as usize);
    f.take(max as u64 + 1).read_to_end(&mut b)?;
    if b.len() > max {
        bail!("file exceeds bound");
    }
    Ok(b)
}
fn temporary(dir: &Path, bytes: &[u8]) -> Result<PathBuf> {
    for _ in 0..64 {
        let name = format!(".tmp-{}", hex::encode(rand::random::<[u8; 16]>()));
        let p = dir.join(name);
        match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow())
            .open(&p)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
                    let _ = fs::remove_file(&p);
                    return Err(e.into());
                }
                return Ok(p);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not allocate temporary file")
}
fn ensure_no_symlink_components(path: &Path) -> Result<()> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut cur = PathBuf::new();
    for c in abs.components() {
        cur.push(c);
        if cur.exists() {
            let m = fs::symlink_metadata(&cur)?;
            if m.file_type().is_symlink() || !m.is_dir() {
                bail!("unsafe store path component: {}", cur.display());
            }
        }
    }
    Ok(())
}
fn check_dir(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.mode() & 0o077 != 0 {
        bail!(
            "store directory must be private and non-symlink: {}",
            p.display()
        );
    }
    Ok(())
}
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_objects_and_controls() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Store::create(&tmp.path().join("node")).unwrap();
        let id = s.put(b"opaque").unwrap();
        assert_eq!(s.get(&id).unwrap(), b"opaque");
        assert_eq!(s.put(b"opaque").unwrap(), id);
        assert!(s.contains(&id).unwrap());
        assert!(s.write_new_control("genesis", &[0; 32]).is_ok());
        assert!(s.write_new_control("genesis", &[1; 32]).is_err());
        s.set_head(&id).unwrap();
        assert_eq!(s.head().unwrap(), Some(id));
    }
    #[test]
    fn rejects_symlink_object_and_directory() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let s = Store::create(&tmp.path().join("node")).unwrap();
        let id = format::id(b"actual");
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"actual").unwrap();
        symlink(&victim, object_path(&s.path.join("objects"), &id)).unwrap();
        assert!(s.get(&id).is_err());
        let link = tmp.path().join("linked");
        symlink(s.path(), &link).unwrap();
        assert!(Store::open(&link).is_err());
    }
    #[test]
    fn corrupted_existing_objects_are_not_replaced_or_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::create(&tmp.path().join("node")).unwrap();
        let id = store.put(b"original").unwrap();
        let path = object_path(&store.path.join("objects"), &id);
        fs::write(&path, b"corrupt").unwrap();
        assert!(store.get(&id).is_err());
        assert!(store.put(b"original").is_err());
        assert_eq!(fs::read(path).unwrap(), b"corrupt");
        assert_eq!(fs::read_dir(store.path.join("objects")).unwrap().count(), 1);
    }

    #[test]
    fn fifo_reads_fail_and_failed_head_publication_cleans_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::create(&tmp.path().join("node")).unwrap();
        let id = format::id(b"unavailable");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            object_path(&store.path.join("objects"), &id),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(store.get(&id).is_err());
        fs::create_dir(store.path.join("control/head")).unwrap();
        assert!(store.set_head(&id).is_err());
        assert_eq!(fs::read_dir(store.path.join("control")).unwrap().count(), 1);
    }
}
