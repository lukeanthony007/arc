use crate::{crypto, format::Id, store::Store};
use anyhow::{Result, ensure};
use minicbor::{Decoder, Encoder};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const MAX_JOURNAL: usize = crate::format::MAX_OBJECT;
#[derive(Clone)]
pub(crate) struct ControlChange {
    pub name: String,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}
#[derive(Clone)]
pub(crate) struct Plan {
    pub genesis: Id,
    pub objects: Vec<Vec<u8>>,
    pub controls: Vec<ControlChange>,
    pub output: Option<(PathBuf, Vec<u8>)>,
}
impl Plan {
    fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.controls.len() <= 8 && self.objects.len() <= 256,
            "journal item limit exceeded"
        );
        let mut b = Vec::new();
        let mut e = Encoder::new(&mut b);
        e.array(5)?
            .u8(1)?
            .bytes(&self.genesis)?
            .array(self.objects.len() as u64)?;
        for object in &self.objects {
            e.bytes(object)?;
        }
        e.array(self.controls.len() as u64)?;
        for c in &self.controls {
            e.array(3)?.str(&c.name)?;
            write_opt(&mut e, c.before.as_deref())?;
            write_opt(&mut e, c.after.as_deref())?;
        }
        match &self.output {
            Some((path, bytes)) => {
                ensure!(
                    path.is_absolute(),
                    "journal package output path is not absolute"
                );
                e.array(2)?
                    .str(
                        path.to_str()
                            .ok_or_else(|| anyhow::anyhow!("output path is not UTF-8"))?,
                    )?
                    .bytes(bytes)?;
            }
            None => {
                e.null()?;
            }
        }
        ensure!(b.len() <= MAX_JOURNAL, "membership journal too large");
        Ok(b)
    }
    fn decode(bytes: &[u8], genesis: Id) -> Result<Self> {
        ensure!(bytes.len() <= MAX_JOURNAL, "membership journal too large");
        let mut d = Decoder::new(bytes);
        ensure!(
            d.array()? == Some(5) && d.u8()? == 1,
            "unsupported membership journal"
        );
        ensure!(d.bytes()? == genesis, "journal genesis mismatch");
        let n = d
            .array()?
            .ok_or_else(|| anyhow::anyhow!("indefinite object list"))? as usize;
        ensure!(n <= 256, "journal object limit exceeded");
        let mut objects = Vec::with_capacity(n);
        for _ in 0..n {
            objects.push(d.bytes()?.to_vec());
        }
        let n = d
            .array()?
            .ok_or_else(|| anyhow::anyhow!("indefinite controls"))? as usize;
        ensure!(n <= 8, "journal control limit exceeded");
        let mut controls = Vec::with_capacity(n);
        for _ in 0..n {
            ensure!(d.array()? == Some(3), "invalid control journal entry");
            let name = d.str()?.to_owned();
            ensure!(
                matches!(name.as_str(), "keys" | "keys-history" | "policy"),
                "invalid journal control"
            );
            controls.push(ControlChange {
                name,
                before: read_opt(&mut d)?,
                after: read_opt(&mut d)?,
            });
        }
        ensure!(
            controls
                .iter()
                .map(|c| c.name.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == controls.len(),
            "duplicate journal controls"
        );
        ensure!(controls.len() == 3, "incomplete journal controls");
        let output = if d.datatype()? == minicbor::data::Type::Null {
            d.null()?;
            None
        } else {
            ensure!(d.array()? == Some(2), "invalid package output");
            let path = PathBuf::from(d.str()?);
            ensure!(
                path.is_absolute(),
                "journal package output path is not absolute"
            );
            let data = d.bytes()?.to_vec();
            ensure!(
                data.len() <= crate::devices::MAX_PACKAGE,
                "package output too large"
            );
            Some((path, data))
        };
        ensure!(d.position() == bytes.len(), "trailing journal data");
        Ok(Self {
            genesis,
            objects,
            controls,
            output,
        })
    }
}
fn write_opt(e: &mut Encoder<&mut Vec<u8>>, value: Option<&[u8]>) -> Result<()> {
    if let Some(v) = value {
        e.array(2)?.u8(1)?.bytes(v)?;
    } else {
        e.array(1)?.u8(0)?;
    }
    Ok(())
}
fn read_opt(d: &mut Decoder<'_>) -> Result<Option<Vec<u8>>> {
    match d.array()? {
        Some(1) => {
            ensure!(d.u8()? == 0, "invalid optional control");
            Ok(None)
        }
        Some(2) => {
            ensure!(d.u8()? == 1, "invalid optional control");
            Ok(Some(d.bytes()?.to_vec()))
        }
        _ => anyhow::bail!("invalid optional control"),
    }
}
pub(crate) fn read_optional_control(store: &Store, name: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(store.path().join("control").join(name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(Some(store.read_control(name)?)),
    }
}
pub(crate) fn begin(store: &Store, password: &str, plan: &Plan) -> Result<()> {
    validate_plan(store, plan, password)?;
    let plain = plan.encode()?;
    let sealed = crypto::seal_journal(password, &plan.genesis, &plain)?;
    store.write_new_control("membership-pending", &sealed)
}
fn validate_plan(store: &Store, plan: &Plan, password: &str) -> Result<()> {
    let (pinned_id, genesis) = crate::app::pinned(store)?;
    ensure!(pinned_id == plan.genesis, "journal pinned genesis mismatch");
    let control_names: std::collections::BTreeSet<_> =
        plan.controls.iter().map(|c| c.name.as_str()).collect();
    let expected_controls: std::collections::BTreeSet<&str> =
        ["keys", "keys-history", "policy"].into_iter().collect();
    ensure!(
        control_names == expected_controls,
        "incomplete or duplicate journal controls"
    );
    ensure!(
        plan.controls.iter().all(|c| c.after.is_some()),
        "journal control has no target state"
    );
    for pair in plan.objects.windows(2) {
        let parent = crate::policy::Policy::decode(&pair[0])?;
        let child = crate::policy::Policy::decode(&pair[1])?;
        ensure!(
            child.previous == Some(parent.id()?)
                && parent.epoch.checked_add(1) == Some(child.epoch),
            "journal policy objects are not a contiguous chain"
        );
    }
    let mut objects = std::collections::HashMap::new();
    for raw in &plan.objects {
        let policy = crate::policy::Policy::decode(raw)?;
        policy.verify(&genesis.root)?;
        ensure!(
            policy.collection == genesis.collection,
            "journal policy collection mismatch"
        );
        ensure!(
            crate::format::id(raw) == policy.id()?,
            "journal policy identity mismatch"
        );
        ensure!(
            objects.insert(policy.id()?, policy).is_none(),
            "duplicate journal policy object"
        );
    }
    let after_policy: Id = plan
        .controls
        .iter()
        .find(|c| c.name == "policy")
        .and_then(|c| c.after.as_ref())
        .ok_or_else(|| anyhow::anyhow!("journal lacks target policy"))?
        .as_slice()
        .try_into()?;
    ensure!(
        objects.contains_key(&after_policy),
        "journal target policy absent from signed objects"
    );
    let after_keys = plan
        .controls
        .iter()
        .find(|c| c.name == "keys")
        .and_then(|c| c.after.as_ref())
        .ok_or_else(|| anyhow::anyhow!("journal lacks target keys"))?;
    let keys = crate::crypto::Secrets::unlock(&genesis.collection, after_keys, password)?;
    let target = &objects[&after_policy];
    ensure!(
        target
            .members
            .iter()
            .any(|m| m.key == keys.root() && !m.revoked),
        "journal target key is not an active member"
    );
    ensure!(
        target.allows_writer(&genesis.root),
        "journal target policy disables genesis authority"
    );
    let after_history = plan
        .controls
        .iter()
        .find(|c| c.name == "keys-history")
        .and_then(|c| c.after.as_ref())
        .ok_or_else(|| anyhow::anyhow!("journal lacks target key history"))?;
    if let Some(before_policy) = plan
        .controls
        .iter()
        .find(|c| c.name == "policy")
        .and_then(|c| c.before.as_ref())
    {
        let before_id: Id = before_policy.as_slice().try_into()?;
        let before_raw = store.get(&before_id)?;
        ensure!(
            crate::format::id(&before_raw) == before_id,
            "previous policy object mismatch"
        );
        let before = crate::policy::Policy::decode(&before_raw)?;
        ensure!(
            before.collection == genesis.collection,
            "previous policy collection mismatch"
        );
        let before_keys = plan
            .controls
            .iter()
            .find(|c| c.name == "keys")
            .and_then(|c| c.before.as_ref())
            .ok_or_else(|| anyhow::anyhow!("journal lacks previous keys"))?;
        let old_keys = crate::crypto::Secrets::unlock(&genesis.collection, before_keys, password)?;
        ensure!(
            old_keys.root() == keys.root(),
            "journal changes local signing identity"
        );
        ensure!(
            before
                .members
                .iter()
                .any(|m| m.key == old_keys.root() && !m.revoked),
            "previous key is not active in trusted policy"
        );
        history_contains(after_history, before_id, before_keys)?;
    } else {
        history_contains(after_history, after_policy, after_keys)?;
    }

    if let Some(before) = plan
        .controls
        .iter()
        .find(|c| c.name == "policy")
        .and_then(|c| c.before.as_ref())
    {
        let before_id: Id = before.as_slice().try_into()?;
        let mut cursor = target.clone();
        let mut found = false;
        for _ in 0..=256 {
            let id = cursor.id()?;
            if id == before_id {
                found = true;
                break;
            }
            let Some(previous) = cursor.previous else {
                break;
            };
            let child_epoch = cursor.epoch;
            let raw = if let Some(p) = objects.get(&previous) {
                p.encode()?
            } else {
                store.get(&previous)?
            };
            ensure!(
                crate::format::id(&raw) == previous,
                "journal ancestry object mismatch"
            );
            cursor = crate::policy::Policy::decode(&raw)?;
            cursor.verify(&genesis.root)?;
            ensure!(
                cursor.collection == genesis.collection
                    && cursor.epoch.checked_add(1) == Some(child_epoch),
                "journal ancestry is not contiguous"
            );
        }
        let old_policy = crate::policy::Policy::decode(&store.get(&before_id)?)?;
        ensure!(
            found && target.epoch > old_policy.epoch,
            "journal target policy does not advance trusted policy"
        );
    } else {
        ensure!(
            target.epoch == 0 && target.previous.is_none(),
            "initial policy journal is not genesis policy"
        );
        ensure!(
            target.allows_writer(&genesis.root),
            "initial policy omits root writer"
        );
    }
    let mut cursor = target.clone();
    let mut path_ids = std::collections::BTreeSet::new();
    for _ in 0..=256 {
        let id = cursor.id()?;
        ensure!(path_ids.insert(id), "journal policy cycle");
        let Some(previous) = cursor.previous else {
            break;
        };
        let child_epoch = cursor.epoch;
        let raw = if let Some(policy) = objects.get(&previous) {
            policy.encode()?
        } else {
            store.get(&previous)?
        };
        ensure!(
            crate::format::id(&raw) == previous,
            "journal ancestry object mismatch"
        );
        cursor = crate::policy::Policy::decode(&raw)?;
        cursor.verify(&genesis.root)?;
        ensure!(
            cursor.collection == genesis.collection
                && cursor.epoch.checked_add(1) == Some(child_epoch),
            "journal ancestry is not contiguous"
        );
    }
    for raw in &plan.objects {
        ensure!(
            path_ids.contains(&crate::policy::Policy::decode(raw)?.id()?),
            "journal contains signed-policy fork evidence"
        );
    }
    Ok(())
}
fn history_contains(raw: &[u8], expected_id: Id, expected_key: &[u8]) -> Result<()> {
    let mut d = Decoder::new(raw);
    ensure!(
        d.array()? == Some(2) && d.u8()? == 1,
        "invalid journal key history"
    );
    let n = d
        .array()?
        .ok_or_else(|| anyhow::anyhow!("indefinite key history"))? as usize;
    ensure!(n <= 4096, "journal key history limit exceeded");
    let mut seen = std::collections::BTreeSet::new();
    let mut matched = false;
    for _ in 0..n {
        ensure!(d.array()? == Some(2), "invalid journal key history entry");
        let id: Id = d.bytes()?.try_into()?;
        let key = d.bytes()?;
        ensure!(seen.insert(id), "duplicate journal key history ID");
        if id == expected_id {
            ensure!(key == expected_key, "journal key history conflict");
            matched = true;
        }
    }
    ensure!(
        d.position() == raw.len() && matched,
        "journal key history is incomplete"
    );
    Ok(())
}
pub(crate) fn commit(
    store: &Store,
    password: &str,
    plan: &Plan,
    fail_after: Option<usize>,
) -> Result<()> {
    begin(store, password, plan)?;
    if fail_after == Some(1) {
        anyhow::bail!("injected membership fault after journal");
    }
    apply(store, plan, fail_after)
}
pub(crate) fn repair(
    store: &Store,
    password: &str,
    genesis: Id,
    fail_after: Option<usize>,
) -> Result<()> {
    let sealed = store.read_control("membership-pending")?;
    let plain = crypto::open_journal(password, &genesis, &sealed)?;
    let plan = Plan::decode(&plain, genesis)?;
    validate_plan(store, &plan, password)?;
    apply(store, &plan, fail_after)
}
pub(crate) fn apply(store: &Store, plan: &Plan, fail_after: Option<usize>) -> Result<()> {
    for control in &plan.controls {
        let current = read_optional_control(store, &control.name)?;
        ensure!(
            current == control.before || current == control.after,
            "membership journal control conflict: {}",
            control.name
        );
    }
    let mut step = 1usize;
    for object in &plan.objects {
        let id = store.put(object)?;
        ensure!(
            crate::format::id(object) == id,
            "journal object ID mismatch"
        );
        step += 1;
        if fail_after == Some(step) {
            anyhow::bail!("injected membership fault");
        }
    }
    for control in &plan.controls {
        let current = read_optional_control(store, &control.name)?;
        if current != control.after
            && let Some(after) = &control.after
        {
            store.set_control(&control.name, after)?;
        }
        step += 1;
        if fail_after == Some(step) {
            anyhow::bail!("injected membership fault");
        }
    }
    if let Some((path, bytes)) = &plan.output {
        write_output_idempotent(path, bytes)?;
        step += 1;
        if fail_after == Some(step) {
            anyhow::bail!("injected membership fault");
        }
    }
    store.clear_membership_pending()?;
    step += 1;
    if fail_after == Some(step) {
        anyhow::bail!("injected membership fault after journal removal");
    }
    Ok(())
}
fn write_output_idempotent(path: &Path, bytes: &[u8]) -> Result<()> {
    match read_bounded(path, crate::devices::MAX_PACKAGE) {
        Ok(existing) => {
            ensure!(
                existing == bytes,
                "existing package output conflicts with journal"
            );
            sync_output(path)?;
            return Ok(());
        }
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => {}
        Err(e) => return Err(e),
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("package output has no parent"))?;
    let mut tmp = None;
    for _ in 0..64 {
        let candidate = parent.join(format!(
            ".arc-membership-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&candidate)
        {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
                tmp = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let tmp = tmp.ok_or_else(|| anyhow::anyhow!("could not allocate package temp file"))?;
    let result = std::fs::hard_link(&tmp, path).map_err(anyhow::Error::from);
    let _ = std::fs::remove_file(&tmp);
    result?;
    sync_output(path)?;
    Ok(())
}
fn sync_output(path: &Path) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        f.metadata()?.is_file(),
        "package output is not a regular file"
    );
    f.sync_all()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("package output has no parent"))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        f.metadata()?.is_file(),
        "package output is not a regular file"
    );
    let mut bytes = Vec::new();
    f.take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "package output exceeds limit");
    Ok(bytes)
}
