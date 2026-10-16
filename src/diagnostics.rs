use crate::{
    format::{self, Id},
    store::Store,
};
use anyhow::{Context, Result};
use std::{fmt, fs, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub identity: Option<Id>,
    pub selected: Option<Id>,
    pub competing_heads: Vec<Id>,
    pub policy_epoch: Option<u64>,
    pub policy_freshness: &'static str,
    pub history_inventory_known: bool,
    pub membership_pending: bool,
    pub partial_objects: usize,
    pub summary: String,
    pub next_action: String,
}
impl fmt::Display for StatusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\nidentity: {}\nselected: {}\ncompeting heads: {}\npolicy epoch: {} (freshness {})\nhistory inventory known: {}\nmembership pending: {}\npartial objects: {}\nnext action: {}",
            self.summary,
            show(&self.identity),
            show(&self.selected),
            self.competing_heads.len(),
            self.policy_epoch
                .map_or("unknown".into(), |x| x.to_string()),
            self.policy_freshness,
            self.history_inventory_known,
            self.membership_pending,
            self.partial_objects,
            self.next_action
        )
    }
}
fn show(id: &Option<Id>) -> String {
    id.map_or("none".into(), |x| format::display_id(&x))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub next_action: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub findings: Vec<Finding>,
}
impl DoctorReport {
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|x| x.severity == Severity::Error)
    }
}
impl fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.findings {
            writeln!(
                f,
                "{:?} {}: {} — {}",
                x.severity, x.code, x.message, x.next_action
            )?;
        }
        Ok(())
    }
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let m = f.metadata()?;
    anyhow::ensure!(
        m.is_file() && m.len() <= max as u64,
        "not a bounded regular file"
    );
    let mut b = Vec::with_capacity(m.len() as usize);
    f.take(max as u64 + 1).read_to_end(&mut b)?;
    anyhow::ensure!(b.len() <= max, "file exceeds bound");
    Ok(b)
}
fn is_missing(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound)
}

pub fn status(node: &Path) -> Result<StatusReport> {
    let store = Store::open(node)?;
    let identity = match read(&node.join("control/genesis"), 32) {
        Ok(b) if b.len() == 32 => Some(b.try_into().unwrap()),
        Ok(_) => None,
        Err(e) if is_missing(&e) => None,
        Err(e) => return Err(e).context("read pinned identity"),
    };
    let selected = match read(&node.join("control/head"), 32) {
        Ok(b) if b.len() == 32 => Some(b.try_into().unwrap()),
        Ok(_) => None,
        Err(e) if is_missing(&e) => None,
        Err(e) => return Err(e).context("read selected head"),
    };
    let membership_pending = match fs::symlink_metadata(node.join("control/membership-pending")) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let fragments = node.join("incoming/fragments");
    let mut partial_objects = 0;
    match fs::symlink_metadata(&fragments) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
            for (scanned, item) in fs::read_dir(&fragments)?.enumerate() {
                anyhow::ensure!(
                    scanned < crate::fragments::MAX_PARTIALS + 2,
                    "fragment inventory exceeds bounded inspection; progress unknown"
                );
                let e = item?;
                if e.file_name() == "lock" || e.file_name() == "write.tmp" {
                    continue;
                }
                let name = e.file_name();
                let meta = fs::symlink_metadata(e.path())?;
                if name.to_string_lossy().len() == 64
                    && meta.is_file()
                    && !meta.file_type().is_symlink()
                    && meta.len() <= crate::fragments::MAX_STATE as u64
                {
                    partial_objects += 1;
                }
            }
        }
        Ok(_) => anyhow::bail!("unsafe incoming fragments directory"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let trust = crate::app::pinned(&store)
        .and_then(|(_, genesis)| crate::app::load_policy(&store, &genesis));
    let trust_error = trust.as_ref().err().map(|error| error.to_string());
    let policy_epoch = trust.ok().flatten().map(|policy| policy.epoch);
    let inventory = if identity.is_some() {
        crate::history::list(node)
    } else {
        Ok(Vec::new())
    };
    let history_inventory_known = identity.is_some() && inventory.is_ok();
    let snapshots = inventory.unwrap_or_default();
    let competing_heads = snapshots
        .iter()
        .filter(|s| s.is_head && Some(s.id) != selected)
        .map(|s| s.id)
        .collect();
    let summary = if trust_error.is_some() {
        "local trust state invalid or unavailable; run arc doctor"
    } else if membership_pending {
        "membership transition pending"
    } else if identity.is_none() {
        "pinned identity unavailable"
    } else if selected.is_none() {
        "no selected snapshot"
    } else {
        "local state inspected; global freshness unknown"
    }
    .to_string();
    let next_action=if membership_pending {"inspect the transition with the explicit membership repair workflow; preserve unknown markers and forks"} else if selected.is_none(){"inspect/import available history; selection requires an explicit user decision"} else {"compare with a trusted peer when available; offline state cannot establish global freshness"}.to_string();
    Ok(StatusReport {
        identity,
        selected,
        competing_heads,
        policy_epoch,
        policy_freshness: "unknown (no global authority queried)",
        history_inventory_known,
        membership_pending,
        partial_objects,
        summary,
        next_action,
    })
}

pub fn doctor(node: &Path) -> Result<DoctorReport> {
    let status = status(node)?;
    let store = Store::open(node)?;
    let mut findings = Vec::new();
    if let Err(error) = crate::app::pinned(&store)
        .and_then(|(_, genesis)| crate::app::load_policy(&store, &genesis))
    {
        findings.push(Finding {
            severity: Severity::Error,
            code: "invalid-trust-state",
            message: format!("pinned identity or policy cannot be validated: {error}"),
            next_action: "preserve this node; recover exact trusted controls and objects from a verified backup or authority".into(),
        });
    }
    if status.identity.is_none() {
        findings.push(Finding {
            severity: Severity::Error,
            code: "identity-missing",
            message: "pinned genesis identity is absent or malformed".into(),
            next_action: "preserve node and restore its trusted genesis pin from a verified backup"
                .into(),
        });
    }
    if status.selected.is_none() {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "head-missing",
            message: "no selected snapshot head is available".into(),
            next_action: "inspect stored history and choose a snapshot explicitly".into(),
        });
    }
    if status.membership_pending {
        findings.push(Finding{severity:Severity::Warning,code:"membership-pending",message:"membership transition marker exists; contents intentionally not decrypted".into(),next_action:"use explicit membership repair after reviewing transition context; do not delete marker".into()});
    }
    if status.partial_objects > 0 {
        findings.push(Finding {
            severity: Severity::Info,
            code: "partial-progress",
            message: format!(
                "{} incoming partial object(s) retained",
                status.partial_objects
            ),
            next_action:
                "resume transfer if expected; otherwise review before any explicit discard".into(),
        });
    }
    if let Some(id) = status.selected {
        match crate::app::verify(node, &id, None) {
            Ok(_) => {}
            Err(e) => findings.push(Finding {
                severity: Severity::Error,
                code: "selected-coverage-incomplete",
                message: format!(
                    "selected snapshot or referenced encrypted closure is invalid: {e}"
                ),
                next_action: "fetch exact immutable snapshot objects from a trusted peer or backup"
                    .into(),
            }),
        }
    }
    if status.policy_freshness.starts_with("unknown") {
        findings.push(Finding {
            severity: Severity::Info,
            code: "policy-freshness-unknown",
            message: "local observation cannot establish current global policy".into(),
            next_action: "compare policy with a trusted authority or peer when connected".into(),
        });
    }
    if !status.history_inventory_known {
        findings.push(Finding{severity:Severity::Warning,code:"history-inventory-unknown",message:"authorized history inventory could not be completed".into(),next_action:"inspect local store permissions, pinned identity and policy controls; do not infer absence of competing heads".into()});
    }
    if status.history_inventory_known {
        for snapshot in crate::history::list(node)? {
            if crate::app::verify(node, &snapshot.id, None).is_err() {
                findings.push(Finding{severity:Severity::Error,code:"snapshot-coverage-incomplete",message:format!("authorized snapshot {} has missing or corrupt referenced encrypted data; plaintext integrity is unchecked without unlock",format::display_id(&snapshot.id)),next_action:"fetch exact immutable objects from a trusted peer or backup".into()});
            }
        }
        for head in status.competing_heads.iter() {
            findings.push(Finding{severity:Severity::Warning,code:"competing-authorized-head",message:format!("another locally authorized history head exists: {}",format::display_id(head)),next_action:"compare histories and choose an explicit merge or selection; diagnostics will not discard either head".into()});
        }
    }
    let mut scanned = 0usize;
    let mut scanned_bytes = 0u64;
    for entry in fs::read_dir(node.join("objects"))? {
        let entry = entry?;
        scanned += 1;
        if scanned > 16_384 {
            findings.push(Finding {
                severity: Severity::Error,
                code: "object-inventory-limit",
                message: "CAS inventory exceeded the bounded scan limit".into(),
                next_action:
                    "inspect a copy with a specialist; inventory was intentionally stopped".into(),
            });
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 64 {
            continue;
        }
        let Ok(id) = format::parse_id(name) else {
            findings.push(Finding {
                severity: Severity::Warning,
                code: "opaque-object-name",
                message: "CAS contains an object with an unsupported filename".into(),
                next_action: "retain it; do not delete unrecognized data".into(),
            });
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        scanned_bytes = scanned_bytes.saturating_add(metadata.len());
        if scanned_bytes > 1 << 30 {
            findings.push(Finding {
                severity: Severity::Error,
                code: "object-inventory-byte-limit",
                message: "CAS inventory exceeded the bounded byte limit".into(),
                next_action:
                    "inventory was intentionally stopped; inspect a copy with a specialist".into(),
            });
            break;
        }
        if store.get(&id).is_err() {
            findings.push(Finding{severity:Severity::Error,code:"corrupt-cas-object",message:format!("CAS object {} is absent, nonregular, oversized or digest-mismatched",name),next_action:"restore the exact immutable object from a trusted peer or backup; do not overwrite evidence".into()});
        }
    }
    Ok(DoctorReport { findings })
}
