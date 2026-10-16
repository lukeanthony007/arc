use arc_store::{app, format, store::Store};
use std::{
    fs::{self, File},
    io::{Read, Write},
};
use tempfile::tempdir;

#[test]
fn recovery_stream_exceeds_old_limit_and_restores_exact_bytes() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let mut file = File::create(source.join("large.bin")).unwrap();
    // 65 MiB: actual encrypted snapshot closure, not an inflated backup header.
    for index in 0..1040u64 {
        let mut block = vec![0; 65536];
        for (offset, byte) in block.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(71) + offset as u64) as u8;
        }
        file.write_all(&block).unwrap();
    }
    drop(file);
    let genesis = app::init(&node, "streaming-recovery-password").unwrap();
    let snapshot = app::capture(&node, &source, "streaming-recovery-password").unwrap();
    let kit = temp.path().join("backup.arc");
    app::export_recovery(&node, &kit, "streaming-recovery-password").unwrap();
    assert!(fs::metadata(&kit).unwrap().len() > 64 * 1024 * 1024);
    let mut header = [0; 8];
    File::open(&kit).unwrap().read_exact(&mut header).unwrap();
    assert_eq!(&header, b"ARCRCV3\n");
    let recovered = temp.path().join("recovered");
    app::recover(&recovered, &kit, &genesis, "streaming-recovery-password").unwrap();
    assert!(Store::open(&recovered).unwrap().head().unwrap().is_none());
    let restored = temp.path().join("restored");
    app::restore(
        &recovered,
        &snapshot,
        &restored,
        "streaming-recovery-password",
    )
    .unwrap();
    let mut expected = File::open(source.join("large.bin")).unwrap();
    let mut actual = File::open(restored.join("large.bin")).unwrap();
    loop {
        let mut a = [0; 65536];
        let mut b = [0; 65536];
        let na = expected.read(&mut a).unwrap();
        let nb = actual.read(&mut b).unwrap();
        assert_eq!(na, nb);
        assert_eq!(&a[..na], &b[..nb]);
        if na == 0 {
            break;
        }
    }
}

#[test]
fn authenticated_completion_rejects_stream_damage_without_publishing() {
    let temp = tempdir().unwrap();
    let node = temp.path().join("node");
    let genesis = app::init(&node, "framing-password").unwrap();
    Store::open(&node)
        .unwrap()
        .put(b"opaque foreign inventory evidence")
        .unwrap();
    let kit = temp.path().join("good.arc");
    app::export_recovery(&node, &kit, "framing-password").unwrap();
    let raw = fs::read(&kit).unwrap();
    let mut frames = Vec::new();
    let mut position = 40;
    while position < raw.len() {
        let size = u32::from_be_bytes(raw[position + 1..position + 5].try_into().unwrap()) as usize;
        frames.push((position, position + 5 + size));
        position += 5 + size;
    }
    assert_eq!(raw[frames.last().unwrap().0], 255);
    let mut variants = Vec::new();
    variants.push(raw[..frames.last().unwrap().0].to_vec()); // no completion
    variants.push(raw[..raw.len() - 1].to_vec()); // truncated tag
    let mut trailing = raw.clone();
    trailing.push(0);
    variants.push(trailing);
    let mut reorder = raw[..40].to_vec();
    reorder.extend_from_slice(&raw[frames[1].0..frames[1].1]);
    reorder.extend_from_slice(&raw[frames[0].0..frames[0].1]);
    reorder.extend_from_slice(&raw[frames[2].0..]);
    variants.push(reorder);
    let mut duplicate = raw.clone();
    duplicate.splice(
        frames[1].0..frames[1].0,
        raw[frames[0].0..frames[0].1].iter().copied(),
    );
    variants.push(duplicate);
    let mut changed = raw.clone();
    changed[frames[0].0 + 6] ^= 1;
    variants.push(changed);
    let mut changed = raw.clone();
    changed[25] ^= 1;
    variants.push(changed);
    let mut oversized = raw.clone();
    oversized[41..45].copy_from_slice(&u32::MAX.to_be_bytes());
    variants.push(oversized);
    for (index, bytes) in variants.iter().enumerate() {
        let bad = temp.path().join(format!("bad-{index}.arc"));
        fs::write(&bad, bytes).unwrap();
        let destination = temp.path().join(format!("recovered-{index}"));
        assert!(
            app::recover(&destination, &bad, &genesis, "framing-password").is_err(),
            "variant {index}"
        );
        assert!(!destination.exists());
        assert!(!fs::read_dir(temp.path()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".arc-recover-")
        }));
    }
    // The unmodified stream preserves the opaque object without assigning trust.
    let recovered = temp.path().join("good-recovered");
    app::recover(&recovered, &kit, &genesis, "framing-password").unwrap();
    let id = format::id(b"opaque foreign inventory evidence");
    assert_eq!(
        Store::open(&recovered).unwrap().get(&id).unwrap(),
        b"opaque foreign inventory evidence"
    );
}
