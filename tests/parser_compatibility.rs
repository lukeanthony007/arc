//! Frozen vectors independently encoded with Python cryptography Ed25519 and explicit
//! canonical CBOR, seed [7;32], collection [1;32], content key [8;32]. Public test keys only.
use arc_store::{
    crypto::Secrets,
    enrollment::Request,
    format::{self, Record, Snapshot},
    policy::{Member, Policy, Role},
};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn empty_manifest_has_frozen_canonical_bytes_and_hash() {
    let expected = [0x82, 0x01, 0x80];
    assert_eq!(format::decode_manifest(&expected).unwrap(), Vec::new());
    assert_eq!(format::encode_manifest(&[]).unwrap(), expected);
    assert_eq!(
        hex::encode(format::id(&expected)),
        "5f0d326aac2728e5b2e42c61eb1ffedfe3a699f5fd88d3de4e8dddcbb5a2d2ce"
    );
}

#[test]
fn signed_genesis_snapshot_policy_and_request_have_frozen_bytes() {
    let keys = Secrets::from_member([7; 32], [8; 32]);
    let collection = [1; 32];
    let genesis = hex::decode(include_str!("fixtures/genesis.hex").trim()).unwrap();
    let snapshot = hex::decode(include_str!("fixtures/snapshot.hex").trim()).unwrap();
    let policy = hex::decode(include_str!("fixtures/policy.hex").trim()).unwrap();
    let request = hex::decode(include_str!("fixtures/request.hex").trim()).unwrap();
    assert_eq!(keys.sign_genesis(collection).unwrap(), genesis);
    assert!(matches!(
        format::inspect(&genesis).unwrap(),
        Record::Genesis(_)
    ));
    let gid = format::id(&genesis);
    assert_eq!(
        hex::encode(gid),
        "ccd362468c62f340983158451b4353a7bb1256f9cf651aa25df495d1b1e41cfd"
    );
    let descriptor = Snapshot {
        collection,
        genesis: gid,
        writer: keys.root(),
        parents: vec![],
        manifest: [3; 32],
        objects: vec![[3; 32]],
    };
    assert_eq!(keys.sign_snapshot(&descriptor).unwrap(), snapshot);
    assert_eq!(
        format::inspect(&snapshot).unwrap(),
        Record::Snapshot(descriptor)
    );
    assert_eq!(
        hex::encode(format::id(&snapshot)),
        "e9850fed18f9871690e42fa23d41ee298692edfab66a26cdc5401250aec4bc56"
    );
    let expected = Policy::new(
        collection,
        keys.root(),
        0,
        None,
        vec![Member {
            key: keys.root(),
            role: Role::Writer,
            revoked: false,
        }],
        vec![],
        &[7; 32],
    )
    .unwrap();
    assert_eq!(expected.encode().unwrap(), policy);
    Policy::decode(&policy)
        .unwrap()
        .verify(&keys.root())
        .unwrap();
    assert_eq!(
        hex::encode(format::id(&policy)),
        "6902ee963cee8053b14d8fc016dd7b9e186fc60b2c872b55bce389fd107e8bb2"
    );
    let message = [
        b"arc-exp-1/enrollment-request\0".as_slice(),
        keys.root().as_slice(),
        &[9; 32],
    ]
    .concat();
    let expected = Request {
        signing: keys.root(),
        encryption: [9; 32],
        signature: SigningKey::from_bytes(&[7; 32]).sign(&message).to_bytes(),
    };
    assert_eq!(expected.encode().unwrap(), request);
    assert_eq!(Request::decode(&request).unwrap(), expected);
    assert_eq!(
        hex::encode(format::id(&request)),
        "dac496097aec287b468aaee04e503658cc018fa31901c9d0950c452feaec3971"
    );
    for bytes in [&genesis, &snapshot] {
        for n in 0..bytes.len() {
            assert!(format::inspect(&bytes[..n]).is_err());
        }
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(format::inspect(&bad).is_err());
    }
    for n in 0..policy.len() {
        assert!(Policy::decode(&policy[..n]).is_err());
    }
    for n in 0..request.len() {
        assert!(Request::decode(&request[..n]).is_err());
    }
}
