use arc_store::{
    crypto::DeviceSecrets,
    format::id,
    policy::{Attestation, Member, Policy, Role},
};

#[test]
fn policy_signature_frontier_and_device_attestation_round_trip() {
    let admin = DeviceSecrets::from_seed([7; 32]);
    let device = DeviceSecrets::from_seed([9; 32]);
    let key = device.public();
    let policy = Policy::new(
        [1; 32],
        admin.public(),
        0,
        None,
        vec![Member {
            key,
            role: Role::Writer,
            revoked: false,
        }],
        vec![[4; 32]],
        // independent authority seed; generate a separate deterministic authority below
        &[7; 32],
    )
    .unwrap();
    policy.verify(&admin.public()).unwrap();
    let bytes = policy.encode().unwrap();
    let loaded = Policy::decode(&bytes).unwrap();
    loaded.verify(&admin.public()).unwrap();
    assert!(loaded.allows_writer(&key));
    assert!(!loaded.allows_writer(&[3; 32]));
    let snapshot = id(b"snapshot-record");
    let attestation = loaded.attest(snapshot, &device).unwrap();
    let encoded = attestation.encode().unwrap();
    let decoded = Attestation::decode(&encoded).unwrap();
    decoded.verify(&loaded).unwrap();
    assert_eq!(decoded.snapshot, snapshot);
}

#[test]
fn revoked_writer_cannot_create_attestation() {
    let admin = DeviceSecrets::from_seed([7; 32]);
    let device = DeviceSecrets::from_seed([9; 32]);
    let policy = Policy::new(
        [1; 32],
        admin.public(),
        0,
        None,
        vec![Member {
            key: device.public(),
            role: Role::Writer,
            revoked: true,
        }],
        vec![],
        &[7; 32],
    )
    .unwrap();
    assert!(policy.attest([8; 32], &device).is_err());
}

#[test]
fn device_key_material_requires_password() {
    let device = DeviceSecrets::generate();
    let locked = device.lock("correct horse").unwrap();
    assert_eq!(
        DeviceSecrets::unlock(&locked, "correct horse")
            .unwrap()
            .public(),
        device.public()
    );
    assert!(DeviceSecrets::unlock(&locked, "wrong").is_err());
}
