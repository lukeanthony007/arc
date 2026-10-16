//! Deterministic mutation smoke campaign; not coverage-guided fuzzing or an audit.
use arc_store::{enrollment::Request, format, policy::Policy};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn check(input: &[u8]) {
    // Successful record inspection already requires exact canonical encoding and
    // valid signatures where present. Policies additionally need an authority
    // check before application; parser success is not authorization.
    let _ = format::inspect(input);
    if let Ok(entries) = format::decode_manifest(input) {
        assert_eq!(format::encode_manifest(&entries).unwrap(), input);
    }
    if let Ok(parsed) = Policy::decode(input) {
        assert_eq!(parsed.encode().unwrap(), input);
        let _ = parsed.verify(&parsed.authority);
    }
    if let Ok(parsed) = Request::decode(input) {
        assert_eq!(parsed.encode().unwrap(), input);
    }
}

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .map(|s| {
            s.parse::<usize>()
                .expect("iteration count must be an integer")
        })
        .unwrap_or(10_000);
    assert!(
        (1..=10_000_000).contains(&iterations),
        "iteration count outside bounded campaign"
    );
    let seed = std::env::var("ARC_PARSER_SEED")
        .ok()
        .map(|s| s.parse::<u64>().expect("seed must be a decimal u64"))
        .unwrap_or(0x4152_4321);
    assert_ne!(seed, 0, "xorshift seed must be nonzero");
    let mut state = seed;
    let mut corpus = vec![
        Vec::new(),
        vec![0xff],
        vec![0x82, 1, 0x80],
        vec![0x9f; 64],
        vec![0; format::MAX_OBJECT + 1],
    ];
    for text in [
        include_str!("../tests/fixtures/genesis.hex"),
        include_str!("../tests/fixtures/snapshot.hex"),
        include_str!("../tests/fixtures/policy.hex"),
        include_str!("../tests/fixtures/request.hex"),
    ] {
        corpus.push(hex::decode(text.trim()).unwrap());
    }
    // Huge declared array/byte lengths without the claimed allocation, a
    // noncanonical integer and an indefinite byte string.
    corpus.extend([
        vec![0x82, 1, 0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x82, 0x18, 1, 0x80],
        vec![0x5f, 0xff],
    ]);
    for input in &corpus {
        check(input);
    }
    let fixed = corpus.len();
    for i in 0..iterations {
        let mut input = corpus[i % corpus.len()].clone();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        match state % 6 {
            0 if !input.is_empty() => input.truncate(state as usize % input.len()),
            1 if !input.is_empty() => {
                let index = state as usize % input.len();
                input[index] ^= ((state >> 32) as u8) | 1;
            }
            2 => input.push(state as u8),
            3 => input.insert(0, state as u8),
            4 if !input.is_empty() => {
                let index = state as usize % input.len();
                input.remove(index);
            }
            _ => {}
        }
        assert!(
            catch_unwind(AssertUnwindSafe(|| check(&input))).is_ok(),
            "parser panic: seed={seed}, iteration={i}"
        );
        if i % 256 == 255 && input.len() <= 65_536 {
            corpus.push(input);
            if corpus.len() > 128 {
                corpus.remove(fixed);
            }
        }
    }
    println!(
        "parser mutation smoke: seed={seed}, iterations={iterations}; no coverage-guided or cryptographic-audit claim"
    );
}
