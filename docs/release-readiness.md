# Experimental release readiness

This iteration adds local diagnostics, streaming complete recovery, repeatable measurements and packaging. It does not freeze the protocol, establish physical carrier qualification or replace independent cryptographic review. The earlier [reliability verification](reliability-and-carriers.md#sprint-verification-record) remains dated evidence for that revision.

## Understand a node before changing it

```sh
arc status NODE
arc doctor NODE
```

Neither command prompts for a password, decrypts file contents, repairs a journal, selects a head or discards progress. `status` describes the pinned identity, selected version, other locally authorized heads, validated local policy epoch, incomplete-transfer files and pending membership guard. History-inspection failure is unknown, not evidence that no competing heads exist. `doctor` checks trusted identity/policy, selected and other authorized snapshot ciphertext coverage and bounded CAS digests; it prints findings with actions and exits unsuccessfully on errors. Warnings, such as no selected snapshot, do not alone make the node invalid.

The diagnostic scan is bounded to 16,384 CAS directory entries and 1 GiB of object bytes, and partial-state enumeration is bounded by the receiver's 128-object quota plus its lock/scratch entries. A reported inspection limit requires further investigation; it is not proof of corruption or complete coverage. Partial-file counts are observations of retained files, not verification that every staged fragment will be accepted. Plaintext integrity still requires `verify NODE SNAPSHOT --decrypt`. Concurrent writes can change what an inspection observes; stop owned writers and repeat if a coherent maintenance checkpoint is needed.

An offline node cannot establish global policy freshness. A pending guard may be a repairable authenticated journal, a legacy marker or a signed-policy fork: preserve it and use the explicit repair workflow. Diagnostic advice never authorizes deleting an unknown guard.

## Streaming complete recovery

New `recovery-export` backups use `ARCRCV3`; `recover` also reads the older bounded `ARCRCV2` container and keys-only `ARCKEY1` kits. V3 changes the recovery container only. Immutable object, membership, transfer-bundle and live synchronization profiles are unchanged.

The header is 40 bytes: eight-byte `ARCRCV3\n`, a random 16-byte Argon2id salt and a random 16-byte XChaCha nonce prefix. The fixed KDF remains Argon2id v19, 65,536 KiB, three iterations, one lane and a 32-byte result. The same derived key encrypts independently authenticated records. Each nonce is the random prefix followed by the eight-byte big-endian record sequence, starting at zero. Each record has a one-byte kind, four-byte big-endian ciphertext length and ciphertext including its 16-byte tag. Additional authenticated data is the exact header, sequence, kind and encoded ciphertext length.

Record kinds are control (1), member device key (2), immutable object (3) and final commitment (255). Control plaintext is a one-byte whitelist index followed by locked control bytes; only genesis, keys, policy and keys-history are admitted. The optional device record contains the already locked device key. Object plaintext is its 32-byte content ID followed by its immutable bytes. Controls and device state precede objects; repeated controls, device keys and object IDs are rejected.

The mandatory final record contains object count (u64 big endian), total object bytes (u64 big endian), and SHA-256 over the concatenation of each preceding record's additional authenticated data and ciphertext. Its own AEAD authenticates those commitments. Position-bound tags reject record movement and duplication. Recovery requires the completion record, exact counts, matching transcript and EOF; a truncated prefix cannot become a recovered node.

The encoded file is limited to 16 GiB and 1,000,000 objects. Individual immutable objects retain their 1 MiB ceiling; each control is bounded by that ceiling, the locked member device key by 256 bytes, and the signed policy/history chain by 256 entries. These are recovery limits: current capture, history, live-inventory and diagnostic bounds still apply independently. Increasing the backup limit does not make every other operation accept a million-object collection.

Export and recovery retain bounded frames rather than the inventory's contents. Memory includes the fixed 64 MiB KDF workspace, several copies of one object/frame, controls and bounded policy/history validation. It does not grow with aggregate inventory bytes. V2 reading retains its old buffered 64 MiB limit.

Recovery authenticates each record before writing it into a private sibling staging node. Staged immutable bytes and locked key controls retain their existing protection; there are no decrypted document temporary files. After authenticated completion it validates the pinned genesis, signed policy ancestry, active member identity and historical key custody. Only then does no-replace rename publish the destination. It never selects a working version. Ordinary errors clean the owned staging directory. Process death may leave a private staging directory containing immutable bytes and locked controls, or an encrypted export temporary file; the destination remains unpublished until completion, and unexplained leftovers should be preserved for investigation.

The [recovery identity and freshness rules](reliability-and-carriers.md#complete-recovery-backups) still apply. Retire the original device before publishing from its recovered identity. Backups cannot recreate keys or objects never held, or prove that their policy checkpoint is current elsewhere.

## Two-host acceptance and honest evidence

The existing [hardware runbook](reliability-and-carriers.md#two-device-acceptance-runbook) covers actual USB carriage, physical separation, LAN, over-the-air Bluetooth, interrupted fragment reuse, wrong peer pins and recovery. The executable runner automates a narrower disposable workflow on two already accessible Linux hosts:

```sh
python3 tools/two_device_acceptance.py \
  --binary target/release/arc \
  --peer EXISTING_TRUSTED_SSH_DESTINATION \
  --peer-binary /absolute/path/to/arc \
  --address PEER_LAN_IPV4 \
  --output target/two-host-result.json
```

Build the same source revision on both hosts first. Both need Python 3.9+; the initiating host needs OpenSSH. Existing SSH host verification must succeed: the runner uses BatchMode and never bypasses host-key checks, discovers peers, installs software or changes firewall/radio state. SSH supplies setup requests, invitations, bundle files and the encrypted recovery artifact. The actual synchronization uses the Arc pinned Noise connection over the supplied LAN address. Passwords travel through stdin and the encrypted SSH channel, never command-line arguments or the result record. The workflow creates private disposable nodes, retains offline branches, explicitly merges, rejects revoked-writer publication, then restores exact historical/current bytes from a backup on the peer. It does not use real user data.

For an already prepared Linux RFCOMM stream, add `--rfcomm /dev/rfcommN /dev/rfcommM`; the first endpoint is local and the second is on the SSH peer. This substitutes Bluetooth endpoint exchange for LAN. The operator must establish and record the actual radio connection separately. No pairing or bindings are changed by the runner. The prepared connection must remain available during the exercise.

```sh
# One-host rehearsal only; output explicitly cannot qualify physical carriers.
python3 tools/two_device_acceptance.py --local-peer \
  --binary target/release/arc --output target/local-acceptance.json
```

The runner records scoped results and failures to a new JSON file without overwrite. Owned Arc subprocess groups are bounded and terminated on ordinary errors/signals, and private fixture cleanup is attempted on each host with an ownership token. A lost SSH connection may prevent remote cleanup; inspect the reported path and preserve it until ownership is confirmed. Physical USB, interrupted RFCOMM fragment reuse and wrong-pin hardware acceptance remain separate runbook steps even after this runner succeeds. Its `physical_two_device_qualification` flag stays false: a complete qualification requires operator evidence beyond this automated subset.

## Hardening and review

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
CARGO_PROFILE_TEST_OPT_LEVEL=2 cargo test --all-targets --locked
cargo run --locked --release --example parser_campaign -- 100000
ARC_PARSER_SEED=123456789 cargo run --locked --release --example parser_campaign -- 100000
```

The deterministic mutation campaign exercises signed immutable record inspection, manifest, policy and enrollment-request codecs with valid frozen vectors, changed bytes, insertions, deletions, truncations, oversized inputs and hostile declared lengths. Accepted codecs must re-encode canonically. Seeds and iteration counts are reported. This is a bounded mutation smoke campaign; coverage-guided fuzzing, transport/backup fuzz campaigns and cryptographic proof are not established by it.

Compatibility tests freeze independently encoded signed genesis, snapshot, policy and enrollment bytes/hashes, plus the empty manifest. Public deterministic fixture keys are never user identities. V2 and legacy keys-only recovery compatibility have separate regressions. The process-exit regression launches a real child that exits without unwinding after a durable membership failpoint; the reopened node must repair idempotently. That checks abrupt application exit, not kernel crashes, filesystem failure or physical power loss. The earlier 29 failpoint boundaries remain broader application-error coverage.

Before making production security claims, commission an independent review of the final revision. Give the reviewer the [threat model](security.md), exact format profiles, trust paths and test commands. Ask specifically about nonce/domain separation and KDF inputs; authenticated recovery completion and stale-policy custody; enrollment/rotation/revocation and historical-key authority; pinned Noise failure behavior and resource limits; filesystem races, durable publication and crash recovery. Findings need locations, reproducible triggers, severity and fix verification. Agent code review is useful bounded evidence but is not this independent external audit. No external reviewer was contacted or report purchased by this sprint.

## Build a local experimental package

After checks pass and the source is committed and clean:

```sh
python3 tools/package_experimental.py --output target/arc-experimental.tar.gz
```

This requires Python 3.11+ and runs a locked release build for the compiler's native host target, then takes the executable path from Cargo's artifact output. It packages the binary, license, profiles, guides and Python tools. The manifest records source revision, architecture, toolchain, binary hash and experimental status; SHA256SUMS checks the included binary. Archive times and ownership are normalized to the source commit. Binary reproducibility across toolchains/machines has not been established. Packaging refuses dirty source, a source change during the build or an existing output. It neither signs nor uploads a release, creates a Git tag, installs the binary nor freezes the protocol. From an extracted package, use `bin/arc` and pass `--binary bin/arc` to the demo/benchmark tools; source-build commands still require a source checkout. Hardware runners require an operator-prepared peer.

For storage measurements, see the [benchmark procedure and measured results](benchmarks.md). Production use, a published release, physical carrier qualification and independent review remain distinct decisions and evidence.

## Readiness verification record

On 2026-10-16 the integrated tree passed 79 tests across 18 executables, strict Clippy, formatting and the locked release binary/example build. Test-profile optimization level 2 avoids unoptimized cryptography without changing assertions or Argon2 parameters. New regressions cover a genuine 65 MiB snapshot recovery and exact restore, required stream completion, framing damage/reordering/duplication, no destination on failure, legacy read compatibility, historical identity separation, canonical inventory names and policy collection binding.

The actual release CLI passed the 33-operation disposable lifecycle demo and the SSH-capable runner's explicit local rehearsal. The latter also exercised `status`, successful `doctor`, and unsuccessful `doctor` after removing only a disposable recovered genesis object. Every restored historical/current file matched; fixtures and the foreground listener were removed. Negative-result checks rejected a supervisor timeout as an authorization success, and terminating the supervisor reaped its owned child.

Two parser mutation campaigns passed 100,000 cases each with seeds 1095910177 and 123456789. The full storage benchmark and short-contact measurement passed as recorded in [benchmarks](benchmarks.md). Local Markdown file links resolved; Python scripts and both embedded remote helpers parsed successfully.

Bounded agent reviews found and led to fixes for policy collection binding, mixed historical identities in V2 recovery, noncanonical inventory aliases, partial store-creation cleanup, diagnostic uncertainty and fragment bounds, benchmark measurement errors, negative-result discrimination and package artifact provenance. Follow-up static reviews reported no unresolved findings within those inspected changes. These are agent-assisted source reviews, not an external cryptographic audit.

The physical acceptance portion remains blocked: this environment exposed a local Bluetooth controller but no configured second SSH host. No pairing, bindings, radio state, user data or remote machine was changed. Physical two-device/USB/Bluetooth, interrupted over-the-air fragment reuse, power-loss qualification, coverage-guided fuzzing and independent external security review remain unverified.
