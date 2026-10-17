# Arc

Arc is a Rust project for decentralized, encrypted data storage and verifiable sync.

The idea came from wanting to separate the security of stored data from the way it moves between devices. Whether it's a network connection or a drive you carry over yourself, you should be able to check what arrived and who was allowed to write it, without relying on a central server.

I'm building Arc around that idea. The longer-term direction includes Wi-Fi, Bluetooth, radio, SMS and other ways of moving data. The current implementation supports offline transfer files, authenticated TCP connections and a Linux Bluetooth RFCOMM adapter. Radio and SMS adapters aren't implemented.

This is still in development. The Linux CLI has local software checks behind it, but physical two-device and over-the-air Bluetooth testing are still pending. The protocol isn't stable or independently audited.

## How it works

Arc keeps files as encrypted snapshots. A snapshot records a version of your files and the versions it came from. A **collection** holds that shared identity and history; a **node** is a local store for its encrypted objects and state.

The connection carries the data. Arc checks signatures, hashes and authorization before accepting a snapshot as valid. A device can hold and pass along encrypted data without having the keys to read it.

Say two laptops start with the same files and both make changes while offline. When they exchange data, Arc keeps both versions. You can inspect the differences, put together the result you want and record a merge with both versions as parents. Receiving data doesn't choose a version for you or overwrite your working files.

There's no required storage server. Each private collection does still have an administrator who manages membership through signed policies. Authorized devices can work offline.

## What's implemented

- **Snapshots and restore.** Capture a folder, verify a version and restore it into a new directory.
- **History and merges.** Compare versions, choose a working base and keep both sides of an offline change.
- **Chunk reuse.** Unchanged blocks at the same file offset can reuse their encrypted bytes while the content key stays the same. Rotating the key requires fresh encryption.
- **Device access.** Enroll independent readers and writers, update their access, revoke devices and rotate content keys.
- **Data exchange.** Move encrypted bundles or connect to a peer whose transport key you've verified. Live sync requests what's missing.
- **Interrupted transfers.** Keep received fragments across reconnects and receiver restarts. Only complete, verified objects enter the store. TCP, RFCOMM and the simulator use this mechanism.
- **Recovery and repair.** Back up objects, membership state and keys without holding the whole collection in memory. Restore into a fresh node, or finish a recorded membership update that stopped between writes.
- **Diagnostics.** Use `status` and `doctor` to see locally known versions, pending work and integrity problems, with suggested next steps.

For now, you run these operations yourself through the CLI. Arc doesn't watch folders, sync in the background or discover peers automatically.

## Try a local round trip

The current implementation needs Linux with `openat2`, `renameat2` and `/proc`, Rust with edition 2024 and `File::try_lock` support, and a filesystem that supports hard links and directory flushing.

To build it without downloading the old prototype's full history:

```sh
git clone --depth 1 --single-branch --branch master https://github.com/lukeanthony007/arc.git
cd arc
cargo build --locked
```

Start with a temporary folder. Arc will prompt for a password. Keep the genesis ID printed by `init` separately so you can check the collection's identity later.

```sh
ARC_DEMO=$(mktemp -d)
mkdir "$ARC_DEMO/source"
printf 'A collection that can travel.\n' > "$ARC_DEMO/source/note.txt"

./target/debug/arc init "$ARC_DEMO/node"
./target/debug/arc capture "$ARC_DEMO/node" "$ARC_DEMO/source"
```

Use the snapshot ID from `capture` in place of `SNAPSHOT_ID`. Verification and restore use the same password.

```sh
./target/debug/arc verify "$ARC_DEMO/node" SNAPSHOT_ID --decrypt
./target/debug/arc restore "$ARC_DEMO/node" SNAPSHOT_ID "$ARC_DEMO/restored"
cmp "$ARC_DEMO/source/note.txt" "$ARC_DEMO/restored/note.txt"
./target/debug/arc history "$ARC_DEMO/node"
./target/debug/arc status "$ARC_DEMO/node"
./target/debug/arc doctor "$ARC_DEMO/node"
```

If `cmp` prints nothing, the restored file matches. Verification checks the encrypted data and its ancestry; `--decrypt` also checks the file contents. Global freshness stays unknown because an offline node can't know whether another device has a newer version.

`status` shows the identity, selected version, other locally known heads and pending work. `doctor` checks encrypted data and trust state, then suggests what to do about any problems it finds. Neither command unlocks files or changes the node.

To make a portable transfer file:

```sh
./target/debug/arc export "$ARC_DEMO/node" SNAPSHOT_ID "$ARC_DEMO/transfer.arc"
```

The transfer file contains encrypted content and history, not secret keys. To restore it elsewhere, you also need the right keys and a collection identity you've checked separately. A transfer file on its own isn't a recovery backup.

Passwords aren't command-line arguments. Arc prompts for them, or a script can explicitly use `--password-stdin`. Run `./target/debug/arc --help` or a command's `--help` for its arguments.

## Add devices and exchange data

The [device and sync guide](docs/device-and-sync-profile.md) walks through these operations:

- **Add a device:** `enable-policy`, `device-request`, `grant` and `join`. Each device gets its own signing and key-envelope keys, with reader or writer access.
- **Update access:** `refresh`, `revoke` and `apply-policy`. Keep the public enrollment requests for later key distribution. Policy updates need to be delivered explicitly.
- **Connect two nodes:** `network-identity`, `serve-once` and `sync`. Check each peer's full public transport key separately. The listener handles one foreground exchange, then exits.
- **Resolve offline changes:** `history`, `diff`, `select` and `merge`. You supply the resolved folder and all the parent versions you're merging.
- **Recover or repair:** `recovery-export`, `recover` and `repair`. The [reliability guide](docs/reliability-and-carriers.md) explains backup contents and which interrupted updates can be repaired.
- **Use the Bluetooth adapter:** `bluetooth-sync` works through an already prepared `/dev/rfcommN` endpoint. Pairing and discovery are handled outside Arc.

A transport key identifies the peer connection. It doesn't grant collection membership. Live exchange transfers the node's encrypted object inventory, including previously imported ciphertext, but leaves private keys and local control files behind. It doesn't apply membership updates or choose a working version.

Recovery brings back the same device identity. Retire the original before publishing from the recovered node; use enrollment if you want to add another device instead. A backup preserves the objects, keys and policy state that node held. It can't tell you whether the policy has changed elsewhere.

```sh
./target/debug/arc recovery-export "$ARC_DEMO/node" "$ARC_DEMO/backup.arc"
./target/debug/arc recover "$ARC_DEMO/recovered" "$ARC_DEMO/backup.arc" --trust-genesis GENESIS_ID
```

Replace `GENESIS_ID` with the value you kept separately from `init`. Arc checks the complete backup before making the recovered node available and doesn't select a working version for you. New V3 backups stream authenticated records. Older V2 backups and keys-only kits are still readable.

## Current limits

Revocation takes effect when a device receives the new policy. It can't take back plaintext or keys someone already has. Access is collection-wide, so sharing a content key can also expose older data encrypted with that key.

Repair handles newly journaled membership updates. Older incomplete markers and conflicting signed policies still stop the operation and need investigation.

Streaming backups are limited to 16 GiB of encoded data and 1,000,000 objects, with a 1 MiB limit per object. Capture, history and exchange have their own smaller limits. The larger backup format doesn't remove those limits or recover objects and keys that were never present.

Physical two-device and Bluetooth validation, stable formats, an independent security review and power-loss qualification are still open. The [hardware runbook](docs/reliability-and-carriers.md#two-device-acceptance-runbook) keeps those checks separate from local processes, pseudoterminals and simulations.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
CARGO_PROFILE_TEST_OPT_LEVEL=2 cargo test --all-targets --locked
```

The latest [verification record](docs/release-readiness.md#readiness-verification-record) covers 79 passing tests, strict Clippy and two parser mutation campaigns of 100,000 cases each. It includes abrupt-process recovery, signed format compatibility and exact recovery beyond the old 64 MiB backup limit. These are software checks, not evidence that the physical carriers or production security have been qualified.

In the [recorded benchmark](docs/benchmarks.md#measured-release-build-baseline), every file was restored from a roughly 98 MiB backup, with about 68 MiB peak memory during export and recovery. That's one synthetic workload, not a general performance claim. A separate simulation kept partial progress and completed its transfer across 11 short contacts.

After building, `python3 tools/sprint_demo.py` runs a disposable local walkthrough. The [readiness guide](docs/release-readiness.md) covers diagnostics, backup framing, parser checks, the SSH-based two-host runner and its one-host rehearsal, and local experimental packaging. The [benchmark guide](docs/benchmarks.md) explains the storage and recovery measurements.

## Read the design

The implementation profiles describe what's in the code now. The broader design also includes things that haven't been built yet.

- [Architecture](DESIGN.md): purpose, trust boundaries, node roles and the broader design.
- [Base implementation](docs/experimental-profile.md): storage format, capture, verification, transfer and single-device recovery.
- [Device and sync implementation](docs/device-and-sync-profile.md): membership, keys, history, merges and live exchange.
- [Recovery and carriers](docs/reliability-and-carriers.md): complete backups, journal repair, persistent fragments and the two-device hardware runbook.
- [Release readiness](docs/release-readiness.md): diagnostics, streaming recovery, executable acceptance, hardening and local packaging.
- [Benchmarks](docs/benchmarks.md): reproducible storage and memory measurements.
- [Data and synchronization](docs/data-and-sync.md): objects, versions, conflicts and transfer design.
- [Security and keys](docs/security.md): threat model, authorization, recovery and metadata limits.
- [Operations and validation](docs/operations-and-validation.md): durability, safe restore and acceptance scenarios.
- [Decisions and sources](docs/decisions-and-sources.md): research, alternatives and unresolved protocol choices.

## Project history and license

The original Rust prototype is on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype) at `5f529a07af44b4fba02715aa0fa5a37eab06a11d`. It's kept in Git history, outside the current source tree. Its claims and instructions belong to that older version.

[MIT](LICENSE).
