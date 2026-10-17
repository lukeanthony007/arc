# Arc

Decentralized encrypted file storage and verifiable sync, written in Rust.

Arc separates data security from transport. Files are encrypted locally, stored as versioned objects and verified when exchanged between nodes. Storage and synchronization do not require a central server or a continuous connection.

The goal is to carry the same verifiable data across different transports: network connections, physical drives, Bluetooth and eventually constrained links such as radio or SMS. Current implementations cover offline bundles, authenticated TCP and a Linux Bluetooth RFCOMM adapter. Radio and SMS adapters are not implemented.

**Status:** experimental Linux CLI. Formats are not stable, and the protocol has not received an independent security audit. Physical two-device, over-the-air Bluetooth and power-loss validation remain pending.

## How it works

A **collection** defines a shared identity, keys and version history. A **node** stores local collection state and encrypted objects. A **snapshot** records a version of the files and the snapshots it descends from.

Arc encrypts file content before transfer. Signed records establish who can publish a snapshot; hashes and authenticated encryption detect altered data. A node can store and relay ciphertext without holding the keys to read it. Transport identity and collection membership are separate: connecting to a peer does not grant access to its collections.

Offline changes create separate branches of history. Arc preserves both branches until an explicit merge records a resolved directory and its parent snapshots. Importing data does not apply membership updates, select a working version or overwrite working files.

Each private collection has an administrator who manages access through signed policies. Authorized devices can work offline, but a disconnected node cannot know whether another node holds a newer policy or snapshot.

## Capabilities

- **Encrypted snapshots and restore.** Capture directories, verify signatures and content, and restore a selected snapshot into a new directory.
- **History and merges.** List versions, compare changes, select a working base and preserve concurrent offline work.
- **Chunk reuse.** Reuse unchanged encrypted blocks at the same file offset under the same content key. Key rotation requires fresh encryption.
- **Device membership.** Enroll independent readers and writers, distribute signed policy updates, revoke members and rotate content keys.
- **Offline and live exchange.** Export encrypted bundles or synchronize with a peer whose full transport key has been verified separately.
- **Resumable transfers.** Retain partial objects across reconnects and receiver restarts. Request missing fragments; admit only complete, verified objects to the store.
- **Recovery and repair.** Stream backups of retained objects, keys and membership state. Explicitly complete journaled membership updates interrupted between writes.
- **Diagnostics.** Inspect identity, locally known versions, pending work and ciphertext integrity through read-only `status` and `doctor` commands.

## Build and run

Requires Linux with `openat2`, `renameat2` and `/proc`, Rust with edition 2024 and `File::try_lock` support, and a filesystem supporting hard links and directory flushing.

```sh
git clone --depth 1 --single-branch --branch master https://github.com/lukeanthony007/arc.git
cd arc
cargo build --locked
./target/debug/arc --help
```

For a local capture and restore:

```sh
ARC_DEMO=$(mktemp -d)
mkdir "$ARC_DEMO/source"
printf 'A collection that can travel.\n' > "$ARC_DEMO/source/note.txt"

./target/debug/arc init "$ARC_DEMO/node"
./target/debug/arc capture "$ARC_DEMO/node" "$ARC_DEMO/source"
```

Enter a password when prompted. Retain the genesis ID from `init` separately: it identifies the collection to trust during recovery. Replace `SNAPSHOT_ID` below with the ID printed by `capture`.

```sh
./target/debug/arc verify "$ARC_DEMO/node" SNAPSHOT_ID --decrypt
./target/debug/arc restore "$ARC_DEMO/node" SNAPSHOT_ID "$ARC_DEMO/restored"
cmp "$ARC_DEMO/source/note.txt" "$ARC_DEMO/restored/note.txt"
./target/debug/arc status "$ARC_DEMO/node"
./target/debug/arc doctor "$ARC_DEMO/node"
```

Use the same password for verification and restore. A successful `cmp` prints nothing. `status` and `doctor` do not unlock files or modify the node; plaintext verification requires `verify --decrypt`.

For a broader disposable walkthrough, run `python3 tools/sprint_demo.py` after building.

## Devices, exchange and recovery

Device enrollment uses `enable-policy`, `device-request`, `grant` and `join`. Each device receives independent signing and key-envelope keys with reader or writer access. Policy updates and key rotation are delivered explicitly through the membership workflow.

Live exchange uses `network-identity`, `serve-once` and `sync`. It transfers the node's opaque object inventory, including previously imported ciphertext, but excludes private keys and local control files. The Bluetooth adapter uses an already prepared `/dev/rfcommN` endpoint; Arc does not handle pairing or discovery.

Offline transfer bundles contain encrypted content and history, not secret keys. Restoring them requires the appropriate keys and a separately authenticated collection identity. A transfer bundle is not a recovery backup.

`recovery-export` creates a complete backup of the node's retained objects and policy/key state. `recover` verifies it against an independently retained genesis ID before making the recovered node available. Recovery restores the same device identity: retire the original before publishing from the recovered node. Use enrollment to add an independent device.

See the [device and sync guide](docs/device-and-sync-profile.md) for enrollment and exchange, and the [recovery guide](docs/reliability-and-carriers.md) for backup, identity retirement and repair procedures.

## Constraints

Arc currently uses explicit CLI operations. Folder watching, background synchronization and peer discovery are not implemented.

Access is collection-wide. Revocation takes effect as devices receive the new policy; it cannot erase previously acquired keys or plaintext. Granting a content key can expose older ciphertext encrypted with that key.

Streaming backups allow up to 16 GiB of encoded data and 1,000,000 objects, with a 1 MiB limit per object. Capture, history and exchange have separate, smaller bounds. Backups cannot recreate missing objects or historical keys, or establish whether the saved policy is current elsewhere.

Journal repair covers newly prepared membership transitions. Legacy incomplete markers and conflicting signed policies remain blocked for investigation.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
CARGO_PROFILE_TEST_OPT_LEVEL=2 cargo test --all-targets --locked
```

The recorded local verification covers 79 passing tests, strict Clippy, two 100,000-case parser mutation campaigns, abrupt-process recovery, signed format compatibility and exact recovery beyond the former 64 MiB backup limit.

A synthetic benchmark restored every file from a roughly 98 MiB backup with about 68 MiB peak memory during export and recovery. A constrained-contact simulation retained progress and completed transfer across 11 short contacts. These results describe specific local workloads, not general performance or physical-carrier qualification.

The [verification record](docs/release-readiness.md#readiness-verification-record) distinguishes completed software checks from outstanding hardware and security validation.

## Documentation

- [Architecture](DESIGN.md): purpose, trust boundaries, node roles and planned capabilities.
- [Base implementation](docs/experimental-profile.md): capture, verification, storage formats and restore.
- [Device and sync implementation](docs/device-and-sync-profile.md): membership, keys, history, merges and live exchange.
- [Recovery and carriers](docs/reliability-and-carriers.md): backups, repair, resumable transfers and hardware validation.
- [Security](docs/security.md): threat model, authorization and metadata limits.
- [Release readiness](docs/release-readiness.md): diagnostics, streaming recovery, validation tooling and experimental packaging.
- [Benchmarks](docs/benchmarks.md): reproducible storage, memory and recovery measurements.

Implementation guides describe current behavior. Architecture documents also include unimplemented goals.

## License and history

[MIT](LICENSE). The previous prototype is preserved on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), outside the current source tree.
