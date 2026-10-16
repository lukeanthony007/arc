# Arc

**Encrypted storage. Verifiable sync. Independent of the carrier.**

Arc is a Rust project for keeping files across devices without depending on a central storage service. Capture an encrypted snapshot, move it through a network or on a drive, and verify exactly what arrived before restoring it.

Your collection should remain yours wherever its bytes travel. A device can carry encrypted data without holding the keys to read it. A lost connection should leave useful progress. Two people working offline should be able to keep both versions.

> **Experimental:** the current CLI implements storage, device membership and synchronization, but the protocol is not stable or independently audited. Try it with disposable data. Linux is the currently supported platform.

## How it works

A **collection** is a set of files with its own identity, keys and version history. A **node** holds local collection state and encrypted objects. A **snapshot** records a version of the files and the versions it descends from.

Arc encrypts content before it leaves a node. Signed records establish who can publish a version; hashes and authenticated encryption detect altered data. A recipient checks the objects and their authorization before treating a snapshot as valid.

The carrier delivers bytes. It does not decide who may read them or which version becomes current. Today, Arc supports offline transfer files and authenticated TCP connections. Bluetooth, radio and SMS are future adapter targets, each with its own bandwidth and delivery constraints.

For example, two laptops can start with the same collection and make changes while disconnected. When they exchange data, Arc preserves both branches. You inspect the differences, prepare a resolved folder and capture a merge that records both parents. Importing data never silently replaces your selected version or writes over your working files.

Storage and exchange need no mandatory server. Each private collection currently has an administrator who controls membership through signed policies; ordinary authorized work can happen offline.

## What works today

- **Encrypted snapshots and restore.** Capture folders, verify signatures and content, and restore a chosen version into a new directory.
- **History and explicit merges.** List versions, compare changes, select a working base and preserve concurrent offline work.
- **Reusable encrypted chunks.** Repeated captures reuse unchanged blocks at the same file offset while the content key remains the same. Rotation forces fresh encryption.
- **Independent devices.** Enroll readers or writers, distribute signed policy updates, revoke members and rotate content keys.
- **Offline and live exchange.** Export opaque transfer bundles or connect to a peer whose transport key you have explicitly verified. Live synchronization requests missing objects.
- **Interrupted-transfer progress.** Complete verified objects survive interrupted contacts. A constrained-link simulator exercises loss, duplication, reordering and corruption.

Arc currently uses deliberate CLI operations. Automatic folder watching, background synchronization and peer discovery are outside this implementation.

## Try a local round trip

You need Rust with edition 2024 and `File::try_lock` support, Linux with `openat2`/`renameat2` and `/proc`, and a filesystem supporting hard links and directory flushing.

Clone the current branch without downloading the prototype's full history:

```sh
git clone --depth 1 --single-branch --branch master https://github.com/lukeanthony007/arc.git
cd arc
cargo build --locked
```

Create a temporary source folder and capture it. Enter a password when prompted, and retain the genesis ID printed by `init` separately: it identifies the collection you trust.

```sh
ARC_DEMO=$(mktemp -d)
mkdir "$ARC_DEMO/source"
printf 'A collection that can travel.\n' > "$ARC_DEMO/source/note.txt"

./target/debug/arc init "$ARC_DEMO/node"
./target/debug/arc capture "$ARC_DEMO/node" "$ARC_DEMO/source"
```

Replace `SNAPSHOT_ID` below with the snapshot ID printed by `capture`. Use the same password for verification and restore.

```sh
./target/debug/arc verify "$ARC_DEMO/node" SNAPSHOT_ID --decrypt
./target/debug/arc restore "$ARC_DEMO/node" SNAPSHOT_ID "$ARC_DEMO/restored"
cmp "$ARC_DEMO/source/note.txt" "$ARC_DEMO/restored/note.txt"
./target/debug/arc history "$ARC_DEMO/node"
```

A successful `cmp` prints nothing. Verification reports ciphertext completeness, checked ancestry and whether plaintext was verified. It also reports global freshness as unknown: a disconnected node cannot know whether another device has a newer version.

To make a portable transfer file:

```sh
./target/debug/arc export "$ARC_DEMO/node" SNAPSHOT_ID "$ARC_DEMO/transfer.arc"
```

That bundle contains encrypted content and history, with no secret keys. Restoring it elsewhere also requires the appropriate keys and a separately authenticated collection identity. Exporting a bundle alone is not a complete recovery backup.

Passwords are prompted for rather than passed as command-line arguments. Scripts must explicitly opt into `--password-stdin`. Use `./target/debug/arc --help` or a command's `--help` for arguments.

## Add devices and exchange data

The [device and sync guide](docs/device-and-sync-profile.md) describes the workflows and their exact constraints:

- **Enroll a device:** `enable-policy`, `device-request`, `grant` and `join`. Devices receive independent signing and key-envelope keys, with reader or writer access.
- **Maintain access:** `refresh`, `revoke` and `apply-policy`. Keep public enrollment requests for subsequent key distribution; deliver policy updates explicitly.
- **Connect two nodes:** `network-identity`, `serve-once` and `sync`. Verify each peer's full public transport key separately. The listener handles one foreground exchange and exits.
- **Resolve offline work:** `history`, `diff`, `select` and `merge`. Supply the resolved directory and every parent the merge resolves.

Transport identity and collection membership are separate. A live exchange transfers the chosen node's opaque object inventory, which can include ciphertext previously imported into that node. It excludes private keys and local control files, and does not automatically apply membership updates or select a new head.

For the original single-device recovery flow, see the [base implementation profile](docs/experimental-profile.md). Recovery recreates the same device identity; use enrollment to add an independent device.

## Current boundaries and next work

Revocation takes effect as devices receive the new policy. It cannot erase plaintext or keys a former member already holds. Granting a content key can also expose historical ciphertext encrypted with that key; access is currently collection-wide.

Remaining reliability work includes recovery export for collections with device membership, repair of interrupted membership changes, and persistent resumption of incomplete object fragments. Today, policy-managed recovery export is refused, interrupted membership changes block normal operations pending manual recovery, and only complete verified objects persist across transfer attempts.

Real Bluetooth, radio and SMS adapters remain unimplemented. The simulator does not establish hardware support, routing behavior or delivery guarantees. Stable formats, independent security review and power-loss qualification also remain open.

## Development and verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The five-milestone implementation passed 35 tests across six executables and a separate 27-operation CLI exercise covering independent devices, offline branches, live exchange, merging, revocation and historical restore. The [verification record](docs/device-and-sync-profile.md#verification-and-remaining-limits) distinguishes full-suite results, final follow-up checks and remaining gaps.

## Read the design

The implementation profiles describe current behavior. The architecture documents also include goals that remain unimplemented.

- [Architecture](DESIGN.md): purpose, trust boundaries, node roles and the broader design.
- [Base implementation](docs/experimental-profile.md): storage format, capture, verification, transfer and single-device recovery.
- [Device and sync implementation](docs/device-and-sync-profile.md): membership, keys, history, merges and live exchange.
- [Data and synchronization](docs/data-and-sync.md): objects, versions, conflicts and transfer design.
- [Security and keys](docs/security.md): threat model, authorization, recovery and metadata limits.
- [Operations and validation](docs/operations-and-validation.md): durability, safe restore and acceptance scenarios.
- [Decisions and sources](docs/decisions-and-sources.md): research, alternatives and unresolved protocol choices.

## Project history and license

The original Rust prototype is preserved on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype) at `5f529a07af44b4fba02715aa0fa5a37eab06a11d`. Its historical claims and instructions belong to that version. The archive remains in Git history, outside the current source tree.

[MIT](LICENSE).
