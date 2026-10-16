# Arc

**Encrypted storage. Verifiable sync. Independent of the carrier.**

Arc is an experimental Rust system for decentralized, encrypted file storage and verifiable synchronization. Each device keeps a local collection. Capture a version, carry its encrypted objects through an available connection or on a drive, then verify and restore them without depending on a central storage service.

Your collection should remain yours wherever its bytes travel. A device can carry encrypted data without holding the keys to read it. A lost connection should leave useful progress. Two people working offline should be able to keep both versions.

> **Under active development:** Arc has a working Linux CLI and local software verification. Physical two-device and Bluetooth qualification are still pending. The protocol is experimental and has not had an independent security audit.

## How it works

A **collection** is a set of files with its own identity, keys and version history. A **node** holds local collection state and encrypted objects. A **snapshot** records a version of the files and the versions it descends from.

Arc encrypts content before it leaves a node. Signed records establish who can publish a version; hashes and authenticated encryption detect altered data. A recipient checks the objects and their authorization before treating a snapshot as valid.

The carrier delivers bytes. It does not decide who may read them or which version becomes current. Arc supports offline transfer files, authenticated TCP connections and an explicit Linux Bluetooth RFCOMM endpoint adapter. The Bluetooth implementation awaits over-the-air qualification; radio and SMS adapters remain future work.

For example, two laptops can start with the same collection and make changes while disconnected. When they exchange data, Arc preserves both branches. You inspect the differences, prepare a resolved folder and capture a merge that records both parents. Importing data never silently replaces your selected version or writes over your working files.

Storage and exchange need no mandatory server. Each private collection currently has an administrator who controls membership through signed policies; ordinary authorized work can happen offline.

## Implemented capabilities

- **Encrypted snapshots and restore.** Capture folders, verify signatures and content, and restore a chosen version into a new directory.
- **History and explicit merges.** List versions, compare changes, select a working base and preserve concurrent offline work.
- **Reusable encrypted chunks.** Repeated captures reuse unchanged blocks at the same file offset while the content key remains the same. Rotation forces fresh encryption.
- **Independent devices.** Enroll readers or writers, distribute signed policy updates, revoke members and rotate content keys.
- **Offline and live exchange.** Export opaque transfer bundles or connect to a peer whose transport key you have explicitly verified. Live synchronization requests missing objects.
- **Interrupted-transfer progress.** Durable partial objects survive reconnects and receiver restarts in TCP, RFCOMM and constrained simulations. Reconnects request missing fragments, and only complete verified objects enter the store.
- **Streaming recovery and journal repair.** Back up retained objects, membership state and keys without buffering the whole collection. Recover into a new node, or explicitly complete a journaled membership update interrupted between writes.
- **Local diagnostics.** Explain identity, selected and competing versions, pending work and ciphertext integrity through `status` and `doctor`, with suggested actions.

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
./target/debug/arc status "$ARC_DEMO/node"
./target/debug/arc doctor "$ARC_DEMO/node"
```

A successful `cmp` prints nothing. Verification reports ciphertext completeness, checked ancestry and whether plaintext was verified. It also reports global freshness as unknown: a disconnected node cannot know whether another device has a newer version.

`status` explains the locally known identity, selected version, competing heads and pending work. `doctor` reports ciphertext integrity and trust-state problems with suggested actions. Both operate without unlocking files or changing the node; decrypting verification remains a separate step.

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
- **Recover or repair:** `recovery-export`, `recover` and `repair`. The [reliability guide](docs/reliability-and-carriers.md) explains backup contents, identity retirement and which interrupted states can be repaired.
- **Use Bluetooth:** `bluetooth-sync` exchanges through an explicitly prepared `/dev/rfcommN` endpoint. Arc handles the encrypted session, not pairing or discovery.

Transport identity and collection membership are separate. A live exchange transfers the chosen node's opaque object inventory, which can include ciphertext previously imported into that node. It excludes private keys and local control files, and does not automatically apply membership updates or select a new head.

Recovery recreates the backed-up device identity; use enrollment to add an independent device. New complete backups contain the retained object inventory and policy/key state. Legacy keys-only backups remain readable. Neither proves that the backed-up policy is still current elsewhere.

```sh
./target/debug/arc recovery-export "$ARC_DEMO/node" "$ARC_DEMO/backup.arc"
./target/debug/arc recover "$ARC_DEMO/recovered" "$ARC_DEMO/backup.arc" --trust-genesis GENESIS_ID
```

Replace `GENESIS_ID` with the independently retained value from `init`. Recovery verifies the complete backup before publishing the new node and leaves its working version unselected. New V3 backups stream authenticated records; older V2 and keys-only kits remain readable.

## Development status and limits

Revocation takes effect as devices receive the new policy. It cannot erase plaintext or keys a former member already holds. Granting a content key can also expose historical ciphertext encrypted with that key; access is currently collection-wide.

Journal repair covers newly prepared membership transitions. Legacy incomplete markers and signed-policy forks remain blocked for investigation. Streaming backups have a 16 GiB encoded limit and a 1,000,000-object ceiling; individual objects remain limited to 1 MiB. Capture, history and exchange have their own smaller bounds. A larger backup limit does not remove those constraints or recreate missing historical keys and objects.

Physical two-device and Bluetooth validation remain pending. The [hardware runbook](docs/reliability-and-carriers.md#two-device-acceptance-runbook) separates those checks from local process, pseudoterminal and simulator verification. Stable formats, independent security review and power-loss qualification also remain open.

The [readiness guide](docs/release-readiness.md) covers diagnostics, streaming backup framing, an executable SSH-based two-host acceptance workflow, parser mutation checks and local experimental packaging. The [benchmark guide](docs/benchmarks.md) measures capture, storage reuse and recovery with disposable data.

## Development and verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
CARGO_PROFILE_TEST_OPT_LEVEL=2 cargo test --all-targets --locked
```

The latest [verification record](docs/release-readiness.md#readiness-verification-record) covers 79 passing tests, strict Clippy, two 100,000-case parser mutation campaigns, abrupt-process recovery, signed format compatibility and exact recovery beyond the old 64 MiB backup ceiling. These are local software checks; physical carrier qualification and an independent external security review remain open.

The [measured storage baseline](docs/benchmarks.md#measured-release-build-baseline) restored every file from a roughly 98 MiB backup with about 68 MiB peak memory during export and recovery. It is one synthetic workload, not a general performance guarantee. A separate constrained-contact simulation preserved progress and converged across 11 short contacts.

For a reproducible local walkthrough after building, run `python3 tools/sprint_demo.py`. The [readiness guide](docs/release-readiness.md) also documents storage benchmarks, an explicit one-host rehearsal of the two-host runner, and local experimental packaging. These tools are available for development; they do not establish production or hardware readiness.

## Read the design

The implementation profiles describe current behavior. The architecture documents also include goals that remain unimplemented.

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

The original Rust prototype is preserved on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype) at `5f529a07af44b4fba02715aa0fa5a37eab06a11d`. Its historical claims and instructions belong to that version. The archive remains in Git history, outside the current source tree.

[MIT](LICENSE).
