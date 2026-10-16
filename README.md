# Arc

Arc is being redesigned as decentralized encrypted storage with verifiable synchronization independent of how the data travels.

A collection should remain usable on one device, across invited peers, or through optional storage and relay nodes. Data can move over live networks or disconnected carriers such as removable media. Bluetooth, radio and SMS are intended adapter targets with their own capacity and platform limits.

The Rust core includes experimental encrypted snapshots and recovery, history/diff/base selection, reusable encrypted chunks, signed device membership, explicit merges, authenticated foreground TCP exchange and a constrained-link simulator. The [base profile](docs/experimental-profile.md) and [device/sync extension](docs/device-and-sync-profile.md) define the implementation and its limits. It is not an audited or stable protocol; use disposable data.

## Design review

Start with [the architecture](DESIGN.md). The review draft covers:

- [Data and synchronization](docs/data-and-sync.md): immutable encrypted objects, snapshots, conflicts, epoch transitions, live reconciliation and offline packages.
- [Security and keys](docs/security.md): threat model, membership, encryption candidates, recovery, revocation and metadata limits.
- [Operations and validation](docs/operations-and-validation.md): safe capture/restore, durable storage, retention, interface behavior and acceptance scenarios.
- [Decisions and sources](docs/decisions-and-sources.md): proposed choices, alternatives, primary research and unresolved implementation gates.

The architecture targets private invited collections with no mandatory storage or coordination server. The experiment now supports independent reader/writer enrollment, explicit key revocation/rotation and multiple offline branches. Policy changes need explicit recipient packages; offline revocation is not instantaneous. Live TCP transfer is separate from collection authorization and never selects a head automatically. Real Bluetooth, radio and SMS adapters remain unimplemented.

The user authorized beginning implementation on 2026-10-16. Stable-format and production-security gates remain open; no security review or hardware integration is implied. Arc does not depend on Luma, an AI model, a blockchain or a transport provider.

## Running the experimental core

Requires Rust with edition 2024 and `File::try_lock` support, Linux with `openat2`/`renameat2` and `/proc`, and a filesystem supporting hard links and directory flushing. No installation or background service is needed.

```sh
cargo run --locked -- --help
cargo run --locked -- init /path/to/new-node
cargo run --locked -- capture /path/to/new-node /path/to/source-directory
cargo run --locked -- verify /path/to/new-node SNAPSHOT_ID --decrypt
cargo run --locked -- restore /path/to/new-node SNAPSHOT_ID /path/to/new-destination
cargo run --locked -- export /path/to/new-node SNAPSHOT_ID /path/to/new-transfer.arc
cargo run --locked -- recovery-export /path/to/new-node /path/to/new-keys.arc
```

Replace paths and `SNAPSHOT_ID` with the printed capture ID. Init/capture/decrypted verification/restore prompt for the password. Pipelines must explicitly opt into `--password-stdin`; passwords are not command-line arguments. Output from init gives the genesis identity to retain independently.

On a fresh recovery device, keep the previous writer offline and authenticate the genesis ID separately:

```sh
cargo run --locked -- recover /path/to/new-recovered-node /path/to/new-keys.arc --trust-genesis GENESIS_ID
cargo run --locked -- import /path/to/new-recovered-node /path/to/new-transfer.arc
cargo run --locked -- verify /path/to/new-recovered-node SNAPSHOT_ID --decrypt
cargo run --locked -- restore /path/to/new-recovered-node SNAPSHOT_ID /path/to/new-restored-directory
```

The keys file carries root/data keys encrypted under the existing password, but no file content. The transfer carries ciphertext and ancestry, but no secret keys. Import changes neither the trusted identity nor the local head. Recovery clones the same device identity; it is not multi-device enrollment.

Run the checks with `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --all-targets`.

## History, devices and live exchange

The [extension guide](docs/device-and-sync-profile.md) explains the complete command flow and its constraints. Use `history`, `diff`, `select` and `merge` to inspect and resolve versions. Ordinary repeated `capture` reuses unchanged authenticated chunks within the same key epoch.

Use `enable-policy`, `device-request`, `grant`, `join`, `refresh`, `revoke` and `apply-policy` for explicit membership and key delivery. Keep public enrollment requests for subsequent key distribution. Catch-up packages carry the full signed policy chain back to the member's trusted checkpoint; interrupted membership transitions fail closed and require manual recovery. Legacy recovery-kit export is refused for policy-managed collections.

For a live exchange, create independent password-protected transport identities with `network-identity`, verify their public keys separately, then use `serve-once` and `sync` with explicit addresses and full peer public pins. These commands exchange the selected node's opaque object inventory, excluding private controls and keys. The server handles one connection with bounded waits and exits; no service is installed. `--help` describes each command's arguments.

The constrained-link library exercises loss, duplication, reordering, corruption and interrupted contacts. It resumes from verified complete objects; persistent partial-fragment resumption and hardware-specific routing/framing are future work.

## Intended demonstration

Capture a collection on one node, transfer part over a live connection, carry the rest through physical media, and verify/restore the same exact snapshot on another node. Preserve competing offline versions, resume interrupted exchanges and keep a blind courier unable to decrypt the content.

Receiving bytes, verifying a restorable snapshot and obtaining a peer's storage receipt are distinct outcomes. Arc must name what was verified and what remains unknown; it cannot establish the globally latest version while disconnected or guarantee that another device will retain data forever.

## Original prototype

The original code, tests, build files and README are preserved unchanged on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), at commit `5f529a07af44b4fba02715aa0fa5a37eab06a11d`.

That branch contains the earlier Rust CLI and its historical claims and instructions. It is reference material for the redesign. There is no archive directory or legacy executable in this checkout.

Git history still contains the prototype. A shallow, single-branch clone of the desired redesign branch avoids fetching its old history; moving files to an archive branch does not erase existing Git objects.

## License

[MIT](LICENSE). The existing copyright notice and license text are retained unchanged.
