# Arc

Arc is being redesigned as decentralized encrypted storage with verifiable synchronization independent of how the data travels.

A collection should remain usable on one device, across invited peers, or through optional storage and relay nodes. Data can move over live networks or disconnected carriers such as removable media. Bluetooth, radio and SMS are intended adapter targets with their own capacity and platform limits.

The new Rust core implements an experimental first slice: encrypted directory snapshots, signed records, exact verification/restore, offline bundles and separately password-protected recovery keys. The [implemented profile](docs/experimental-profile.md) defines its limits and exact encodings. It is not an audited or stable protocol; use disposable data.

## Design review

Start with [the architecture](DESIGN.md). The review draft covers:

- [Data and synchronization](docs/data-and-sync.md): immutable encrypted objects, snapshots, conflicts, epoch transitions, live reconciliation and offline packages.
- [Security and keys](docs/security.md): threat model, membership, encryption candidates, recovery, revocation and metadata limits.
- [Operations and validation](docs/operations-and-validation.md): safe capture/restore, durable storage, retention, interface behavior and acceptance scenarios.
- [Decisions and sources](docs/decisions-and-sources.md): proposed choices, alternatives, primary research and unresolved implementation gates.

The architecture targets private invited collections, an offline-capable membership authority, multiple independent writers and explicit conflict resolution. The current `arc-exp-1` implementation is narrower: one root/device, foreground local operations and offline file exchange. Membership changes, revocation, live networking and multi-writer resolution are not implemented.

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

## Intended demonstration

Capture a collection on one node, transfer part over a live connection, carry the rest through physical media, and verify/restore the same exact snapshot on another node. Preserve competing offline versions, resume interrupted exchanges and keep a blind courier unable to decrypt the content.

Receiving bytes, verifying a restorable snapshot and obtaining a peer's storage receipt are distinct outcomes. Arc must name what was verified and what remains unknown; it cannot establish the globally latest version while disconnected or guarantee that another device will retain data forever.

## Original prototype

The original code, tests, build files and README are preserved unchanged on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), at commit `5f529a07af44b4fba02715aa0fa5a37eab06a11d`.

That branch contains the earlier Rust CLI and its historical claims and instructions. It is reference material for the redesign. There is no archive directory or legacy executable in this checkout.

Git history still contains the prototype. A shallow, single-branch clone of the desired redesign branch avoids fetching its old history; moving files to an archive branch does not erase existing Git objects.

## License

[MIT](LICENSE). The existing copyright notice and license text are retained unchanged.
