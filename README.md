# Arc

Arc is being redesigned as decentralized encrypted storage with verifiable synchronization independent of how the data travels.

A collection should remain usable on one device, across invited peers, or through optional storage and relay nodes. Data can move over live networks or disconnected carriers such as removable media. Bluetooth, radio and SMS are intended adapter targets with their own capacity and platform limits.

This repository currently contains design documents, not a new executable implementation. The original Rust prototype is preserved separately. No new security guarantee, working carrier integration or production readiness is claimed.

## Design review

Start with [the architecture](DESIGN.md). The review draft covers:

- [Data and synchronization](docs/data-and-sync.md): immutable encrypted objects, snapshots, conflicts, epoch transitions, live reconciliation and offline packages.
- [Security and keys](docs/security.md): threat model, membership, encryption candidates, recovery, revocation and metadata limits.
- [Operations and validation](docs/operations-and-validation.md): safe capture/restore, durable storage, retention, interface behavior and acceptance scenarios.
- [Decisions and sources](docs/decisions-and-sources.md): proposed choices, alternatives, primary research and unresolved implementation gates.

The proposed first profile uses private invited collections, an offline-capable membership authority, multiple independent writers and explicit conflict resolution. Storage and delivery have no mandatory central service. These are recommendations for review, not adopted user decisions.

Implementation waits for design approval and completion of the exact protocol, cryptographic, dependency and recovery specifications. The architecture does not depend on Luma, an AI model, a blockchain or a particular transport provider.

## Intended demonstration

Capture a collection on one node, transfer part over a live connection, carry the rest through physical media, and verify/restore the same exact snapshot on another node. Preserve competing offline versions, resume interrupted exchanges and keep a blind courier unable to decrypt the content.

Receiving bytes, verifying a restorable snapshot and obtaining a peer's storage receipt are distinct outcomes. Arc must name what was verified and what remains unknown; it cannot establish the globally latest version while disconnected or guarantee that another device will retain data forever.

## Original prototype

The original code, tests, build files and README are preserved unchanged on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), at commit `5f529a07af44b4fba02715aa0fa5a37eab06a11d`.

That branch contains the earlier Rust CLI and its historical claims and instructions. It is reference material for the redesign. There is no archive directory or legacy executable in this checkout.

Git history still contains the prototype. A shallow, single-branch clone of the desired redesign branch avoids fetching its old history; moving files to an archive branch does not erase existing Git objects.

## License

[MIT](LICENSE). The existing copyright notice and license text are retained unchanged.
