# Arc

Decentralized encrypted file storage and verifiable sync, written in Rust.

Arc separates data security from transport. Nodes store encrypted snapshots and verify their integrity, history and authorization without a central storage server. Data can travel through a live connection or offline media.

**Experimental.** Linux CLI; unstable formats; no independent security audit. Physical two-device, over-the-air Bluetooth and power-loss validation remain pending.

## Capabilities

- Encrypted snapshots, integrity verification and exact restore.
- Version history, offline branches and explicit merges.
- Encrypted chunk reuse under the same content key.
- Independent reader/writer devices, signed membership policies, revocation and key rotation.
- Offline bundles, authenticated TCP and a Linux Bluetooth RFCOMM adapter.
- Persistent transfer fragments across reconnects and receiver restarts.
- Streaming recovery backups and journaled membership repair.
- Read-only `status` and `doctor` diagnostics.

Importing data does not change membership, select a version or overwrite working files. Each private collection has an administrator; storage and exchange require no central server.

## Build

Requires Linux with `openat2`, `renameat2` and `/proc`, Rust with edition 2024 and `File::try_lock` support, and a filesystem supporting hard links and directory flushing.

```sh
git clone --depth 1 --single-branch --branch master https://github.com/lukeanthony007/arc.git
cd arc
cargo build --locked
./target/debug/arc --help
```

Run `python3 tools/sprint_demo.py` after building for a disposable local walkthrough. See the [base implementation guide](docs/experimental-profile.md) for capture, verification and restore, and the [device and sync guide](docs/device-and-sync-profile.md) for enrollment and exchange.

## Constraints

- CLI-driven operations. No folder watching, background sync or peer discovery.
- Bluetooth requires a prepared `/dev/rfcommN` endpoint. Radio and SMS adapters are not implemented.
- Access is collection-wide. Revocation cannot erase previously acquired keys or plaintext.
- Offline nodes cannot establish global freshness.
- Transfer bundles exclude secret keys and are not recovery backups. Recovery restores the same device identity; enrollment creates an independent device.
- Streaming backups allow up to 16 GiB encoded data and 1,000,000 objects. Individual objects are limited to 1 MiB; capture, history and exchange have separate, smaller bounds.

## Documentation

- [Architecture](DESIGN.md): design, trust boundaries and planned capabilities.
- [Security](docs/security.md): authorization, keys, recovery and metadata limits.
- [Recovery and carriers](docs/reliability-and-carriers.md): backups, repair, resumable transfers and hardware validation.
- [Verification record](docs/release-readiness.md#readiness-verification-record): completed local software checks and remaining validation.
- [Benchmarks](docs/benchmarks.md): measured storage, memory and recovery behavior.

Implementation guides describe current behavior. Architecture documents also include unimplemented goals.

## License and history

[MIT](LICENSE). The previous prototype is preserved on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), outside the current source tree.
