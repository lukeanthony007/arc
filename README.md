# Arc

Encrypted file storage and sync across your own devices, without a central server.

Arc keeps versioned, encrypted copies of your files and lets you exchange them between devices. It checks that received data is intact and that changes came from an authorized device. Files remain encrypted during transfer, including when carried on a drive.

The connection is separate from the security of the data. Devices can work offline and exchange changes later, without depending on a cloud storage provider or a continuous internet connection.

## What you can do

- **Keep file history.** Save versions of a folder and restore a chosen version into a new directory.
- **Work offline.** Preserve changes from multiple devices and explicitly merge them when they reconnect.
- **Control access.** Add devices with read or write access, remove members and rotate encryption keys.
- **Transfer encrypted data.** Exchange files directly over a network or export a bundle for offline delivery.
- **Resume interrupted transfers.** Keep partial progress across reconnects and receiver restarts.
- **Back up and recover.** Preserve the stored files, keys and access settings needed to recover a device.

Receiving data does not overwrite your working files or choose a version for you. Arc keeps conflicting versions available until you resolve them.

## How you would use it

Start with a folder and capture a version in Arc. Enroll another device, then exchange the encrypted data over a supported connection or through a transfer file. The receiving device verifies the data before you restore the version you want.

If both devices make changes while disconnected, neither version is discarded. Compare the changes, prepare the combined folder and record a merge.

A device can also carry encrypted data without having permission to read it. Transporting a collection and accessing its contents are separate operations.

## Current status

Arc is an experimental command-line application for Linux, written in Rust. Operations are manual: there is no desktop interface, automatic folder watching, background sync or peer discovery.

Offline transfer files and direct network exchange are implemented. A Linux Bluetooth adapter is also implemented, but over-the-air validation is pending. Radio and SMS are future transport options, not current features.

Local software checks cover capture, restore, device access, recovery and interrupted transfers. Physical two-device and power-loss testing remain pending. Formats are not stable, and the protocol has not received an independent security audit.

## Get started

Build from source on Linux with a recent Rust toolchain:

```sh
git clone --depth 1 --single-branch --branch master https://github.com/lukeanthony007/arc.git
cd arc
cargo build --locked
./target/debug/arc --help
```

Run `python3 tools/sprint_demo.py` after building for a disposable local walkthrough.

The [capture and restore guide](docs/experimental-profile.md) covers the basic workflow. The [device and sync guide](docs/device-and-sync-profile.md) covers adding devices, exchanging data and resolving offline changes.

## Access and recovery

Each private collection has an administrator who controls device access. Removing a device prevents access to future data encrypted with replacement keys once the updated policy is applied; it cannot erase files or keys the device already holds.

A transfer bundle is not a complete backup: it contains encrypted data and history, but no secret keys. Use Arc's recovery backup workflow to preserve both. Recovery restores the original device identity; enroll a new device when you want an additional independent copy.

See [recovery and backups](docs/reliability-and-carriers.md) for the procedures and limits.

## Further reading

- [Design](DESIGN.md): architecture and longer-term direction.
- [Security](docs/security.md): access rules, threat model and limitations.
- [Development and verification](docs/release-readiness.md): completed checks and outstanding validation.
- [Benchmarks](docs/benchmarks.md): measured storage and recovery behavior.

## License and history

[MIT](LICENSE). The original prototype is preserved on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype).
