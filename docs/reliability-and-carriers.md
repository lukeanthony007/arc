# Recovery, interrupted updates and carrier validation

This profile extends the experimental storage and [device/sync profile](device-and-sync-profile.md). It describes the new recovery container, journal repair and resumable exchange. It does not establish a stable protocol or a cryptographic audit.

The hardware portion is a runbook for two Linux machines. The user selected preparation of that runbook; physical two-device, USB and over-the-air Bluetooth validation have not been performed. Local process, socketpair, pseudoterminal and simulator checks must be reported separately.

## Complete recovery backups

```sh
arc recovery-export NODE BACKUP
arc recover NEW_NODE BACKUP --trust-genesis GENESIS_ID
```

Both commands prompt for the node's password. Authenticate and retain the genesis ID separately. A new `ARCRCV2` backup includes the node's immutable object inventory, the signed policy checkpoint and chain contained in that inventory, current and retained historical encrypted keys, and its member device key where applicable. The complete payload is authenticated and encrypted using Argon2id and XChaCha20-Poly1305. This differs from an `export` transfer bundle, which excludes secret keys.

The backup includes ciphertext already imported into that node, even if it is not currently authorized for publication. Having those bytes does not authorize them. Snapshots still undergo the ordinary signature, policy and content verification when used. A backup can only preserve objects and historical keys the node actually holds; it cannot repair preexisting missing objects or reconstruct keys never received.

Recovery validates the container and identities, builds a private sibling staging node, then publishes to a new destination without overwrite. It does not choose a working head. Use `history`, `verify --decrypt`, `restore` and then an explicit `select` if continuing work.

Recovery recreates the backed-up identity. Retire the original device before using the recovered identity to publish. A member backup retains that member's permissions, not the administrator's authority. A backup's policy is a dated trusted checkpoint, not proof that no later revocation exists: reconcile with a trusted current peer or administrator before publishing. Existing `ARCKEY1` kits remain readable; they contain keys only and require separately retained data bundles.

Backups omit transport identities, unfinished transfers and pending membership transactions. Keep network identity files separately or create and re-pin new ones. Export refuses a pending membership transition; repair it first. The encoded plaintext payload is limited to 64 MiB and 16,384 objects, including container overhead; memory use is several times the payload while encrypting or decoding. This is not a streaming large-archive format.

## Repair an interrupted membership update

```sh
arc repair NODE
```

New enable, grant, revocation and policy-application operations prepare an exact target before publishing it. A password-authenticated journal is durably written as `control/membership-pending` before changing active controls. It retains the intended signed policy objects, before/after control bytes and any outbound invitation or key package. The writer lock excludes concurrent local capture or membership changes.

Repair checks the password, pinned genesis and journal, refuses controls inconsistent with both recorded states, and completes the same prepared result. It does not generate another key rotation. An already published identical package is accepted; a conflicting file is preserved and blocks completion. Repair without a pending transaction is idempotent.

Legacy literal markers and signed-policy-fork guards do not contain a complete transaction and remain blocked. Repair never means deleting those guards. Preserve their node and evidence for investigation. Injected write-boundary failures exercise application-level recovery; they are not a complete filesystem, kernel or physical power-loss qualification.

## Resume incomplete objects

TCP and RFCOMM use a new experimental `arc-exp-2/fragment-sync` application profile inside the pinned Noise session. This changes live interoperability; both peers need this version. Immutable storage objects and offline bundles retain their existing formats.

For each requested object, the sender declares its ID and bounded size. The recipient requests only missing 4,096-byte fragments. Each complete authenticated message can be staged durably; after reconnecting and reauthenticating, a fresh receiver discovers that state on disk. An incomplete message is retransmitted. The recipient publishes and acknowledges an object only after its complete content digest matches and its immutable store write succeeds.

Partial states live under `incoming/fragments`, separate from keys and trusted controls. A receiver lock serializes writers. Limits are 128 partial objects, 32 MiB of retained encoded state, 16,384 fragments per object and the existing 1 MiB object ceiling; one bounded temporary rewrite can add transient overhead. Quotas cause explicit failure rather than evicting unrelated progress. Fragment checksums detect accidental disk damage but do not authenticate an untrusted sender. Final object verification remains required.

The simulator uses the same staging with a caller-selected payload MTU. Keep that MTU fixed while an object is incomplete. To intentionally reset a damaged or incompatible partial object:

```sh
arc partial-discard NODE OBJECT_ID
```

This removes only that object's unfinished state. It does not delete verified objects. Complete objects received through an offline bundle supersede their partial state and are reclaimed on the next receiver session. Byte reception, object durability, snapshot authorization, plaintext verification and selection of a working version remain distinct.

## Run the disposable local demonstration

From the repository, after building:

```sh
cargo build --locked
python3 tools/sprint_demo.py
```

The helper uses one host, independent device identities and temporary directories. It exercises enrollment, USB-style bundle files, offline branches, pinned loopback TCP exchange, explicit merge, revoked-writer rejection, full backup and exact old/current restore after key rotation. It removes its fixtures and stops its foreground listener even on failure. It does not access Bluetooth, a mounted USB drive or another computer.

The Rust tests separately inject membership write failures, interrupt live object exchange, reopen persistent fragments, and exercise raw pseudoterminal behavior. These are repeatable software checks, not a substitute for the following hardware procedure.

## Sprint verification record

The complete suite passed 62 tests across 11 executables, including 29 injected durable-operation boundaries across enable, grant, revoke and policy application. The test profile used `CARGO_PROFILE_TEST_OPT_LEVEL=2` to avoid unoptimized cryptographic code; assertions and the fixed Argon2id memory/work parameters were retained. Strict Clippy (`--all-targets --locked -- -D warnings`), formatting and the locked debug build passed.

Coverage includes exact historical/current restore after rotation, reader permissions after recovery, wrong password/genesis and modified backup rejection without publishing a destination, legacy keys-only compatibility, preserved untrusted/incomplete CAS evidence, stale journal rejection, receiver locking and aggregate quotas, damaged partials, short-contact convergence, interrupted authenticated live transfer with fragment reuse, wrong Noise pins, and raw pseudoterminal bytes, deadlines and terminal restoration.

The locked debug CLI completed the 33-operation disposable demonstration: independent identities, offline branches, pinned loopback exchange, explicit merge, rejection of late revoked-writer work, and exact old/current restores from one complete backup after rotation. The helper removed its temporary fixtures and stopped its listener. Fifty local Markdown links resolved and code fences were balanced.

Bounded source reviews found and led to fixes for journal output framing, backup enumeration of abandoned staging files, and duplicate fragments reseeding rejected assemblies. Integration checks also caught and corrected timeout rounding. These reviews and fault injections are not independent cryptographic or physical power-loss qualification.

Physical two-device, mounted-media and over-the-air Bluetooth acceptance remains pending by the user's selected runbook scope. No real personal collection, outside peer, paid carrier, pairing changes or persistent service was used.

## Two-device acceptance runbook

Use two Linux machines with the same Arc revision. Start with disposable directories on both. Verify genesis and full Noise public pins over a channel you trust; copying an unverified key from the same unknown peer does not establish identity. Record revision, OS, Bluetooth adapters, filesystem, elapsed times, byte counts, errors and exactly which steps passed. Keep passwords and private key files out of the result record.

Commands below use `arc` as shorthand. In each terminal, from that machine's repository checkout, build and define a session-local helper:

```sh
cargo build --locked
ARC_BINARY="$PWD/target/debug/arc"
arc() { "$ARC_BINARY" "$@"; }
```

Carry `ARC_A` or `ARC_B` into additional terminals on the corresponding machine; they must refer to the same disposable directories.

### 1. Establish independent identities

On machine A, the administrator:

```sh
ARC_A=$(mktemp -d)
mkdir "$ARC_A/source"
printf 'base\n' > "$ARC_A/source/note.txt"
arc init "$ARC_A/node"
arc enable-policy "$ARC_A/node"
arc network-identity "$ARC_A/network.key"
```

On machine B:

```sh
ARC_B=$(mktemp -d)
arc device-request "$ARC_B/writer.key" "$ARC_B/writer.req"
arc network-identity "$ARC_B/network.key"
```

Retain the printed genesis, writer signing public key and both transport public keys. Copy only B's public request to `$ARC_A/writer.req`, review its identity, then run on A:

```sh
arc grant "$ARC_A/node" "$ARC_A/writer.req" "$ARC_A/invitation" writer
```

Copy the invitation to `$ARC_B/invitation`. On B, substitute A's independently authenticated genesis ID:

```sh
arc join "$ARC_B/node" "$ARC_B/writer.key" "$ARC_B/invitation" --trust-genesis GENESIS_ID
```

### 2. Carry a base through actual removable media

On A:

```sh
arc capture "$ARC_A/node" "$ARC_A/source"
arc export "$ARC_A/node" BASE_SNAPSHOT_ID "$ARC_A/base.arc"
```

Copy `base.arc` through an actual mounted drive to `$ARC_B/base.arc`, using your chosen mount path. On B:

```sh
arc import "$ARC_B/node" "$ARC_B/base.arc"
arc verify "$ARC_B/node" BASE_SNAPSHOT_ID --decrypt
arc restore "$ARC_B/node" BASE_SNAPSHOT_ID "$ARC_B/source"
arc select "$ARC_B/node" BASE_SNAPSHOT_ID
```

Compare restored file bytes with A's originals independently. Record successful verified restore separately from successful file copying.

### 3. Diverge offline, then exchange over a real LAN

Disconnect the machines from one another. On A, change `source/note.txt` and capture a version; record `HEAD_A`. On B, make a different change and capture `HEAD_B`. Reconnect only when both snapshots exist.

On B, replace `B_LOCAL_IP` and `A_TRANSPORT_PUBLIC_KEY`:

```sh
arc serve-once "$ARC_B/node" B_LOCAL_IP:9090 "$ARC_B/network.key" A_TRANSPORT_PUBLIC_KEY
```

On A:

```sh
arc sync "$ARC_A/node" B_LOCAL_IP:9090 "$ARC_A/network.key" B_TRANSPORT_PUBLIC_KEY
arc history "$ARC_A/node"
arc diff "$ARC_A/node" HEAD_A HEAD_B
```

Confirm that both heads remain and receiving data did not silently select a different base. Prepare `$ARC_A/resolved` with the exact chosen result, then:

```sh
arc merge "$ARC_A/node" "$ARC_A/resolved" --parents HEAD_A HEAD_B
```

Record the merge ID and retain both inputs. Arc does not choose the file-level resolution for you.

### 4. Prepare an explicit Bluetooth RFCOMM connection

This adapter uses Linux Bluetooth Classic RFCOMM, not BLE GATT. Both machines need compatible controllers, a prepared paired connection, kernel RFCOMM support and permission to open the chosen character device. BlueZ's optional `rfcomm` utility is not installed or configured by Arc. Do not change unrelated pairings or release all device bindings.

Prepare pairing using your OS tools. For a direct channel-1 test, BlueZ documents these foreground setup commands; privilege and package availability depend on the distribution. Choose unused endpoint numbers and a free channel:

On B, in a separate terminal:

```sh
rfcomm -r -A -E listen /dev/rfcomm0 1
```

On A, replace B's Bluetooth address and keep the command running:

```sh
rfcomm -r -A -E connect /dev/rfcomm0 B_BLUETOOTH_ADDRESS 1
```

[BlueZ rfcomm reference](https://man.archlinux.org/man/rfcomm.1.en). This is an operator-run example, not evidence these controllers were qualified. Verify `rfcomm show /dev/rfcomm0` and access to the connected endpoint on each machine before starting Arc. `bind` alone is not proof that a connection is established. OS pairing does not replace Arc's Noise pins.

In another terminal on B:

```sh
arc bluetooth-sync "$ARC_B/node" /dev/rfcomm0 "$ARC_B/network.key" A_TRANSPORT_PUBLIC_KEY --respond
```

Then on A:

```sh
arc bluetooth-sync "$ARC_A/node" /dev/rfcomm0 "$ARC_A/network.key" B_TRANSPORT_PUBLIC_KEY
```

The `--respond` flag selects the Noise role, independently of which OS opened the physical Bluetooth connection. Arc accepts only direct `/dev/rfcommN` character paths, applies raw terminal settings, and restores them on ordinary return or error. A session has an absolute 20-second budget; rerun after an interruption or timeout. Forced process death can prevent terminal-setting restoration, so recreate the scoped connection before reuse. Arc does not discover peers, pair devices, advertise a service or power radios on.

For resumption, add enough new disposable data that an object is still in flight, interrupt the connection, and reconnect with a fresh RFCOMM byte stream. Repeat the same commands. Record nonzero `fragments_reused` on the sending side and exact restore on B; a successful retry with only complete objects skipped does not prove partial-object resumption. A mismatched Noise pin must fail before inventories are disclosed. Confirm the imported merge with `verify --decrypt` and restore to a new directory before selecting it.

### 5. Revoke and recover without the original device

On A, revoke B's signing public key and capture the current resolved directory under the new key:

```sh
arc revoke "$ARC_A/node" B_SIGNING_PUBLIC_KEY "$ARC_A/rotation"
arc capture "$ARC_A/node" "$ARC_A/resolved"
arc recovery-export "$ARC_A/node" "$ARC_A/recovery.arc"
```

After revocation, create a late snapshot on still-offline B. Carry its export back to A. Import may retain its ciphertext, but A must reject it as an authorized current snapshot when verified. A disconnected B cannot discover revocation on its own.

Stop using A's original identity. Securely carry the complete recovery backup to a fresh machine or fresh storage location, retain the independently authenticated genesis, and run:

```sh
arc recover NEW_NODE RECOVERY_BACKUP --trust-genesis GENESIS_ID
arc verify NEW_NODE PRE_ROTATION_MERGE_ID --decrypt
arc verify NEW_NODE POST_ROTATION_SNAPSHOT_ID --decrypt
arc restore NEW_NODE PRE_ROTATION_MERGE_ID NEW_OLD_DESTINATION
arc restore NEW_NODE POST_ROTATION_SNAPSHOT_ID NEW_CURRENT_DESTINATION
```

Compare both restored trees exactly with the recorded originals. Use wrong-password, wrong-genesis and modified-backup attempts with separate unused destinations: they must fail without publishing a destination node. Do not continue publishing from both the original and recovered administrator. Update current policy from an independently trusted source before treating an older backup as current.

### Record the result honestly

A complete hardware record needs actual evidence for USB carriage, separate hosts, LAN transfer, over-the-air Bluetooth, interrupted-fragment reuse, denied wrong pins, revocation and exact recovery. If a step cannot run, record its blocker rather than substituting loopback or simulation. End only the foreground processes and endpoint bindings created for this exercise; preserve unrelated radio state. Hardware validation, production deployment and independent security review remain separate milestones.
