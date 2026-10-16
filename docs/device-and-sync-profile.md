# Experimental history, devices and live synchronization

This extension continues the experimental `arc-exp-1` core. The unchanged single-root object format is described in [the original profile](experimental-profile.md); this document describes the added operations and their limits. Stable interoperability and qualified independent cryptographic review remain open. The [five milestone contract](next-milestones.md) supplies acceptance criteria; actual verification belongs in the implementation handoff.

The subsequent [recovery and carrier profile](reliability-and-carriers.md) extends this implementation with authenticated complete backups, explicit journal repair, persistent fragments and Linux RFCOMM endpoints. It defines the new live application profile and the pending hardware qualification.

## History, selection, reuse and conflicts

`history NODE` lists locally authorized version descriptors and their parents, selected base and head status. Head discovery uses descriptor ancestry independently of retained file payloads. A head is relative to the records and policy known locally, not a globally newest version. Missing or rejected versions are not silently promoted.

`diff NODE OLD NEW` decrypts and validates both selected manifests and reports added, removed and modified paths by logical content/type. It does not treat randomized encryption or a different entry ID alone as a content edit. `select NODE SNAPSHOT` deliberately changes the working base under the same writer lock used by capture. It leaves competing versions intact.

Capture compares authenticated old blocks at the same file offset and reuses exact immutable ciphertext only when bytes and the content key match. The manifest remains freshly encrypted. After a key rotation, the next capture encrypts all selected content under the fresh key instead of reusing old ciphertext. This is not global plaintext deduplication or content-defined chunking; an inserted byte can change subsequent fixed-size blocks.

`merge NODE RESOLVED_DIRECTORY --parents HEAD_A HEAD_B` captures the user's explicit chosen result with all named parents. Arc validates the inputs; it does not automatically merge arbitrary file contents. Independent offline branches remain available until the user resolves them. Existing retention rules still apply; no automatic destructive pruning is added.

## Device lifecycle and authority

The administrator retains the genesis-root signing key. An enrolled device has independently random Ed25519 signing and X25519 envelope private keys protected in a versioned Argon2id/XChaCha20-Poly1305 container. A public request binds both public keys with the device's signature. A request proves possession, not the real-world identity of its holder; the administrator reviews the supplied request before granting access.

The lifecycle commands are:

1. `enable-policy NODE` activates root-signed membership rules on the administrator's collection.
2. `device-request PRIVATE_KEY_FILE PUBLIC_REQUEST_FILE` generates an independent device identity.
3. `grant ADMIN_NODE REQUEST_FILE INVITATION_FILE reader|writer` creates a recipient-bound invitation and advances signed membership.
4. `join NEW_NODE PRIVATE_KEY_FILE INVITATION_FILE --trust-genesis GENESIS_ID` verifies the independently supplied genesis pin, complete policy chain and invitation before creating the member node.
5. `refresh ADMIN_NODE PACKAGE --requests REQUEST_FILE` distributes current-policy key envelopes to existing active members after another member is added. Repeat `--requests` for multiple requests.
6. `revoke ADMIN_NODE DEVICE_PUBLIC_KEY PACKAGE --requests REMAINING_REQUEST` removes a member, creates fresh content-key material and envelopes for remaining devices. Keep the public requests needed for distribution.
7. `apply-policy MEMBER_NODE PRIVATE_KEY_FILE PACKAGE` applies that member's authenticated successor policy/key envelope.

All password-requiring commands use the existing terminal prompt or explicit `--password-stdin`; no private key or password belongs in an argument. The device key file and member-node key file currently use the same supplied password. Public requests can be copied openly; private device files and recovery material stay private.

Policies bind the collection, root authority, sequential epoch, predecessor policy ID, device signing keys/reader-writer rights and an explicit accepted historical snapshot set. Each new policy-managed snapshot additionally has a device-signed attestation binding its exact ID to the policy and epoch. A reader has content keys but cannot publish an accepted snapshot. Merely knowing a transport key or importing a CAS object does not grant collection membership.

Invitations and rotation envelopes use RFC 9180 HPKE with X25519/HKDF-SHA256/ChaCha20-Poly1305. Root signatures bind recipient, collection/genesis, policy, epoch, role, encapsulation and ciphertext. Invitations do not contain the administrator's signing seed. The packet contains the genesis record and signed policy chain required for explicit enrollment. Key wrapping and signatures have different purposes: HPKE base mode alone does not identify the administrator.

A grant shares the currently authorized content key, including any historical ciphertext that key can decrypt. Grants do not automatically rotate every existing object or provide per-directory read restrictions. Explicit revocation rotates the content key. Past keys and plaintext cannot be erased from a removed member. A disconnected node cannot know about a revocation it has not received.

Known policy determines which old snapshots remain accepted. Late revoked-device work outside the fixed accepted set stays stored but cannot become an authorized current version. Root-signed policy forks fail closed with retained evidence. An already authenticated network connection does not bypass these checks.

Version-two refresh/rotation packages carry the complete ordered, root-signed policy chain. A member that missed several updates verifies that chain back to its current trusted checkpoint before applying the recipient envelope. Authentic historical replays reject without changing the node; a conflicting signed chain retains evidence and fails closed. Joining a new node with a current invitation is a separate enrollment operation. Refresh lets still-active writers learn the current policy after another grant.

## Rotation, historical keys and incomplete transitions

Previously held password-protected keys are indexed by verified policy IDs and retained separately from the current key. Verification, restore and diff can use an available historical key for an accepted snapshot. Catch-up does not manufacture intermediate epoch keys a device never received. New capture encrypts with the active key; the key comparison explicitly prevents cross-epoch ciphertext reuse. Newly admitted members receive only what their invitation grants; no administrator key archive is copied into the invitation.

Rotation changes policy and key state locally, then recipients apply their own envelopes through any carrier. It is not an atomic change across disconnected devices. A fresh current-state capture may be needed before a newly keyed member can restore current content. `recovery-export` now produces a complete authenticated backup including retained objects, policy state and keys; legacy root-only kits remain readable. See the [recovery format and limitations](reliability-and-carriers.md#complete-recovery-backups).

Membership operations use an exclusive local writer lock. New transitions prepare their exact target and store a password-authenticated journal in `membership-pending` before publishing it. `repair NODE` completes a valid interrupted transaction without generating another key rotation. Unknown legacy markers and signed-policy forks remain blocked for investigation; never delete those guards to force publication. Fault-injection checks are not full power-loss qualification.

## Explicit live synchronization

`network-identity KEY_FILE` creates a separate password-protected Noise static identity and prints only its public key. `serve-once NODE ADDRESS IDENTITY_FILE PINNED_PEER_PUBLIC_KEY` binds an explicit foreground listener for one exchange. `sync NODE ADDRESS IDENTITY_FILE PINNED_PEER_PUBLIC_KEY` connects to that explicit peer. Neither installs a service, discovers strangers, opens a provider account or sends paid carrier traffic.

The connection uses Noise XX with X25519/ChaChaPoly/BLAKE2s and compares the full expected peer static key before encrypted object inventories. Transport pins are currently explicit and separate from collection enrollment; no automatic policy-derived transport certification is claimed. Only opaque immutable objects are exchanged. Private key/control files and selected-head pointers are excluded.

Inventory reconciliation requests missing IDs. Repeating a completed exchange sends no already present objects. The new live profile persists complete 4,096-byte object fragments between contacts and requests only missing fragments after reauthentication. An incomplete encrypted message is retransmitted; an object is published and acknowledged only after full digest verification and durable storage. No automatic head or membership-policy promotion occurs.

Application messages are segmented below Noise's per-message size limit, with bounded reassembly. The roles take ordered sending/receiving turns to avoid both peers blocking while sending bulk data. Inventory/object counts, aggregate bytes, frame sizes, connection and I/O waits are bounded. Large inventory and bidirectional object tests are required; small-message success alone is insufficient.

The first CLI scope is the node's opaque object inventory, potentially including unrelated ciphertext previously imported into that node. The user chooses the node and peer explicitly. Collection-filtered selection and automatic scheduling are future improvements; a transport pin is permission for that explicit transfer, not permission to read plaintext.

## Constrained contacts

The constrained-link library models payload MTU, deterministic losses, duplicates, reordering, corruption and interrupted contacts. It shares persistent fragment staging with live exchange and publishes only complete digest-verified objects into the same CAS. It enforces finite object/byte budgets. Complete objects delivered through offline bundles supersede incomplete state on the next receiver session.

MTU in this simulator is payload-only; it does not include a real radio/SMS header. Keep it fixed for a partial object or explicitly discard that partial before changing it. Link discovery, routing, battery/airtime behavior and real radio/SMS adapters remain outside the simulation. The separate Linux RFCOMM adapter has implementation checks and a [hardware runbook](reliability-and-carriers.md#two-device-acceptance-runbook); over-the-air behavior and delivery guarantees remain unqualified.

## Verification and remaining limits

The following record describes the earlier five-milestone implementation. The subsequent recovery/resumption sprint has a separate [profile and reproducible demonstration](reliability-and-carriers.md).

On Linux with Rust/Cargo 1.99.0, strict Clippy passed and the full suite passed 35 tests across six test executables. After adding the final envelope-count guard, the complete device lifecycle regression passed again; formatting, strict Clippy and the CLI binary build also passed on that final source.

The checks cover legacy offline recovery, same-key chunk reuse and logical identity retention, one-block changes, two offline heads and explicit merge, incomplete-ancestry head rejection, independently enrolled writers, reader publication denial, writer-lock contention, revocation, fresh content-key isolation, historical-key retention across repeated rotations, full-chain catch-up, replay rejection without quarantine and oversized envelope-count rejection. Live tests cover pinned-peer mismatch, large bidirectional objects, inventories larger than one Noise message, missing-object/no-op reconciliation, bounded requests and encrypted identity files. Constrained tests cover loss, reordering, duplication, corruption, interruption and resumption alongside offline bundles.

Separate source reviews examined the authority and transport integration. Their concrete findings were incorporated: invitation wire/signature separation, shared capture/transition locking, replay-versus-fork handling, payload-independent ancestry validation before head reduction, complementary inventory/request ordering, relative identity paths and bounded requested-object scope. A follow-up review of chain catch-up led to restoring the envelope-count bound before verification. These were bounded reviews of this integration, not an independent cryptographic audit or production certification.

At that checkpoint, policy-aware recovery export, repair and persistent fragments were still open. Those software gaps are addressed by the subsequent profile; physical carrier validation, independent security review and power-loss qualification remain open. No real personal collection, paid carrier, external peer or production deployment was exercised in that earlier verification.

A separate 27-operation CLI exercise created an administrator and independently keyed writer, imported and selected a base, created two offline heads, synchronized over a pinned loopback Noise connection, explicitly merged them, revoked the writer, rejected a late revoked-device snapshot and restored retained history exactly after key rotation. Disposable binary and text fixtures were compared and removed. No outside peer or real personal collection was used.
