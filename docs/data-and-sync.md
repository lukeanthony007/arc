# Data, versions and exchange

Part of the [Arc design review draft](../DESIGN.md). All choices below are proposed. This describes semantic records and algorithms; it is not a frozen byte-level wire specification. Gates W1–W5 in [the decision register](decisions-and-sources.md) must be closed before implementation.

## 1. Identifiers and canonical records

Use immutable objects. An object identifier is a domain-separated cryptographic digest of its complete canonical encoded bytes, including its type, format/profile version, collection identifier and epoch where applicable. The proposed digest is SHA-256. Exact domain strings, length framing and type codes belong in the frozen profile; concatenating variable strings without unambiguous framing is forbidden.

A signed record has a canonical unsigned body and a signature over a distinct domain plus that body. The immutable record ID hashes the complete signed encoding. Do not include the record's own ID in its signed body. Every reference uses the exact ID, never a display name, filesystem path or timestamp. The verifier checks the requested ID before acting on a decoded record. Changing a signature, header, payload or reference creates a different object.

Proposed encoding: a restricted deterministic CBOR profile based on RFC 8949, using explicit record schemas and integer field tags. Reject duplicate fields, unknown mandatory fields, indefinite-length items, nonminimal encodings, floats, unapproved tags and values outside declared bounds. The profile must define treatment of optional extensions and canonical map ordering. A generic CBOR decoder accepting a value is insufficient for signature verification. Signed bytes must have one accepted representation.

A collection ID and logical entry IDs are independently random 256-bit values. They are not content hashes and do not encode a user, machine or filename. File-entry identity survives rename and revision; copying a file as a new logical entry generates a new entry ID. The collection ID is bound to the root key through genesis and verified enrollment.

## 2. Semantic object model

| Record | Required semantic fields | Visibility and role |
| --- | --- | --- |
| Genesis policy | Version/profile, collection ID, root verification key, epoch zero, initial device records/rights, initial epoch-key commitment, root signature | Public to admitted peers; establishes the pinned collection |
| Policy transition | Collection, predecessor policy ID, sequential epoch, replacement membership set, accepted preceding-epoch frontier, new key commitment, root signature | Public authority chain; no secret keys |
| Device record | Signing key, recipient encryption key, live-session public key, device label reference, version | Key binding is authorized by policy; labels need not be public |
| Epoch-key envelope | Collection, policy/epoch, recipient device, suite, encapsulation, wrapped secret, authorized signature | Recipient decrypts; sender authorization and context must verify |
| Snapshot descriptor | Collection, policy ID, epoch, writer, sorted distinct parent IDs, public closure-index root, encrypted manifest-root ID, snapshot kind, optional author-claimed time, signature | Signed immutable version; clock time never decides precedence |
| Closure-index page | Collection/epoch, level, sorted unique object IDs with type and encoded length, or child-page references | Public authenticated inventory of a snapshot's encrypted tree/content |
| Encrypted manifest page | Public type/collection/epoch/suite/salt/nonce framing; encrypted manifest structure and AEAD tag | Authorized readers see paths, entry IDs and file relationships |
| Encrypted content chunk | Public type/collection/epoch/suite/salt/nonce framing; ciphertext and AEAD tag | Exact file bytes are confidential |
| Export/request/receipt record | Collection, signer, explicit policy checkpoint and scope/root IDs, request nonce when relevant, claimed observation/retention, signature | A transfer claim; does not change content or membership |

The descriptor authenticates its closure-index root and encrypted manifest root. Closure pages form a bounded Merkle tree. A blind storage node can enumerate the required ciphertext IDs and lengths without decrypting file paths; a reader additionally checks that the decrypted manifest's referenced objects equal the declared content closure. This explicit public inventory is necessary: an encrypted manifest alone cannot let a blind node independently prove that it possesses all required chunks.

The closure inventory contains the encrypted manifest pages and content chunks, with no duplicate IDs. Its own index pages are reached from the root and validated separately. It excludes the snapshot descriptor, policy records, key envelopes and historical parent closures; each is tracked as its own dependency category. This avoids a cyclic content hash and separates snapshot bytes from history. Unexpected extra objects are not implicitly pinned or admitted merely because they arrived in the same package.

### Manifest and content representation

A manifest describes one complete logical tree. Each entry contains its stable ID, parent directory ID, UTF-8 name, type, supported metadata and, for regular files, byte length, a plaintext file digest inside the encrypted manifest, and an ordered list/tree of content references with plaintext lengths. File descriptors can span authenticated encrypted pages. Directories have stable IDs; the root is a distinguished entry. Entry IDs and resolved paths must be unique, the parent graph must be acyclic, and all entries must be reachable from the root. A zero-length file has an empty content list and the digest of empty bytes. Plaintext digests are never public object IDs.

The first profile captures regular files/directories only. Unsupported names or filesystem types are reported, not silently renamed or skipped. Store exact UTF-8 name bytes; define bytewise comparison for the logical tree. Restore separately detects case-folding, normalization and reserved-name collisions on the destination. File timestamps are captured metadata, not trusted evidence. No ACL, owner, xattr, hardlink or executable-behavior preservation claim is made until individually specified. Symlink support is deferred.

Initial chunking is fixed-size, proposed 64 KiB plaintext chunks with a final short chunk; manifest pages also have bounded size. This is simple and limits retransmission loss. It is not optimized for inserted bytes in large files; content-defined chunking is a future profile candidate. Each new encrypted object gets fresh key/nonce material as defined by the crypto profile. Reusing an existing object means reusing the exact immutable ciphertext, never re-encrypting different plaintext with a reused nonce.

Reuse is restricted to the same collection and epoch. Do not expose a public plaintext-content hash or cross-collection deduplication oracle. A local plaintext fingerprint cache used to find reusable chunks is sensitive state and must be encrypted or rebuilt while unlocked. Two independent devices encrypting equal bytes may produce different object IDs; that is expected.

## 3. Snapshots, ancestry and conflicts

Ordinary snapshots name one or more parent snapshots from the active epoch. The first snapshot in epoch zero may have no parent. Other parentless snapshots are invalid. An explicit transition snapshot is the only way to cross epochs, as specified below. Every parent must belong to the collection and precede the child in an acyclic dependency graph.

A writer captures against a named base. If several current heads exist, the interface must show them: it may preserve a branch and create a child of the selected head, or explicitly resolve selected heads and name them all as parents. It must not silently label an unresolved tree as a merge. A malicious authorized writer can still publish misleading content; signatures authenticate that decision, not its honesty.

Eligible heads are accepted snapshots with no accepted descendant in the currently known validated DAG. Unknown ancestry yields an unresolved candidate, not a proven head reduction. With equal validated records and policy checkpoint, peers must derive the same accepted heads regardless of delivery order. There is no universal latest head and no automatic tie-break by clock, signer or hash.

Concurrent snapshots remain distinct even if their file trees happen to match. A merge is a new full snapshot naming the heads being resolved and recording the user's chosen result. File edits, rename/delete conflicts and competing changes to the same path all require explicit resolution in the first profile. The data plane never guesses a semantic merge.

Deletion is absence from the newer complete tree, interpreted against its parents. No separate indefinitely growing tombstone log is needed for this snapshot model. Historical trees and their parent graph preserve evidence of prior presence. A stale snapshot cannot be overlaid as a file-level patch: it remains an older version or concurrent branch. History pruning must not remove the ancestry needed to distinguish these states. Restoring an older version into a new published version is an explicit new snapshot, not a rollback of the DAG.

## 4. Policy transitions and offline revocation

Policy epochs advance linearly and include a fixed preceding-epoch accepted frontier F: a bounded set of old-epoch snapshot IDs. The accepted set from that epoch consists of F and its transitive snapshot ancestors, subject to the earlier policies' own fences. The root authority must validate F before signing. An empty frontier explicitly accepts no old snapshots; the interface must make that consequence clear.

The proposed frontier ceiling is 64 heads. If the selected accepted frontier exceeds it, routine rotation is blocked: the user must explicitly resolve enough branches beforehand or deliberately exclude named heads into preserved quarantine. There is no automatic head dropping or synthetic merge that pretends divergent trees were resolved. Exclusion is visible in the signed frontier and preflight report. The ceiling itself remains a design-review choice.

On learning a valid successor policy, every replica applies the same fence. Old-epoch records outside that closure cease to be eligible for current promotion even if they arrived earlier or were formerly local heads. Preserve them as quarantined versions and preserve all pending user work. Missing ancestry means acceptance is unresolved until the needed descriptors/proofs arrive; it is never inferred from a timestamp or a peer's assertion.

Stop advertising newly fenced records as current and invalidate derived current-state summaries, while preserving the original signed records and checkpoint-scoped receipts as historical evidence. Send the newer policy before resuming current-head advertisements. A prior restore cannot be recalled: notify local consumers that its authorization classification changed, without modifying their restored files. Never reinterpret an old receipt as a claim under the new policy.

A transition snapshot in the new epoch binds the new policy and names exactly one member of F as its source parent. It reproduces that source tree with all reachable manifest and content objects encrypted under the new epoch. If F has several heads, prepare one transition snapshot for each, preserving the disagreement. A later explicit merge can reconcile them. For an empty F, a distinct epoch-start snapshot has an empty tree and no data parents. The wire profile must distinguish epoch-start, transition and ordinary snapshots.

Only a current authorized writer with the needed source plaintext/keys may produce these transition snapshots. Policy publication does not imply data migration has finished. Revocation becomes known locally as soon as policy validates; new content publication waits for a complete new-epoch baseline. If none of the remaining authorized devices can decrypt an accepted head, report that baseline as unavailable; do not invent a substitute or silently exclude it.

Routine rotation preflight must establish a migration writer, old keys, complete source closures and storage capacity for every retained head; otherwise it is blocked before signing. An explicitly chosen emergency revocation may publish the fence despite an unavailable baseline, but must display the resulting blocked new-epoch publication/recovery state. Never fall back to publishing new work under the revoked epoch to hide that interruption.

The recommendation is to apply this complete current-state re-encryption on every membership/key-epoch transition for uniform semantics. It costs bandwidth and storage but avoids making new-epoch restoration depend on old epoch keys. Historic snapshots keep their old ciphertext and keys; historical access must be granted explicitly. Past recipients may retain all previously disclosed data.

After transition, an authorized writer may review a quarantined version and reissue selected changes on a valid new-epoch base. Reference the old record as provenance, not as an ordinary causal parent that bypasses the fence. The new writer takes responsibility through a new signature. There is no automatic replay of revoked writers' work.

Two different policy successors of the same predecessor are an authority fork, not a content conflict. Stop policy-dependent promotion beyond the last common policy, retain both branches and report the fork. The first profile has no automatic policy-fork resolution; re-establish trust through an authenticated migration to a new collection. Ordinary object intake can continue into bounded quarantine. See [security](security.md).

## 5. Validation and local state

Do not implement a single overloaded synced/valid state. Track independent axes so a blind durable replica is possible without decryption.

| Axis | States and interpretation |
| --- | --- |
| Intake | Absent, partial, complete bytes, malformed/rejected |
| Byte integrity | Unchecked, canonical/digest verified, failed |
| Authority | Unknown dependencies, authorized under named policy, fenced/quarantined, policy fork, invalid |
| Closure | Missing index, partial ciphertext closure, ciphertext closure complete |
| Plaintext | Locked/missing key, authentication failed, schema invalid, selected tree materializable |
| Persistence | Staged, locally committed under durability contract, rechecked after reopen |
| History | Missing descriptors, ancestry verified through named roots, retained payload history complete for named scope |

The public closure lets a blind node claim exact ciphertext coverage; it cannot claim valid plaintext or truthful authorship metadata. An authorized reader must authenticate all referenced encrypted objects and check the decrypted manifest against the public inventory before claiming a complete restorable snapshot.

A user may materialize a cryptographically valid selected snapshot with incomplete ancestry, provided the interface explicitly labels authorization/ancestry as unresolved and the user opts into an isolated inspection restore. Such a snapshot must not become an accepted current head, seed automatic replication, or execute anything. Normal trusted restore requires the policy and ancestry needed to establish acceptance. Content-hash success alone is insufficient.

Full historical payload retention is optional and separately measured. A complete current snapshot does not imply every ancestor's content remains available. Policy metadata and the ancestor descriptors needed for eligibility are mandatory for accepted-head computation even when historical file payloads are absent.

Pipeline: bound and parse framing; stream to quarantine; verify digest/canonical form; verify signature and dependencies; classify authority under pinned policy; validate closure; persist verified objects atomically; then, when keys are available, authenticate/decode plaintext and check the tree. Re-evaluate classification when policy or missing ancestry arrives. No receive path overwrites a working folder.

## 6. Interactive reconciliation

A live adapter supplies a mutually authenticated private session using a reviewed existing protocol. Pin the authorized device/session key binding before disclosing collection inventories. An unauthenticated hello must not reveal collection membership. Session protection is additional to object-level validation.

1. Establish transport/session limits and a compatible fixed profile. Authentication covers negotiation; unsupported versions fail closed.
2. Identify only mutually authorized requested collections. Exchange known policy checkpoints and required missing policy records first. Validate and apply fences before accepting advertised heads.
3. Exchange sorted, paginated snapshot/ancestor inventories for the explicitly selected scope. Inventory messages carry a query/session identifier and pagination state. Claims about unseen global heads are not accepted.
4. Request missing descriptors and closure pages, then exact missing object IDs. Basic sorted enumeration is the correctness baseline. Bloom filters or Merkle-set accelerators may optimize later but must never be the only completeness test.
5. Receive bounded objects/fragments, verify independently and journal useful progress. A peer-provided resume token is only a hint; locally verified objects determine what is missing.
6. Acknowledge verified receipt and local durable retention separately. End with a report naming policy checkpoint, selected roots, missing objects, conflicts, key state and any explicitly signed peer receipt.

Mid-session policy changes invalidate the previous authority classification, not immutable object hashes. Pause new snapshot promotion, validate the transition, and recompute the plan. Do not continue using a stale role because a connection was authenticated earlier.

Cancellation preserves committed objects and the bounded transfer journal. Reconnection may choose another adapter. No exactly-once delivery promise is needed: repeating an identical immutable object is idempotent. Retry budgets/backoff are local; exhausting them yields visible pending/failed status, not an endless loop.

## 7. Offline packages

Distinguish a self-contained snapshot export from a partial transfer package. Both use one record stream container, but their signed declarations state different scopes. A transfer package may legitimately contain only missing objects, an inventory request, policy records or key envelopes. It must not call itself a complete backup.

A snapshot export declares collection/root fingerprint, profile, selected snapshot IDs, policy checkpoint, included history scope and an inventory commitment. It includes the descriptors, closure pages and ciphertext objects needed for those snapshots, plus the complete policy chain and ancestry descriptors needed to establish their acceptance. Historical payloads and recipient key envelopes are optional explicitly listed additions. A backup is recoverable only if the required keys are separately available or included as explicitly protected recovery material.

Container records have bounded declared lengths and stable object IDs. The signed export declaration authenticates the inventory commitment; each embedded immutable record remains independently verified. A blind exporter may sign a declaration of ciphertext coverage but cannot certify plaintext validity. The receipt/export signer need not be the snapshot author; forwarding does not confer write permission. A plain filesystem courier need not sign anything.

No outer recipient encryption is required in the first container: content objects and key envelopes are already encrypted, while public verification metadata remains visible. Do not describe the whole file as metadata-private. An opaque outer envelope is a later optional profile with its own overhead/key handling.

Import is incremental. A truncated file may contribute complete independently verified objects; the export itself remains incomplete until its declaration and promised inventory are satisfied. A missing end record or length mismatch must not be reported as a complete package. Duplicate records are no-ops after validation; unexpected records remain subject to admission/quota and are not pinned automatically. Import never auto-enrolls a root, grants rights or invokes embedded paths/URLs.

## 8. Fragmentation and constrained carriers

End-to-end acceptance is at the bounded immutable object level. Proposed fragment metadata: transfer identifier, full object ID or an authenticated session-local alias, expected total encoded length, offset and fragment length. Exact header encoding and whether any abbreviated IDs are permitted are W1/W3 gates. Short unchecked IDs cannot establish identity.

Check bounds and quota before allocating. Identical repeated ranges are harmless. Conflicting overlaps discard that assembly and record the supplier; never choose arbitrary bytes from overlapping alternatives. Reject out-of-range data. Sparse temporary storage is bounded by declared total size and per-peer aggregate caps. Track missing ranges, but do not label partial ciphertext cryptographically verified before the full object digest passes.

An authenticated live session can reject forged fragments earlier. On unauthenticated media, a malicious fragment may waste a bounded object's retransmission; this is an explicit denial-of-service limitation. The first profile does not invent per-fragment signatures or claim independent fragment proofs. Complete object hashing, signature binding and AEAD still govern acceptance.

The adapter reports payload size after its own overhead, reliable/unreliable delivery, order, duplex or one-way delivery, expected contact duration, rate/energy/cost hints, and admission/rate limits. The scheduler enforces local budgets and picks policy/control records, selected descriptors, closure pages and content according to user intent. Adapter claims are scheduling hints, never security facts. If overhead leaves no usable payload, report unsupported rather than weaken identifiers or authentication.

SMS is an explicitly budgeted constrained carrier. A single signed control record may itself need multiple segments. Prefer compact requests, identifiers and receipts; even these must obey the complete signed-record validation contract. Tiny content transfers may be requested deliberately, but bulk collections wait for a suitable carrier. No automatic paid transmission is part of the first release. Bluetooth/radio discovery, framing and provider behavior each require a separate adapter profile and real-device validation.

## 9. Proposed finite limits

These are conservative review inputs, not measured performance claims or frozen compatibility requirements. Separate protocol maxima from configurable local admission limits. A local resource refusal is not evidence that a structurally valid peer record is malicious.

| Item | Proposed protocol ceiling or behavior |
| --- | --- |
| Plaintext content chunk | 64 KiB; final chunk may be shorter |
| Encrypted manifest page | 64 KiB plaintext before encryption |
| Public closure page | 64 KiB encoded |
| Signed snapshot/policy/key-envelope record | 1 MiB encoded; per-type field limits also apply |
| Encoded object staging allocation | 1 MiB maximum, checked before allocation |
| Parser nesting | 32 levels; reject deeper structures |
| Snapshot parents / transition frontier | 64 IDs; oversized frontiers block rotation until explicitly resolved or excluded into quarantine |
| Devices per collection policy | 1,024 device records within total record bound |
| Manifest entries per snapshot | 100,000; pagination does not waive total bound |
| Logical path | 4,096 UTF-8 bytes, 255 bytes per name, 64 components |
| Snapshot ciphertext content closure | 10,000,000 unique objects, streamed traversal with local quotas |
| Closure-index shape | Fanout at most 1,024; at most three index levels and 16,384 index pages per snapshot |
| Encrypted manifest graph | At most 1,000,000 pages, included within the overall object closure |
| Ancestor traversal | Iterative, memoized; proposed 1,000,000 descriptors per acceptance operation, resumable beyond local work budget |
| Offline package | 1 GiB proposed default import budget, explicit opt-in for larger streamed exports; not a format-size limit |
| Incomplete assemblies | 32 per authenticated peer/selected import by default; aggregate disk budget always enforced |
| Queues/timeouts | Finite configured limits; expiration discards only unprotected staging, never committed pins |

The combination of maxima matters: a manifest entry can reference many content pages. Receivers must validate aggregate counts/lengths, index levels/fanout, duplicate references, arithmetic overflow and consistency with the descriptor before trusting completeness or reserving advertised storage. Exact per-field tables and bounded streaming algorithms remain W1/W5 work. A file is limited by the permitted object/manifest closure and local storage, not a guessed unlimited integer range. Hard compatibility limits require review against intended archive sizes before freezing.

No concrete SMS adapter profile is supported by this draft. W3 must first select its signed-record size ceiling, maximum segments per transfer, monetary/airtime budget representation and actual provider framing. A carrier whose header cannot fit its usable payload is unsupported, not permission to omit authentication.
