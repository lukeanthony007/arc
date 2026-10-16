# Operations, interfaces and validation

Part of the [Arc design review draft](../DESIGN.md). This page specifies target behavior and the full acceptance plan. Following the user's instruction to begin implementation, [arc-exp-1](experimental-profile.md) implements a narrower local/offline subset; only tests actually reported in the implementation handoff are completed. Full policy, crash, live-network and hardware scenarios below remain future work. Gates and dependencies are in [the decision register](decisions-and-sources.md).

## 1. Local persistence contract

A node stores immutable canonical objects, policy/ancestor descriptors, selected roots and pins, a derived query index, bounded intake/transfer journals and a separately protected key store. The protocol does not require a specific on-disk database. Proposed implementation: an ordinary filesystem object store plus a transactional embedded index; select SQLite or another maintained store only after reviewing crash consistency, recovery and encryption needs.

The object store is authoritative for retained bytes. The derived index can be rebuilt from objects and protected local control records. Pins, retention choices, trusted policy high-water checkpoints, active transfer reservations and pending local changes are not disposable cache. They require durable records and backup appropriate to their sensitivity. A clean reindex must not reset trusted identity, forget a revocation, unpin data or accept a different collection root.

Proposed private node layout, subject to the disk-format gate:

```text
node/
  objects/             immutable ciphertext and public signed records
  control/             trusted checkpoints, pins and retention decisions
  index/               rebuildable query structures
  incoming/            bounded incomplete objects and quarantine
  transfers/           bounded resumable transfer journals
  keys/                protected key-store material, never plaintext defaults
```

This is runtime data outside the source repository. A user-selected export/restore location is separate. Restrictive permissions and filesystem hygiene are required but not equivalent to encryption. No repository template creates or populates this layout during design.

### Atomic local publication

1. Reserve admission space; write a new object to a uniquely named temporary file on the intended storage filesystem.
2. Validate bounded framing, digest and the record's dependencies as available. Do not trust the filename as proof of the bytes.
3. Flush the complete object and use a no-clobber atomic promotion to its content-addressed location; flush the directory as supported. An existing object is reused only after validating its size/digest or a trustworthy locally maintained validation record.
4. Commit the index/control transaction referencing only objects whose durable write succeeded. Publishing a captured snapshot additionally requires its entire local closure and acceptance dependencies.
5. After restart, reconcile interrupted journal entries. Complete unreferenced objects may be reindexed or collected only under retention rules; references to missing objects make the snapshot incomplete, never silently valid.

Storage/index ordering must never leave a committed complete snapshot referring to unflushed objects. The exact fsync/rename/database rules, Windows portability behavior and filesystem assumptions must be demonstrated in the disk-format gate. Devices/controllers that lie about flushes remain outside software guarantees. Report durability relative to the tested storage contract rather than claiming immunity to all hardware failures.

### Locked operation

A node without content keys can validate public envelopes, serve admitted ciphertext and report ciphertext closure. It cannot materialize manifests or claim restoreability. A local reader may lock/unlock its key store independently of networking. Derived sensitive caches must be encrypted or dropped when locked; lock behavior needs a verified resource-lifetime design.

## 2. Capture and restore safety

Capture regular files/directories through handles where practical, record pre/post file identity and size/mtime evidence, and reject detected mutation. A filesystem snapshot integration can strengthen consistency later. Importing a live database through ordinary file reads is not an application-consistent backup.

Never follow an arbitrary captured path outside the selected root. Reject symlinks and special files in the first profile. Do not ingest Arc's key store or active runtime directory through accidental recursion. An explicit capture preview names exclusions and unreadable files; a partially captured source must not be called a complete capture.

Restore first verifies the selected descriptor, required authority/ancestry, complete ciphertext closure, AEAD and manifest consistency. Then build a complete destination plan: decoded names, length expectations, collisions, filesystem limits and overwrite decisions. Use a private staging destination and path-safe handles; disallow absolute paths, dot/dot-dot names, NULs, separator injection and traversal through preexisting symlinks. Do not follow file metadata into commands or permissions that cause execution.

Default behavior restores into a new directory. Existing destinations require a reviewed mapping and explicit overwrite policy. Atomic promotion is possible only under the supported same-filesystem/destination constraints; otherwise report partial progress and preserve the staging result for recovery. A failed restore must not damage the preexisting destination. Restored file hashes/lengths are checked against the authenticated manifest. Filesystem timestamps/metadata are applied only within the supported profile.

## 3. Retention, replication and garbage collection

Keep current accepted heads, unresolved concurrent heads, pending local snapshots and their dependencies protected by default. Quarantined work created locally stays protected until an explicit review decision; untrusted remote quarantine is bounded and can expire according to admission policy. A peer cannot force permanent retention by sending an object.

Explicit pins name snapshots and scope: ciphertext closure, authority/ancestry metadata and optional historical payloads. Required policy chains and eligibility descriptors stay retained while a dependent snapshot is protected. Key envelopes/recovery material are separate retention dependencies; a complete ciphertext copy with lost keys is not a recoverable backup.

Garbage-collection dependency classes are explicit: a protected snapshot retains its descriptor, full closure index, encrypted manifest/content closure and acceptance dependencies. A historical ancestor needed only for eligibility retains its signed descriptor and required policy/parent descriptors; its closure index and encrypted payload may be pruned unless separately pinned. Pruning those old payloads changes historical payload completeness, not the validity of its retained signature/ancestry. An explicit history-content pin expands protection to the corresponding ancestor closures. Trusted checkpoints and fork evidence remain protected control state.

The first release uses full copies, not erasure coding. The interface reports known copy locations and dated verification/receipt observations. Two copies on the same physical device or controlled by the same operator are not assumed independent. The application cannot infer real failure domains merely from different node IDs.

No automatic deletion based on a peer receipt. No automatic pruning of retained history in the first release. Manual prune is a two-step operation:

1. Compute a consistent mark set from all protected roots, required ancestry/policy, active transfer/capture reservations and retained quarantine. Show which snapshots/history would become unavailable and which keys remain required.
2. After explicit confirmation, recheck that the control generation is unchanged, then delete only unmarked objects. If concurrent work changed roots/reservations, recompute rather than use a stale sweep plan. Record the result and reverify affected closure reports.

Deleting a current path is a version change; deleting old bytes is a local retention change. They must not share a single ambiguous command. Remote deletion requests cannot prove erasure. Accidental pruning may be repaired from another retained copy, but the interface cannot promise such a copy exists.

## 4. Interface contract

CLI-first is proposed for validation and a transparent demonstration. Exact command spelling is not frozen. The local library/API exposes the same operations; no remotely exposed HTTP service is required for the first release.

| Operation family | Required behavior |
| --- | --- |
| Create / enroll | Explicit storage/root identity, authenticated invitation, recovery scope and rights |
| Capture / history | Preview source, publish exact signed snapshot, show parents/heads and capture limits |
| Inspect / verify | Name snapshot, policy checkpoint, verification depth, missing dependencies, plaintext/key state and local durability |
| Export / import | Declare self-contained vs partial scope, included key envelopes, completeness and admission budget |
| Sync | Explicit peer/collection/scope/budget, resumable progress, pending reasons and independent validation |
| Resolve | Show input heads and chosen result, create a new signed merge without deleting inputs |
| Restore | Exact snapshot and safe new destination, conflict preview, no implicit overwrite |
| Membership / rotate | Show permission diff, fixed accepted frontier, migration/key-delivery progress and excluded work |
| Recovery / replacement | Scoped encrypted kit, fresh-device drill, trusted checkpoint comparison and new identity by default |
| Retention / prune | Explicit pin scope and dry-run impact before destructive local deletion |

Machine-readable results contain operation/request ID, selected collection/root IDs, policy checkpoint, per-axis verification states, committed byte/object counts, unresolved conflicts/dependencies, retryability, and a stable error code. Text output explains those states without promising global freshness. Percent progress must declare its denominator; discovering more required objects can change an estimate.

Proposed failure categories: malformed/unsupported format, unknown identity, policy missing, policy fork, authorization denied, epoch fenced, missing dependency, missing key, integrity/AEAD failure, manifest invalid, conflict unresolved, resource limit, carrier budget exhausted, connection unavailable, storage full, durable-write failure, capture changed and unsafe restore destination. No failure silently selects another root, downgrades encryption or broadens permissions.

Read-only inspection is distinct from effects. Preview operations never contact a new peer or send material. Network delivery, paid carrier use, plaintext export, key export and destructive pruning each need the user's explicit intent or an already configured bounded policy. Future agents use these same interfaces; an LLM never receives root keys or gains implicit send authority.

## 5. Observability and support

Keep logs local by default. Record operation IDs, failure classes, byte counts and durations; avoid plaintext names/content, secrets and full membership identifiers in ordinary logs. Diagnostic export is explicit, previews included fields and explains remaining metadata. There is no telemetry service in the first profile.

Expose queue size, pending contact, budget exhaustion, disk pressure, failed validation, current policy checkpoint and last verification observations. A quiet queue must not be rendered as proof that all peers are synchronized. Health reports distinguish local corruption from remote absence and unavailable keys.

Time is informational: local clocks support logs, retry scheduling and observation timestamps, not version winner selection or trusted revocation time. Clock rollback must not resurrect rejected policy or bypass byte/transfer budgets. Rate/timeout accounting should use monotonic local time where available; persisted expirations remain conservative across restarts.

## 6. Acceptance matrix

These are the full target acceptance scenarios. A subset has executable coverage in arc-exp-1, as documented in its profile and implementation handoff; the matrix is not a claim that all scenarios passed. Each names a property that can falsify the design. Cross-implementation format vectors and fault-injected durability tests remain distinct from ordinary unit/integration tests.

| Scenario | Required observation | Requirement |
| --- | --- | --- |
| Local round trip | Capture arbitrary bytes, restart, verify and restore exact lengths/digests without a network | R1, R4, R8 |
| Mixed carriers | Receive part live, carry remaining objects physically, import duplicates, finish same selected closure | R2, R6 |
| Blind courier/storage | Retain and verify ciphertext closure without keys; plaintext restoration remains unavailable | R3, R7 |
| Corruption and substitution | Flip ciphertext/header/reference bytes, swap collection/epoch and alter signature; reject without plaintext release | R4 |
| Partial transfer | Truncate package or interrupt fragment assembly; preserve complete verified objects, report remaining incompleteness | R6, R7 |
| Fragment hostility | Reorder, repeat and overlap ranges; identical duplicates harmless, conflicting overlaps rejected, memory/disk bounded | R6, R10 |
| Divergent writers | Two children of a common base remain heads regardless of delivery order; explicit merge names both | R5 |
| Delete/edit and rename collision | Neither branch silently overwrites the other; restoring one branch does not change accepted history | R5, R9 |
| Historical payload omission | Current snapshot restorable with required ancestry metadata; missing old payloads reported separately | R7 |
| Missing ancestry or policy | No automatic head promotion; isolated inspection requires explicit unresolved-trust label | R4, R7 |
| Revocation fence | Deliver same records/policy in different orders; accepted/quarantined sets converge to the same frontier result | R4, R5 |
| Locally pending revoked work | New policy reclassifies but preserves local data; reissue is a new authorized signature | R5, R9 |
| Epoch migration with conflicts | Re-encrypt each retained head, preserve disagreement; new reader restores current roots without old keys | R3, R5, R8 |
| Incomplete rotation | Policy known but envelope/baseline absent; show blocked migration rather than current-state success | R7, R9 |
| Policy equivocation | Two successors cause fork state; no timestamp/arrival/majority winner or automatic root repair | R4, R9 |
| Stale device/root recovery | Data scope recoverable when keys exist; stale admin remains blocked without independent checkpoint evidence | R8, R9 |
| Missing/wrong recovery secrets | Fail explicitly, preserve source backup, do not imply provider recovery | R8 |
| Storage crash matrix | Kill between every write/flush/rename/index/control step; reopen never falsely reports complete durability | R7, R9 |
| Disk full | Fail reservation/write/commit safely; preserve prior snapshots and report incomplete new work | R9, R10 |
| Concurrent prune/capture | New protected objects cannot be swept using a stale root generation | R9 |
| Destination traversal/collision | Malicious names, links and case/normalization collisions cannot escape staging or overwrite existing files | R9 |
| Unsupported profile/downgrade | Reject before interpretation; authenticated negotiation cannot switch to weaker validation | R4 |
| Resource exhaustion | Deep/numerous records, oversized lengths, KDF parameters and unauthenticated traffic stay within configured bounds | R10 |
| Misleading peer receipt | Receipt does not make a missing local snapshot complete or automatically delete the last local copy | R7, R9 |
| Recovery drill | Fresh device restores disposable data using only chosen backup + scoped kit and verified identity evidence | R8 |

## 7. Performance and platform qualification

Proposed initial implementation platform is Linux on x86-64 with CLI/file and one live IP adapter. This follows the current development environment, not a claim that other platforms are unsupported forever. Cross-platform naming, crypto/key storage and durable-write assumptions require separate qualification before claiming portability. No iOS/Android/Bluetooth/radio integration is demonstrated by an IP simulator.

Measure peak memory, staging disk, total ciphertext/index overhead, capture/restore throughput, reconciliation bytes, no-op sync overhead, restart recovery time and loss/interruption behavior. Use explicit fixtures such as many small files, large binary files, one-byte modifications, conflicting branches and repeated epochs. Publish fixture sizes/hardware/link conditions with results. No throughput, node-count, battery-life or fault-survival target is claimed as achieved.

Review the proposed limits against large photo/video libraries before freezing them. A bounded initial collection size is acceptable if clearly documented; silently accepting a collection that cannot be exported or recovered is not. Run fuzzing/property testing for formats, DAG/state transitions, reassembly, permission checks and restore paths after implementation is authorized. Independent security review and real-world adapter validation are separate from passing internal tests.

## 8. Gated delivery sequence

| Gate/phase | Deliverable | Exit condition |
| --- | --- | --- |
| D0 — this review | Full architecture, threat model, semantics, operational and acceptance plan | User reviews purpose, boundaries and major tradeoffs; outstanding decisions remain visible |
| D1 — protocol freeze | Exact schemas/preimages, crypto/key/backup formats, dependency assessment, adapter profile, limits and static golden vectors | W1–W5/C1–C2/P1–P2 closed with evidence; reviewed design explicitly approved for implementation |
| I1 — local core | Capture, encrypted immutable storage, policy verification, exact snapshot restore and scoped recovery | Local, hostile-input, key-loss and crash scenarios pass |
| I2 — disconnected exchange | Self-contained/partial packages, blind replica closure, resumable intake | Offline and mixed-package corruption/duplicate/completeness scenarios pass |
| I3 — live exchange | One authenticated live adapter, bounded inventories/scheduling, conflicts and epoch migration | Mixed live/package convergence and revocation/order scenarios pass |
| I4 — constrained-link proof | Deterministic loss/reorder/MTU/cost simulation using the same core | Bounded recovery/resumption documented; no hardware support claim |
| I5 — real carriers | Individually approved Bluetooth, radio or SMS profile/integration | Actual device/provider tests, cost controls and platform limits documented per adapter |
| Release review | Security assessment, fresh-device recovery, compatibility fixtures and reproducible demonstration | Claims limited to exercised behavior; unresolved release blockers visible |

The architectural requirements for all carriers are designed even though adapters arrive sequentially. The user's subsequent instruction to begin implementation authorizes the bounded experimental profile documented separately; it does not imply D1, production-security review, complete I1/I2 acceptance or any live/hardware adapter is finished. Retain these exits as the stable-profile and release targets rather than rewriting a working prototype into evidence of full satisfaction.
