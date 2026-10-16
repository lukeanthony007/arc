# Security, authority and key lifecycle

Part of the [Arc design review draft](../DESIGN.md). This is a threat model and candidate security design, not an audit, proof or claim of production readiness. The cryptographic and recovery gates in [the decision register](decisions-and-sources.md) remain closed.

## 1. Assets and adversaries

Protect file plaintext, private manifest metadata, private keys and recovery material; prevent unauthorized changes from being presented as accepted versions; preserve a defensible account of what bytes, signatures and dependencies were checked. Retention and recovery must remain understandable when peers disappear.

Assume transports, removable media, relay/storage operators and unauthenticated inputs can be malicious. They may drop, delay, reorder, duplicate, truncate, substitute, withhold or replay objects; advertise false inventories; send resource-exhausting input; collude; and correlate public metadata. An authorized reader may redistribute plaintext. An authorized writer may publish malicious or false data. An administrator may make mistakes or equivocate. Disk corruption, abrupt power loss, stale backups and loss of all online copies are ordinary failure cases.

Assumptions: chosen primitives and library implementations satisfy their reviewed contracts; honest endpoints generate sufficient randomness and protect private keys; user-confirmed trust bindings are correct. Those are dependencies, not properties established by this document.

| Threat | Intended control | Residual limitation |
| --- | --- | --- |
| Carrier/storage reads files | Encrypt payload and manifest before storage/export | Public metadata and traffic remain visible; compromised reader can disclose plaintext |
| Tampered/substituted objects | Canonical digest, signature and AEAD checks with collection/type/epoch binding | Malicious authorized content can still be well signed |
| Unauthorized writer | Pinned root and policy-specific device signature checks | Stale offline devices cannot know an unseen revocation |
| Stale or forked authority | Persist highest trusted checkpoint; verify chain/fences; detect competing successors | Fresh/stale recovery cannot prove global freshness without independent evidence |
| Missing or lying storage | Named closure checks, dated receipts, verification/restore exercises | No promise of future retention or guaranteed availability |
| Malicious package/filesystem tree | Bounded intake, isolated inspection, traversal/collision checks, no execution | Restored documents may still be unsafe if opened by another application |
| Key or device loss | Explicit encrypted recovery kit, retained replicas, replacement-device process | Lost secrets without backup may make data permanently unrecoverable |
| Key compromise | Revoke, rotate, quarantine late writes, re-encrypt current state | Past disclosure and root compromise cannot be undone |
| Resource exhaustion | Admission, quotas, streaming, bounded parsing/assemblies, backpressure | An attacker can still deny a physical link or use its bandwidth |

No guarantee of anonymity, resistance to a compromised unlocked endpoint, covert presence, coercion resistance, secure erasure, truthful document contents, trusted creation time, post-quantum security, regulatory compliance or indefinite survival is made.

## 2. Trust and enrollment

Collection identity binds a random collection ID, root verification key and genesis-policy digest. An invitation carries that binding, intended recipient device keys, proposed rights, protocol profile and a known policy checkpoint. The root signs the membership policy; the inviter cannot grant more rights by editing an invitation wrapper.

Enrollment requires an authenticated out-of-band fingerprint comparison or an already trusted authenticated channel. QR codes can carry the binding but scanning an arbitrary QR code does not prove the sender's identity. Human labels never override a mismatched root or device fingerprint. Imported content cannot silently enroll a collection, replace a root, add a peer or trigger outbound discovery.

Pin complete cryptographic identities. Network addresses, phone numbers and short display codes are routing/usability data, not identity. Collection authorization and peer network-session authentication are checked separately. A known device's valid network handshake does not authorize every collection it requests.

The first private-collection profile uses one logical root authority for a linear membership chain. The private root key should normally be offline or unlocked only for administration. This is a deliberate administrative trust concentration; no claim of decentralized membership consensus is made. Content writes and reads require no always-online root service.

## 3. Permissions and key roles

Read permission supplies the epoch secrets needed to decrypt the collection state. Write permission authorizes snapshot signatures. Storage admission governs who may consume a particular node's disk/bandwidth and is independent of content-read permission. The root key changes collection policy. The first writer role combines read and write because a complete-tree capture/merge needs read access; blind write-only ingestion is deferred.

Use distinct signing, envelope recipient and session key material. A policy-authorized device record binds these roles to one device identifier. Device-key rotation is explicit; it is not inferred from a reused hostname. Do not convert Ed25519 keys into X25519 keys or reuse a single key across protocols just to reduce the record size.

Whole-collection epochs are the first read boundary. Sending fewer files does not stop a member from decrypting other ciphertext for the same epoch if obtained later. Separate collections provide separate authorization boundaries. Membership changes rotate the epoch under the proposed uniform transition rule; adding a reader does not automatically disclose historical keys.

Blind nodes may validate signatures, policy chains, the public closure index and ciphertext digests. They cannot validate plaintext meaning, restoreability, the truth of claimed metadata or whether an authorized writer constructed sensible data. Their receipt vocabulary must reflect this limit.

## 4. Candidate cryptographic profile

The recommended primitive set is deliberately concrete enough to review, but the composition, byte layouts and dependencies are not approved. No application-specific construction should be implemented before C1/W1 are resolved.

| Purpose | Recommended review candidate | Required review detail |
| --- | --- | --- |
| Object identity | SHA-256 over domain-separated complete canonical record | Exact type/version framing, collision handling, digest vs signature preimages |
| Policy/snapshot/export signatures | Ed25519 via maintained high-level API | Strict validation, canonical encodings, invalid/small-order input behavior, domain strings |
| Recipient envelopes | RFC 9180 HPKE base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | Root-signed wrapper supplies sender authorization; bind recipient, policy, epoch, collection and suite to HPKE context and signature |
| Content/manifest encryption | XChaCha20-Poly1305 through a maintained library | Randomness, nonce scope, per-object subkeys, AAD, object size and usage limits |
| Subkey derivation | HKDF-SHA256 with distinct reviewed labels | Bind collection, epoch, purpose and per-object salt; no ambiguous concatenation |
| Live connection | Existing Noise XX implementation with pinned authorized session keys; candidate suite Noise_XX_25519_ChaChaPoly_SHA256 | Finish authentication/key-binding checks before inventory; protect version negotiation; reject unknown peer keys |
| Recovery-kit password protection | Maintained Argon2id-based encrypted-container implementation | Format/library selection, memory/time parameters, salt, AEAD binding, migration and malicious KDF-cost caps |

HPKE base mode alone does not authenticate who sent an envelope. The signed outer record must authorize the key-envelope sender and bind the exact encapsulation, ciphertext, recipient key and policy. Proposed v1: only the root authority signs epoch-key envelopes; it may prepare them offline. Receiving the same epoch secret through two records must agree with the policy's commitment. The profile must define that commitment without exposing the secret or enabling password guessing against a low-entropy value; epoch secrets are randomly generated high-entropy material.

Per-object encryption recommendation: derive purpose-separated object keys from the random epoch secret and a fresh public per-object random salt; generate the AEAD nonce through the library's reviewed random-nonce interface; authenticate the public framing as AAD. Reuse only exact stored ciphertext. The exact salt/nonce sizes, uniqueness assumptions, extraction/expansion inputs, usage limits and failure handling are C1 decisions. The draft does not claim that listing secure primitives is a proof that this construction is secure.

Encryption framing must bind collection, epoch, object type, suite and declared lengths. Do not include the final ciphertext digest inside its own AAD or introduce another circular definition. The signed snapshot/closure authenticates final object IDs. A malicious reader who holds an epoch key may construct valid AEAD ciphertext, but cannot publish an authorized snapshot without an authorized signing key.

There is no algorithm negotiation that permits silent downgrade after failure. The genesis/profile and signed policy identify permitted suites; unknown mandatory suites/versions fail closed. Future migrations need an explicit signed policy/format transition and a compatibility plan. An authenticated network session cannot override immutable-format requirements.

Content persistence does not promise forward secrecy: anyone who later obtains a retained epoch key can decrypt retained ciphertext from that epoch. Any forward secrecy offered by the live-session protocol protects that session, not long-lived stored objects or previously copied recovery kits.

## 5. Keys at rest and disclosure

Public object/index storage contains ciphertext and intentionally public verification metadata. Keep private keys and epoch secrets in a separately protected local key store, using platform facilities where available. The exact Linux-first storage/unlock and fallback behavior is C2; an unencrypted key file beside encrypted objects is not an acceptable advertised encrypted-at-rest boundary.

Private manifest caches, plaintext fingerprints, working copies, restore staging and logs are additional plaintext surfaces. Encrypt persistent sensitive caches or rebuild them while unlocked. Disable plaintext content logging. Key material, recovery phrases and full payloads must not appear in command-line arguments, environment examples, diagnostics or telemetry. OS paging, crash dumps and unlocked-process memory remain endpoint concerns; zeroization alone is not a complete defense.

Locked means content/private keys are unavailable to the process and sensitive caches are not readable through the interface. It does not mean public membership/graph metadata vanishes. Exporting or restoring plaintext is an explicit user action; Arc cannot protect a plaintext copy afterward.

## 6. Rotation and revocation

Every valid policy successor advances the epoch and defines an accepted preceding-epoch frontier. Apply the exact fence semantics in [data and sync](data-and-sync.md#4-policy-transitions-and-offline-revocation); do not substitute locally observed arrival time for that frontier.

Administrative sequence:

1. Review the current membership, known competing heads and the explicit frontier that will remain accepted. Show any known pending work excluded by this choice. Enforce the proposed 64-head frontier ceiling without silent omission. For routine rotation, confirm that authorized migration writers possess the old keys, complete source closures and capacity for every retained head; block otherwise. Emergency revocation can explicitly accept an unavailable new baseline, with new-epoch publication blocked until recovery.
2. Generate a fresh random epoch secret and recipient envelopes for the new reader set. Record the new membership, previous-policy digest, epoch, frontier and secret commitment in the signed transition.
3. Publish the policy and deliver recipient envelopes through any carrier. Removed devices receive no new secret. Receipt by one device is not global policy dissemination.
4. Current authorized writers create complete new-epoch transition snapshots for the retained heads using fresh ciphertext. Preserve divergent heads and retain old encrypted history separately.
5. Mark migration complete only for explicitly verified new-epoch roots/replicas. Resume ordinary new-epoch publication from valid baselines.

A peer learning the transition may reclassify its previously accepted local work as quarantined. Preserve it and offer reviewed reissue. Never erase it just because the writer is now revoked. A disconnected peer may keep creating old-epoch snapshots and reading old ciphertext; it cannot know the new policy until it receives trustworthy evidence.

Revocation cannot erase plaintext, keys or old ciphertext already copied. Re-encrypting current state does not retroactively protect disclosed content. Readers admitted in the new epoch receive current state through the migrated roots; access to older epochs requires explicit key-envelope grants. Future membership changes remain an offline administrative bottleneck by design, although ordinary operations continue under the last known policy.

## 7. Recovery and compromise

A recovery kit has an explicit scope: collection identity/genesis, trusted policy checkpoint, chosen epoch secrets, optional root authority secret, encryption format/KDF parameters and the inventory of what it can recover. Ordinary data-recovery kits need not contain the root secret; root recovery material is separately labeled as authority recovery. Do not silently give every reader administrative recovery powers.

The kit is encrypted under a strong user-held recovery secret or reviewed password-protected container. It does not contain the data unless the user deliberately creates a combined backup. New epochs require a newly exported kit if they are to be covered; the interface reports kit scope/staleness instead of implying an old kit covers future state. Arc must not upload it to a provider by default.

Recovery drill: on a fresh isolated device, import a disposable ciphertext backup, authenticate the collection/root binding, unlock the scoped recovery kit, validate policy and selected snapshot, restore exact bytes and compare them to the disposable original. Exercise missing key, wrong secret, altered kit and incomplete backup outcomes. Do not delete the original until the user has independently established the intended recovery result.

A stale device backup must not automatically resume membership administration. Ordinary device recovery recommends a newly enrolled identity. A restored root can have an old policy checkpoint: it must compare against independent trusted peers or an externally retained checkpoint before signing a successor. With no such evidence, administration remains blocked; it can still recover covered historical data. An entirely rolled-back local machine cannot reliably detect its own rollback without trusted external state.

Possession of a recovery kit is not an authority-succession proof or permission to repair a fork. It restores only the keys and checkpoint explicitly inside it. A different root/collection needs a newly authenticated trust binding, and an old root secret cannot certify that no later policy exists.

If a member key is compromised, revoke it, rotate and review its affected signatures. A signature cannot distinguish the legitimate holder from an attacker with that key. Preserve suspicious versions for explicit review.

If root authority is lost without recovery material, existing authorized reads/writes can continue under known policy but membership cannot safely change. Create a new collection and explicitly migrate trusted data if administration must resume. If root compromise or a policy fork is suspected, freeze policy-dependent promotion and establish a new collection/root through authenticated member coordination. The first profile intentionally has no in-band claim that the compromised root can certify its own repaired trust.

Threshold recovery, social recovery, hardware-backed signing, delegated administrators and root succession are deferred. They require their own threat models rather than labels promising automatic resilience.

## 8. Metadata, storage and deletion limits

Public envelopes/closure indexes disclose collection linkage, epochs, authorized key sets, writers, version graph shape, ciphertext sizes/counts and reuse patterns to recipients of that metadata. Link observers may also learn addresses, timing, traffic volume and contact patterns. File names and tree relationships remain encrypted, but size correlation may still reveal information. No traffic-analysis resistance or anonymity is promised. Padding, private discovery and opaque outer packages are possible future profiles, not current guarantees.

A cryptographic hash establishes equality of bytes to a named identifier. An authorized signature establishes that a key holder signed the record. Neither proves true real-world authorship, trusted capture time, ownership of source material, or factual truth. Provenance fields are signed claims unless supported by a separately trusted source.

Deletion from a newer snapshot removes content from that view. Local pruning can release unprotected objects. Neither causes remote nodes or backups to erase their copies. Requests to stop retaining data are operational requests; do not report them as provable secure deletion. Destroying local keys does not establish that no copies exist elsewhere.

Durable-storage receipts are signed observations/promises about named objects, policy scope and retention terms. They are not a proof of future possession, independent failure domains or indefinite availability. The first profile has no proof-of-retrievability protocol. Recovery exercises and explicit copy placement provide practical evidence with stated dates and limits.
