# Implemented experimental profile: arc-exp-1

Status: experimental implementation initiated after the user's 2026-10-16 instruction to begin implementation. This page owns the implemented subset and exact experimental encodings. The broader [architecture](../DESIGN.md) remains the target; its unimplemented features and review gates are not claimed complete. `arc-exp-1` is not a frozen, interoperable v1 protocol, a security-audited product or a safe sole backup for valuable data. Format changes may require explicit export/migration or disposal of experimental collections.

The user subsequently authorized all five next milestones. This page preserves the original base format and its original verification record. Current history/reuse, membership/key lifecycle, merging, authenticated live transfer and constrained-contact behavior is specified in [the extension profile](device-and-sync-profile.md). Statements below about the original single-device slice are historical scope, not the complete current feature list.

The later [recovery and carrier profile](reliability-and-carriers.md) supersedes keys-only recovery export with a complete authenticated backup, adds journal repair and persistent partial objects, and specifies the current live application protocol and RFCOMM endpoint adapter. The `ARCKEY1` layout below is retained for legacy import compatibility.

## Implemented scope

A Linux Rust library and foreground CLI create a single-root collection, capture regular files/directories into encrypted chunks and an encrypted manifest, sign snapshots, verify scoped closure and ancestry, restore into a new destination, and transfer immutable objects through an offline file bundle. A separate encrypted recovery kit contains the existing root/data secrets but no source data. Import does not enroll another identity, select a head, overwrite working files or execute received content.

The single root/device signs genesis and snapshots. This is a deliberately narrower bootstrap than the proposed device/authority separation. There are no membership policies, device enrollment, epochs/rotation, revocation, HPKE envelopes, multi-writer merge operations, network sessions, radio/Bluetooth/SMS adapters, background jobs, automatic garbage collection or telemetry. No code from the archived prototype was restored.

Snapshots preserve parent descriptors and stable entry IDs for unchanged paths. Rename detection, shared-ciphertext reuse between captures and partial-directory selection are not implemented: fresh captures currently encrypt fresh chunks even for unchanged data. File bytes, names and complete manifests are encrypted; object sizes, collection identity, signer, public closure and ancestry are visible. Ancestry verification does not require ancestors' file payloads, and a selected export carries ancestry descriptors but only the selected snapshot's content closure.

The current key profile retains one random data key for the collection and a root signing seed. Recovery restores the same device identity. Keep the previous writer offline when continuing from a recovered copy; this does not create an independently enrolled peer. Concurrent captures on the same node are refused through an OS-released exclusive file lock. There is no distributed writer coordination or automatic head selection after recovery/import.

## Exact canonical encodings

All integers and lengths use minicbor's shortest definite-length encodings. All containers below are fixed arrays, not maps. Decoders check exact array lengths, fixed-width fields, limits and EOF, then compare canonical re-encoding to the supplied bytes. Unsupported tags, versions or record types fail. Byte strings have the exact stated lengths; UTF-8 strings must decode strictly.

`ID(bytes) = SHA-256(ASCII("arc-exp-1/id") || 0x00 || bytes)`. IDs are 32 bytes and displayed as 64 hexadecimal characters; signature keys are 32 bytes and signatures 64 bytes. API parsing accepts upper/lower hex; output is lowercase. No plaintext file digest becomes a public object ID.

| Object | Canonical CBOR value |
| --- | --- |
| Genesis | `[1, collection32, root_public32, signature64, 1]` |
| Snapshot | `[2, collection32, genesis_id32, writer_public32, parents_array, manifest_id32, closure_array, signature64]` |
| Encrypted object | `[3, collection32, kind, nonce24, ciphertext_with_tag]` |
| Plaintext manifest | `[1, entries_array]` |
| Manifest entry | `[entry_id32, relative_path_string, directory_bool, plaintext_size_u64, plaintext_sha256_32, ordered_chunk_ids_array]` |
| Password-protected keys | `[1, "arc-exp-1", collection32, 1, salt16, nonce24, ciphertext80]` |

Genesis signatures use Ed25519 over `ASCII("arc-exp-1/genesis-signature") || 0x00 || collection32 || root_public32`. Snapshot signatures use Ed25519 over `ASCII("arc-exp-1/snapshot-signature") || 0x00 || CBOR([1, collection32, genesis_id32, writer_public32, parents_array, manifest_id32, closure_array])`. Verification uses ed25519-dalek strict verification. A valid self-signature is insufficient for trust: the application additionally checks the separately stored genesis pin and snapshot writer equality to that pinned root.

Parents and public closure IDs are sorted bytewise and unique. The closure includes the encrypted manifest and every encrypted file chunk, but not the snapshot descriptor or historical payloads. A reader decrypts the manifest, reconstructs its referenced-ID set and compares it to the public closure; it also checks each file's authenticated length, chunk structure and SHA-256 digest. Blind verification checks signatures, selected closure structure/digests and ancestry but does not claim plaintext validity or global freshness.

Manifest entries are sorted by unique relative UTF-8 path and have unique random 32-byte logical entry IDs. Paths have no absolute prefix, backslash, NUL, empty/dot/dot-dot component, component longer than 255 bytes, total longer than 4,096 bytes or more than 64 components. Every parent directory is explicit. Directory size is zero, digest is SHA-256(empty), and chunks are empty. Empty regular files also have zero chunks and the empty digest. File chunk count equals ceil(size / 65,536); chunk order is file order, permits repeated IDs and is not sorted by digest. Every nonfinal chunk is exactly 65,536 plaintext bytes.

## Cryptography and key custody

Generate independent random root signing seed32 and content key32 with the OS RNG. The root uses Ed25519. Stored objects use XChaCha20-Poly1305 with a fresh random 24-byte nonce under the content key. `kind=1` is file content and `kind=2` is manifest. Object AAD is `ASCII("arc-exp-1/object-aad") || 0x00 || ASCII("arc-exp-1") || collection32 || kind_byte`. The profile/collection/kind are consequently bound even though their bytes do not disclose a filename.

The key container plaintext is `root_seed32 || content_key32`. Derive its 32-byte encryption key using Argon2id version 19 with 65,536 KiB memory, three iterations, parallelism one and a random salt16. Encrypt with XChaCha20-Poly1305 and a fresh nonce24. Key-container AAD is `ASCII("arc-exp-1/keystore-aad") || 0x00 || ASCII("arc-exp-1") || collection32`. KDF profile is fixed to 1; input cannot ask for attacker-selected work factors. The encrypted plaintext is 64 bytes plus the 16-byte AEAD tag. Password input must be nonempty and at most 4,096 UTF-8 bytes; strength is the user's responsibility. No secret is accepted as a command-line argument or implicitly read from an environment variable.

Root/content/password-derived/plaintext-key buffers use zeroizing owners. This is not protection against a compromised unlocked process, snapshots, OS swap, crash dumps or copies made elsewhere. Content keys persist across snapshots, so stored history does not have forward secrecy. This experimental profile does not implement the proposed HKDF per-object salts/subkeys or platform keychain backend; these remain required review topics before a stable profile. The raw node key file contains only the password-encrypted container, not an unencrypted key beside ciphertext.

Cryptographic primitives are provided by dependency libraries, not implemented here. `Cargo.lock` fixes the resolved dependency graph. Argon2's `zeroize` feature is enabled. No claim of crate audit coverage, current advisory clearance or review of this composition is made merely because libraries were selected. The broader C1 qualified cryptographic review remains open for production/stable protocol claims.

## Object storage, capture and restore

Runtime data goes in an explicitly selected new node directory, not the source repository. Node directories use mode 0700 and files 0600. Object paths are hexadecimal IDs. Incoming bytes are bounded and digest-checked; duplicates validate the existing bytes. Writes use exclusive temporary files, file flush, no-clobber hard-link publication and directory flush. Controls `genesis` and `keys` are no-clobber; the local `head` pointer is atomically replaced only after complete capture validation and durable object writes. A failed operation may retain unreferenced encrypted objects. No automatic pruning is implemented.

The application serializes local capture with an exclusive `writer.lock` held until completion. The opaque storage library alone does not claim to authorize data or serialize arbitrary callers. Filesystem assumptions are Linux regular filesystem support for hard links, directory flushes and no-replace rename. `get` rechecks ID rather than trusting a filename. `O_NOFOLLOW`/`O_NONBLOCK` and regular-file checks prevent symlink/FIFO intake. Local concurrent or privileged modification of the private node directory is outside the supported trust boundary. No fault-injected power-loss matrix has been completed.

Capture anchors source traversal to open directory descriptors via Linux `/proc/self/fd`, rejects symlinks/special files/non-UTF8 names, and compares identity/size/mtime/ctime before/after reads. This detects ordinary changes but is not a transactional filesystem snapshot or application-consistent backup. The node cannot reside inside the selected source. Exact bytes are preserved; ACLs, xattrs, hardlinks, symlinks and owner metadata are not preserved. Source structure is not rearranged.

Restore verifies ancestry and the entire selected snapshot's content before creating plaintext staging. It reconstructs a private new directory, rechecks decrypted file bytes while writing, flushes files/directories and uses Linux `renameat2(RENAME_NOREPLACE)` to publish without replacing an existing destination. Unsupported target filesystems fail. Private staging is removed on ordinary errors; a killed process may leave a private plaintext staging directory that needs deliberate cleanup. There is no claim of secure erasure of that staging or restored plaintext.

## Offline transfer and recovery containers

The bundle format is `ASCII("ARCEXP1") || LF || count_u32_be`, followed by exactly `count` records of `object_id32 || encoded_length_u32_be || encoded_object_bytes`, then `ASCII("ARCEND1") || LF` and EOF. Export sorts/deduplicates IDs, validates all source objects, streams one bounded object at a time to a temporary file and publishes without overwrite. Import rejects repeated IDs within one bundle, oversized lengths/counts, digest failures, invalid/truncated footer and trailing bytes. Separate repeated imports are idempotent. Partial valid objects may survive a later import error; a failed import is not reported as a complete bundle.

The container itself has no sender signature: it carries independently signed records and encrypted objects. It is an opaque transfer container, not a proof that every included object is authorized, not a snapshot closure declaration, and not an automatic enrollment mechanism. Root/closure verification happens explicitly at the application layer. No network transmission occurs.

Recovery kit framing is `ASCII("ARCKEY1") || LF || genesis_id32 || genesis_record_length_u32_be || genesis_record || encrypted_keys_length_u32_be || encrypted_keys || EOF`. Recovery requires the expected genesis ID supplied independently, verifies its digest and self-signature, authenticates/decrypts the key container, confirms root/key agreement, and only then creates a new node. Secret keys remain encrypted inside the kit; its public identity and sizes are visible. Recovery exports are no-clobber. Kit and content bundle are separate artifacts; both plus the password are required for a full restore. This is recovery of the same single-root identity, not authority succession or peer enrollment.

## Bounded profile and remaining work

| Resource | Implemented ceiling |
| --- | --- |
| Encoded stored object | 1,048,576 bytes |
| Plaintext manifest | MAX_OBJECT minus 128 bytes of envelope allowance |
| Content chunk | 65,536 plaintext bytes |
| Entries | 4,096 |
| Total chunk references | 4,096; capture reserves one closure slot for the manifest |
| Unique snapshot closure | 4,096 objects |
| Snapshot parents | 64 |
| Traversed ancestry descriptors | 4,096 |
| Bundle records | 16,384 |
| Bundle object payload total | 1 GiB; framing overhead additional |
| Password/key container | Password 4,096 bytes; encoded key container 256 bytes |

These bounds are intentional pilot restrictions and differ from the larger architecture's proposed maxima. A path can hit the manifest-size cap before reaching the entry cap. An object transfer container accepts opaque bounded bytes; accepted current snapshot semantics always require application verification against the pinned identity. No unlimited recursion or unbounded byte allocation is intended.

The next milestones listed at the original base handoff were history/selection, ciphertext reuse, device membership, merges and live transfer. These are now addressed by the experimental [device/sync extension](device-and-sync-profile.md). Stable protocol review, full power-loss recovery, multi-epoch catch-up improvements and real carrier qualification remain separate work.

## Verification of this implementation

On the current Linux development host with Rust/Cargo 1.99.0, `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --all-targets --locked` passed. The suite has 19 tests: 14 module tests and five integration tests. Coverage includes ordered/repeated chunk references and noncanonical encodings, strict signature checks, wrong keys/passwords, cross-collection binding, immutable-object corruption, FIFO/symlink refusal, failed head-publication cleanup, truncated/trailing bundles, exact multichunk recovery/restore, foreign-collection import isolation, special-source rejection and destination nonoverwrite.

An additional eight-command CLI exercise initialized a node, captured disposable files, exported ciphertext and recovery keys, recovered a new node, imported, decrypted/verified and restored a snapshot. The restored 153,610-byte binary and text file matched the originals exactly. Temporary fixture data was removed. No real personal data, network peer, provider account or paid carrier was used.

Separate contributors reviewed the integrated cryptographic/authority and filesystem/transfer boundaries. Their findings led to a capture-root `openat2` no-symlink anchor and cleanup of failed head-publication staging. The fixed chunk ceiling reserves one manifest slot and is documented above. These bounded reviews did not audit the cryptographic composition or establish production safety. Linux source parents and node storage still depend on the stated local OS trust boundary.

Rust 1.89 is the declared minimum needed for the implementation's standard-library APIs; only 1.99 was exercised here. Thirty local Markdown links and code-fence balance were checked. No independent cryptographic audit, advisory clearance scan, full crash/power-loss matrix, actual radio/Bluetooth/SMS test or performance qualification was performed.
