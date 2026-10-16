# Decisions, evidence and implementation gates

Part of the [Arc design review draft](../DESIGN.md), revision 0.1, 2026-10-16. User requirements, assistant recommendations, external source claims and demonstrated behavior are distinct. This register is the authoritative status of the design choices below; a proposal appearing in another document does not make it approved.

## 1. Established direction

The user defined Arc as decentralized secure data storage with source/transport-agnostic verifiable synchronization, explicitly including physical handoffs, SMS, Wi-Fi, Bluetooth and radio. The user asked for a ground-up redesign and a full design before implementation. Luma is context only and must not shape the core around a PKM integration.

The prototype is preserved at commit `5f529a07af44b4fba02715aa0fa5a37eab06a11d` on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype). Its [historical README](https://github.com/lukeanthony007/arc/blob/5f529a07af44b4fba02715aa0fa5a37eab06a11d/readme.md) describes source-agnostic transport, cryptographically verified archives and topology-dependent deployments. It also makes broad claims about anonymity, seizure resistance, survival despite node loss, timestamps and recovery. Those claims were not demonstrated in this design work and do not become requirements or guarantees by preservation.

The redesign baseline `b00047a` proposed a local preservation tool with prominent Luma integration. This draft supersedes that framing: distributed storage and exchange are part of the core architecture, and integrations are optional downstream consumers. The original prototype and its history remain unchanged.

## 2. Recommended choices for user review

All rows are **proposed, not adopted**. The rationale describes why the draft uses them; alternatives remain available until approval.

| ID | Proposed decision | Reason and cost | Alternative considered |
| --- | --- | --- | --- |
| A1 | Private, invited collections first | Concrete trust/admission boundary; no public discovery infrastructure | Public swarm first adds spam, discovery, metadata and incentive problems |
| A2 | One offline-capable root membership authority per collection | Simple verifiable policy chain; ordinary work independent of authority availability | Multi-admin/threshold consensus has materially different fork/recovery design |
| A3 | Whole-collection read permission; reader/writer/storage roles | Avoids implicit claims that selective sync restricts keys | Per-path capabilities require additional key/metadata and policy composition |
| A4 | Complete snapshot DAG with shared encrypted chunks | Exact restore scope and preserved independent versions; manifest overhead | Operation-log/CRDT model adds replay, compaction and semantic merge requirements |
| A5 | Explicit user-authored merges | No silent data loss or arbitrary clock winner; more visible conflicts | Automatic text merge can be a later application feature; binary winner selection is unsafe as a default |
| A6 | Fixed policy frontier and current-state re-encryption on epoch transitions | Arrival-order-independent revocation and new-reader recovery without old keys; migration costs and paused publication during baseline preparation | Arrival-time acceptance diverges; shared historical keys simplify migration but expand disclosure |
| A7 | Public authenticated closure index, encrypted paths/content | Blind nodes can verify named ciphertext coverage; graph/size metadata leaks | Encrypt every reference and require owner assertions or a more complex proof system |
| A8 | Full copies and explicit pins before erasure coding | Straightforward recovery and failure reporting; more storage | Erasure coding needs placement, repair and availability assumptions |
| A9 | File packages plus one live IP adapter and constrained-link simulation first | Proves shared validation across disconnected/live modes with limited platform work | All hardware/carriers at once makes core and adapter failures hard to distinguish |
| A10 | Rust core, CLI and local structured API; Linux first | Matches project direction and current development environment; portable semantics still required | GUI/mobile-first work delays validating storage/protocol behavior |
| A11 | No automatic destructive retention, source-folder watching or network discovery initially | Preserves user intent while failure semantics are established | Automation can follow with explicit scoped policies |
| A12 | No mandatory Luma, LLM, blockchain, paid service or provider account | Core remains useful independently | Consumers can integrate through the same local API later |

The most consequential user choices are A1–A3 (who trusts whom), A4–A6 (offline work and membership changes), and A9–A10 (first demonstrable scope). The rest can follow those decisions. No implementation permission is inferred from reviewing a table.

## 3. Pre-implementation gates

A full architecture is present; a frozen implementable cryptographic protocol is not. These are concrete remaining design deliverables, not TODOs to discover while coding. They are currently **open**. Do not claim implementation readiness until each required gate has a reviewed artifact and the user has approved beginning implementation.

| Gate | Required artifact / decision | Exit evidence |
| --- | --- | --- |
| W1 — exact formats | Versioned field/tag/type tables for every record, deterministic CBOR rules, hash/signature preimages, domain labels, integer/size limits, ID and closure-tree construction | Hand-reviewable valid/invalid golden encodings and a complete dependency/cycle check; no ambiguous signed representation |
| W2 — authority/convergence | Formal predicates for snapshot acceptance, policy fences, transition clones, eligible heads and unresolved dependencies; historical-key grant rules | State-transition table and adversarial delivery-order walkthroughs, including two policy forks and partially migrated frontiers |
| W3 — exchanges/adapters | Container framing/end-of-stream rules, authenticated live transcript/profile, pagination, fragment/resume format, carrier capability/budget vocabulary | Byte/MTU accounting for minimum carrier frames, truncation/replay/overlap cases, and compatibility behavior |
| W4 — persistence/recovery | Transaction ordering, trusted checkpoint/pin persistence, key-store and recovery-kit formats, filesystem/platform contract, safe restore rules | Crash-point table, rebuild/rollback analysis and complete fresh-device recovery procedure |
| W5 — bounded interoperability | Interacting maxima for objects, manifests, DAGs, policies, bundles and parsers; feature/version negotiation and migration policy | Reviewed finite profile, invalid-input cases and static interoperability fixtures; local refusal distinguished from protocol invalidity |
| C1 — cryptographic composition | Exact primitive suites and key separation, wrapping/signing contexts, nonce/subkey strategy, canonicalization, library/API and version assessment | Qualified independent cryptographic review of the actual profile; known limitations and required changes incorporated; this document review is not a substitute |
| C2 — key custody | Linux key store/unlock behavior, password KDF parameters, recovery scope/staleness, root-loss/fork migration and device replacement | Reviewed user flows and threat/failure walkthroughs; no undocumented plaintext key fallback |
| P1 — dependency/reuse | Bounded Willow/Reticulum/library evaluation against the agreed invariants, licenses, maintenance/security evidence and actual APIs | Explicit adopt/adapt/reject decisions with versioned evidence; no dependency chosen from marketing claims |
| P2 — product approval | User accepts the intended first user, scope, permission/authority model, conflict/revocation costs and first supported environment | Explicit design and implementation approval after the remaining design artifacts are reviewable |

C1 requires a suitably qualified review; parallel design contributions in this session are not a security audit. Golden vectors and table-top scenarios before implementation are design evidence. Executable interoperability, fuzzing, performance, real hardware and crash testing belong to the later authorized implementation/release phases, not claims that can be made now.

Do not promise that a review eliminates all vulnerabilities. If review changes a premise or record format, update dependent semantics, vectors and recovery procedures before approval. A blocked dependency or unavailable qualified reviewer remains a visible blocker.

## 4. Reuse strategy

Do not commit to replacing established cryptographic constructions, radio stacks or synchronization mathematics without evaluating them. Equally, do not adopt an entire platform merely because one feature overlaps.

**Willow:** evaluate whether its storage/replication primitives can carry an append-only Arc snapshot namespace while preserving Arc's explicit version/conflict/retention semantics. Willow's ordinary model replaces entries by timestamp and supports prefix pruning; directly treating it as Arc's history model would change the design. Its Drop Format strongly informs asynchronous exchange, but is labeled a proposal. Its encryption discussion explicitly separates authorization/replication from content confidentiality. Any integration needs explicit parameter/wire compatibility and encryption choices. Rust code exists; presence is not evidence that every required protocol is implemented or stable.

**Reticulum:** evaluate as an optional network/radio adapter. Keep Arc's immutable record validation and storage semantics independent of its routing. Do not rewrite LoRa/radio routing as part of the storage core. Its reference environment and deployment requirements need assessment before promising a Rust-native or mobile integration.

**Bundle Protocol/BPSec:** use as design references for disconnected transfers, convergence-layer adapters, store-carry-forward and object-level security. Evaluate a standards-compatible adapter if a concrete deployment needs it; Arc is not BP/BPSec-compatible merely because the architecture follows similar principles.

**Tahoe-LAFS:** study ciphertext storage, capability distinctions, integrity trees and repair/placement. Defer erasure coding until full-copy recovery is sound and the intended availability/placement model is explicit.

**Syncthing and Bitchat:** study inventories, bounded transfer, transport separation, contact handling and the difference between delivered messages and durable storage. Their documented protocols are not automatic Arc interoperability.

## 5. Primary research sources and exact relevance

Accessed during the Arc research/design session on 2026-10-16. These are live sources unless a revision is explicitly identified. They are evidence for the claims listed, not instructions to execute, endorsements, pinned dependency versions or proof of security. No source code/library was built or audited for this design.

| Source | Observed claim / relevance | Boundary |
| --- | --- | --- |
| [Bitchat whitepaper](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md), version 2.0, dated 2026-07-06 | BLE and Nostr transport abstraction, store/forward, bounded courier storage, Noise sessions, file/media support, metadata and forward-secrecy limitations | Messaging/ephemerality priorities; author-described implementation, not independently verified |
| [Reticulum understanding guide](https://reticulum.network/manual/understanding.html) | Cryptographic networking across diverse physical/network interfaces and constrained links | Communication layer; does not specify Arc's archival version/retention behavior |
| [Briar how it works](https://briarproject.org/how-it-works/) | Direct encrypted synchronization over Bluetooth, Wi-Fi/Tor and described memory-card exchange; persistent forums/blogs | Overview-level evidence; no Bramble implementation audit or exact deployed removable-media test |
| [Willow specification index](https://willowprotocol.org/specs/index.html) | Data model, permissions and several live/asynchronous exchange specifications | A family of specifications, not one automatically complete application |
| [Willow data model](https://willowprotocol.org/specs/data-model/index.html) | Timestamp-based replacement, subspaces/namespaces and prefix pruning; parameterized model | Destructive update semantics need an explicit mapping for preserved Arc history |
| [Willow Drop Format](https://willowprotocol.org/specs/drop-format/index.html) | Proposal for verifiable data carried through USB, email, messages and other arbitrary channels | Proposal status; recommends transport encryption rather than inherently encrypting every drop |
| [Encrypted Willow](https://willowprotocol.org/specs/e2e/index.html) | No built-in content encryption; explains payload/path encryption and metadata that replication needs | Arc cannot claim confidentiality simply by choosing Willow |
| [Willow Rust repository](https://codeberg.org/worm-blossom/willow_rs) | Current README describes Rust implementation of various parts of the specifications | Component coverage, version stability and security not established; old GitHub repo points here |
| [RFC 9171, Bundle Protocol v7](https://www.rfc-editor.org/rfc/rfc9171.html) | Bundle overlay and convergence-layer adapters for delay/disruption-tolerant communication | Does not supply Arc membership, application conflict resolution or durable replication policy |
| [RFC 9172, BPSec](https://www.rfc-editor.org/rfc/rfc9172.html) | Integrity/confidentiality for store-carry-forward bundles; transport security alone is insufficient | Does not protect compromised endpoints or prove indefinite retention |
| [Tahoe-LAFS architecture](https://github.com/tahoe-lafs/tahoe-lafs/blob/master/docs/architecture.rst) | Client encryption, erasure-coded storage shares, verification trees and capabilities | Different storage/network architecture; not evaluated as a direct dependency |
| [Syncthing Block Exchange Protocol](https://docs.syncthing.net/specs/bep-v1.html) | Block/hash inventory reconciliation over reliable transport with TLS | Physical courier exchange requires a different mapping |
| [IPFS privacy and encryption](https://docs.ipfs.tech/concepts/privacy-and-encryption/) | Transport encryption does not imply content encryption; public DHT metadata can reveal relationships | Content addressing alone is not private storage |
| [Twilio SMS size reference](https://www.twilio.com/docs/glossary/what-sms-character-limit) | 140-byte underlying single-message payload and encoding/segmentation limits; per-segment billing in its service | Provider behavior/pricing varies; SMS is not assumed an efficient bulk carrier |
| [RFC 9180, HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) | Standardized hybrid public-key encryption with explicit modes/context | Arc sender authorization and composition still need review; base mode alone does not authenticate sender |
| [RFC 8949, CBOR, section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) | Deterministic encoding requires preferred serialization, no indefinite lengths and specified map-key ordering | Arc must restrict schemas and reject ambiguous/invalid inputs beyond generic decoding |
| [Noise framework](https://noiseprotocol.org/noise.html), revision 34 | Handshake/transport framework with static/ephemeral keys and pattern-dependent properties | Trust binding, application negotiation and chosen library remain Arc responsibilities |

## 6. Review and verification record

Prepared from the user clarification, the archived README at the pinned revision above and focused primary-source research. Separate security/key-lifecycle and replication/transport design contributions informed this draft; the integrated documents are the review target. Their proposals were reconciled where they differed: public closure indexes for blind completeness, independent validation/persistence axes, snapshot absence instead of a separate tombstone log, fixed epoch frontiers and preserved conflicts, and new-collection migration instead of automatic policy-fork repair.

The two contributors then reviewed the integrated security, synchronization and relevant operational sections. Their concrete findings led to explicit migration preflight and emergency blocked states, safe handling of oversized frontiers, retraction of stale current-state summaries without altering restored files, separate GC dependency classes, finite index-shape proposals, an unsupported-until-specified SMS profile and a recovery-kit authority clarification. The integration owner checked those amendments. This is a bounded design-consistency review, not a cryptographic audit, proof of convergence or independent review of every final sentence.

No new runtime code, service, network adapter, key material, sample financial data or production collection was created. No build, runtime behavior, cryptographic test, performance measurement or recovery drill has been performed. Documentation consistency and local links are checked separately during task completion. Repository publication status belongs in the task handoff; a pushed review branch is not a merged design or user approval.
