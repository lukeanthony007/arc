# Five milestone acceptance contract

This work extends the experimental Arc core. This page states the required observable results; it does not claim a feature works merely because its API exists. The implementation handoff records actual checks and outstanding limitations.

| Milestone | Required observable result |
| --- | --- |
| History and selection | List locally known signed versions and heads, compare authorized plaintext manifests, explicitly select a restored/imported base without deleting competing versions |
| Ciphertext reuse | Unchanged captured blocks retain exact encrypted object IDs; editing one block replaces that block while preserving other blocks; no public plaintext deduplication index |
| Independent devices | Reader/writer keys differ from the collection root; enrollment binds the pinned collection, recipient and signed permission; readers cannot publish; revoked members cannot obtain fresh content keys or promote late updates under the known policy |
| Conflicts and merge | Two offline writers produce retained sibling heads; selecting one does not delete the other; a deliberate resolved-directory merge names both parents and becomes their descendant |
| Live transfer | Explicit authenticated foreground session over loopback/IP, pinned peer identity before inventory disclosure, missing-object exchange, no automatic trust/head promotion, repeat transfer sends no existing objects and interrupted work resumes by verified IDs |

A constrained-link test must exercise limited payload size, loss, duplication, reordering and interrupted contacts using the same immutable object identities/validation. A simulator does not establish working Bluetooth, radio or SMS support. Actual adapters remain separately qualified work.

Policy and live-session authentication have different responsibilities. A peer possessing the pinned network key does not gain collection write permission. Imported records remain subject to signed collection authority and content verification. Offline revocation is not instantaneous: policy checkpoints, fixed accepted frontiers and preserved rejected/late work must have explicit behavior.

All existing single-root offline tests remain regression requirements unless an explicit experimental-format migration changes the contract. Passwords and new device private keys must stay in protected containers; invitations must not copy the administrative signing seed to a member. No external peer, provider account or paid carrier is authorized for the local acceptance exercises.
