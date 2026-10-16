# Arc

Arc is being redesigned from the ground up as an archive system for material people want to preserve and control. The original Rust prototype is preserved on a separate branch.

This checkout is a fresh design starting point. It contains no executable implementation, installer, networking service or AI integration. The direction below is proposed for discussion; storage formats, interfaces and security guarantees remain to be designed and tested.

## Proposed direction

Start with a local archive that can retain original material, identify exact versions, verify stored bytes and restore them reliably. Rust is the proposed implementation language, continuing the project's original direction.

Preservation should be understandable: what was saved, where it came from, which version is being used, what changed and what can actually be recovered. Encryption and key management need an explicit threat model and recovery design. Integrity verification, authorship, capture time and the truth of a document's claims are different properties; a content hash alone does not prove all of them.

Transport, collaboration and AI-assisted discovery can build on that foundation when concrete use cases justify them. The redesign does not inherit claims of anonymous networking, verified chain of custody, regulatory compliance or resilience at scale from the prototype's README.

## How Arc could work with Luma

[Luma](https://github.com/lukeanthony007/luma) helps a person develop understanding, maintain an editable wiki and carry purposeful work across conversations. Arc could provide an optional preservation layer for the material that understanding depends on.

The proposed division is:

- **Arc:** preserve source bytes and versions, provide stable references, and report what has been verified or remains unavailable.
- **Luma:** interpret sources, connect ideas, maintain explanations and decisions, and help the person choose what to do next.
- **The person:** decide what to retain, what can be shared, and how the knowledge and archive should be used.

For example, a person could retain a research report in Arc and ask Luma to explain it. A wiki page could reference the exact archived version and relevant passage. When a revised report arrives, the old version would remain available while Luma examines how the new evidence affects its explanation. This is an illustrative workflow, not a working integration.

A useful interface would let Luma inspect archive metadata, retrieve an authorized version and check its integrity without exposing encryption keys to the model. Provenance should distinguish the original source, capture date, source revision when known, and any extraction or transformation used for analysis. Original bytes and generated text need separate identities.

The wiki remains editable and portable Markdown. Arc could also preserve explicitly requested wiki snapshots, but restoring an older snapshot must not silently overwrite current human edits. An archive reference is not an access grant, and archiving material does not authorize sending it to an AI provider.

Luma should remain useful with ordinary files and no Arc installation. Arc should remain useful without Luma or an LLM. Integration should not create two competing authoritative copies of the user's current knowledge.

## Questions for the redesign

The first step is to choose a concrete user and preservation problem. Candidate uses include a personal research collection, a creative archive or a team's controlled document library. Their recovery, sharing and retention needs may differ.

Before implementing the storage format, settle:

- What an archive owns: originals, versions, metadata and optional derived artifacts.
- How stable references, complete snapshots and safe restore behave, including interruptions and conflicting files.
- What encryption protects, where keys live, and how access, recovery and revocation work.
- How a user verifies preservation and rehearses recovery with suitable test material.
- Which local read operations a Luma integration actually needs, and how access and extraction limits are communicated.

The first useful demonstration should show a file being retained, retrieved and verified, with corruption and failed restoration handled explicitly. A later Luma demonstration could show an explanation tracing back to that exact version and being reconsidered when a new version appears. These are proposed acceptance scenarios, not completed tests.

## Original prototype

The original code, tests, build files and README are preserved unchanged on [`archive/rust-prototype`](https://github.com/lukeanthony007/arc/tree/archive/rust-prototype), at commit `5f529a07af44b4fba02715aa0fa5a37eab06a11d`.

That branch contains the earlier Rust CLI and its historical claims and instructions. It is reference material for the redesign. There is no archive directory or legacy executable in this checkout.

Git history still contains the prototype. A shallow, single-branch clone of the desired redesign branch avoids fetching its old history; moving files to an archive branch does not erase existing Git objects.

## License

[MIT](LICENSE). The existing copyright notice and license text are retained unchanged.
