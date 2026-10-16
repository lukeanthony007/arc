# CLI benchmarks

Build the real executable, then run the disposable local driver:

```sh
cargo build --release --locked
python3 tools/benchmark.py --binary target/release/arc --output target/benchmark-results.json
```

Use `--quick` for smaller routine fixtures; the default exercises a 96 MiB file and 256 small files. `--timeout` bounds each CLI process. GNU `time` must be available on `PATH` and records each process's peak RSS in KiB. JSON records command, OS/Python/compiler metadata, fixture sizes, stored object count and bytes, snapshot IDs, and wall-clock durations. The release profile is reported as expected for the default binary path, not proven embedded build provenance.

The driver creates a private temporary workspace and removes it on completion; passwords are random, supplied over stdin, and not recorded. A nonzero command or timeout fails the run. It captures unchanged and modified content, recovery-exports and recovers a node, restores the collection and compares every relative file path and SHA-256 using streaming reads. No massive fixture is loaded into Python RAM. Output records the binary hash and backup size; the unchanged-capture delta starts after the initial capture. Existing evidence files are never overwritten. Review local output before publishing it.

Measure repeated short contacts through the actual durable fragment receiver separately:

```sh
cargo run --release --locked --example contact_benchmark > target/contact-benchmark.json
```

This transfers four deterministic 64 KiB opaque objects with a 4,096-byte MTU, seven attempted fragments per contact, every fifth attempted fragment dropped, every fourth duplicated and two-fragment reordering. It reopens the receiver each contact, requires retained partial progress and compares exact completed bytes. JSON records elapsed time, contacts, attempted fragments and contacts that reused partial state. Framing overhead, airtime, radio discovery, battery and actual link speed are not modeled.

These are local single-host measurements, not two-host convergence or physical device evidence. KDF work is included in CLI timings rather than isolated as an identity-KDF microbenchmark. Filesystem caching, CPU scaling, storage and build configuration affect results. The full dataset is a baseline, not a throughput guarantee or a statistical comparison; repeat on the target machine to guide optimization. This experimental application is not audited.


## Measured release-build baseline

The 2026-10-16 readiness run used Linux 7.2.9 x86_64, glibc 2.44, Rust 1.99.0 and the locked release build. Its disposable collection contained one 96 MiB file and 256 4 KiB files (97 MiB before a seven-byte edit). All restored paths and SHA-256 hashes matched. One full run, warm local filesystem caches and concurrent system activity are not controlled laboratory conditions.

| Operation | Wall seconds | Peak RSS (KiB) |
|---|---:|---:|
| Initial capture | 2.15 | 69,736 |
| Unchanged capture | 3.35 | 69,736 |
| Capture after small edit | 3.32 | 69,620 |
| Complete backup export | 1.17 | 69,756 |
| Complete recovery | 1.46 | 69,752 |
| Restoring the collection | 2.11 | 69,760 |

The backup held 102,397,212 encoded bytes and 1,800 objects, exceeding the former 64 MiB container ceiling. Export/recovery peak RSS stayed near the fixed Argon2 workspace plus bounded buffers. This observation supports the implementation's bounded-memory design for this workload; it does not measure the full 16 GiB limit.

An unchanged capture added two objects / 145,093 bytes; the small edit added three objects / 149,278 bytes. Reuse saves content storage, but unchanged capture was slower than initial capture in this run. Timing of prior-state validation and chunk comparison is a useful next profiling target; these figures alone do not identify the dominant function.

Raw local evidence is emitted to the requested JSON path, with command timings, exact sizes and binary hash. The run's binary SHA-256 was `57b238cac719df155cb41c27d0199437fd1cff0b39654f44914a65f210de3cc5`. Temporary fixtures were removed. This is synthetic benchmark evidence, not user collection data.

The separate short-contact run converged in 11 contacts and 74 attempted fragments, with retained partial progress reused on 10 contacts. Exact bytes matched after 0.045 seconds of local execution. This is receiver/simulator timing, not a wireless throughput figure.
