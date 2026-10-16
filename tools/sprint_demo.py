#!/usr/bin/env python3
"""Disposable single-host CLI acceptance. This is NOT a two-device/hardware result."""
import argparse
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import tempfile


def exercise(binary, root):
    password = secrets.token_urlsafe(24)
    operations = 0

    def call(*args, private=False, succeeds=True):
        nonlocal operations
        result = subprocess.run(
            [str(binary)] + (["--password-stdin"] if private else []) + [str(a) for a in args],
            input=password + "\n" if private else None,
            text=True, capture_output=True, timeout=60,
        )
        operations += 1
        if (result.returncode == 0) != succeeds:
            raise RuntimeError(f"Unexpected result for {args[0]}: {result.stderr.strip()}")
        return result.stdout

    def value(output, label):
        found = re.search(rf"^{label} ([0-9a-f]{{64}})$", output, re.M)
        if not found:
            raise RuntimeError(f"Missing {label} in CLI output")
        return found.group(1)

    admin, member = root / "admin", root / "member"
    genesis = value(call("init", admin, private=True), "genesis")
    call("enable-policy", admin, private=True)
    device = value(call("device-request", root / "writer.key", root / "writer.req", private=True), "device_public")
    call("grant", admin, root / "writer.req", root / "invitation", "writer", private=True)
    call("join", member, root / "writer.key", root / "invitation", "--trust-genesis", genesis, private=True)
    source_a, source_b = root / "source-a", root / "source-b"
    source_a.mkdir()
    source_b.mkdir()
    payload = bytes(range(251)) * 1300
    for source in (source_a, source_b):
        (source / "payload.bin").write_bytes(payload)
        (source / "note.txt").write_text("base\n")
    base = value(call("capture", admin, source_a, private=True), "snapshot")
    call("export", admin, base, root / "usb.arc")
    call("import", member, root / "usb.arc")
    call("select", member, base)
    (source_a / "note.txt").write_text("administrator offline edit\n")
    head_a = value(call("capture", admin, source_a, private=True), "snapshot")
    (source_b / "note.txt").write_text("writer offline edit\n")
    head_b = value(call("capture", member, source_b, private=True), "snapshot")
    pub_a = value(call("network-identity", root / "net-a.key", private=True), "transport_public")
    pub_b = value(call("network-identity", root / "net-b.key", private=True), "transport_public")
    server = subprocess.Popen(
        [str(binary), "--password-stdin", "serve-once", str(member), "127.0.0.1:0", str(root / "net-b.key"), pub_a],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        server.stdin.write(password + "\n")
        server.stdin.close()
        server.stdin = None
        with selectors.DefaultSelector() as selector:
            selector.register(server.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError("Listener did not report readiness")
            ready = server.stdout.readline().strip()
        if not re.fullmatch(r"listening 127\.0\.0\.1:\d+", ready):
            raise RuntimeError("Unexpected listener readiness output")
        call("sync", admin, ready.split()[1], root / "net-a.key", pub_b, private=True)
        _, error = server.communicate(timeout=30)
        operations += 1
        if server.returncode:
            raise RuntimeError(f"Listener failed: {error.strip()}")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)
    heads = call("history", admin)
    if head_a not in heads or head_b not in heads:
        raise RuntimeError("Offline branches were not retained")
    call("diff", admin, head_a, head_b, private=True)
    resolved = root / "resolved"
    resolved.mkdir()
    (resolved / "payload.bin").write_bytes(payload)
    (resolved / "note.txt").write_text("explicitly resolved result\n")
    merged = value(call("merge", admin, resolved, "--parents", head_a, head_b, private=True), "snapshot")
    call("revoke", admin, device, root / "rotation", private=True)
    fresh = value(call("capture", admin, resolved, private=True), "snapshot")
    (source_b / "note.txt").write_text("late work from revoked writer\n")
    late = value(call("capture", member, source_b, private=True), "snapshot")
    call("export", member, late, root / "late.arc")
    call("import", admin, root / "late.arc")
    call("verify", admin, late, "--decrypt", private=True, succeeds=False)
    call("recovery-export", admin, root / "complete.recovery", private=True)
    recovered = root / "recovered"
    call("recover", recovered, root / "complete.recovery", "--trust-genesis", genesis, private=True)
    if "selected=true" in call("history", recovered):
        raise RuntimeError("Recovery unexpectedly selected a working head")
    for label, snapshot in (("historical", merged), ("current", fresh)):
        call("verify", recovered, snapshot, "--decrypt", private=True)
        destination = root / f"restore-{label}"
        call("restore", recovered, snapshot, destination, private=True)
        if (destination / "payload.bin").read_bytes() != payload:
            raise RuntimeError("Restored binary mismatch")
        if (destination / "note.txt").read_bytes() != (resolved / "note.txt").read_bytes():
            raise RuntimeError("Restored text mismatch")
    call("repair", recovered, private=True)
    call("bluetooth-sync", "--help")
    print(f"PASS: {operations} CLI operations; independent identities, offline branches, loopback exchange,")
    print("explicit merge, revoked-writer rejection and complete historical/current recovery verified.")
    print("This used one host and disposable files. Physical devices, USB hardware and Bluetooth were not exercised.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/arc"))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="arc-sprint-demo-") as directory:
        exercise(binary, Path(directory))
    print("Temporary fixtures removed; foreground listener stopped.")


if __name__ == "__main__":
    main()
