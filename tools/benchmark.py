#!/usr/bin/env python3
"""Measure disposable local Arc CLI workloads; no radio or external peer is used."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fixture(path, size, seed):
    rng = random.Random(seed)
    block = bytes(rng.randrange(256) for _ in range(65536))
    with path.open('wb') as f:
        left = size
        while left:
            part = block[:min(left, len(block))]
            f.write(part)
            left -= len(part)


def measured(args, password, timeout):
    timer = shutil.which('time')
    if not timer:
        raise RuntimeError('GNU time is required for per-process peak RSS measurement')
    wrapped = [timer, '-f', '__ARC_RSS_KIB=%M', '--', *args]
    started = time.monotonic()
    proc = subprocess.Popen(wrapped, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(password + '\n', timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise RuntimeError(f'timed out: {args[1:]}')
    elapsed = time.monotonic() - started
    match = re.search(r'^__ARC_RSS_KIB=(\d+)$', err, re.M)
    err = re.sub(r'^__ARC_RSS_KIB=\d+\n?', '', err, flags=re.M)
    if proc.returncode:
        raise RuntimeError(f'command failed ({proc.returncode}): {args[1:]}: {err.strip()}')
    if not match:
        raise RuntimeError('GNU time did not report peak RSS')
    return {'command': [str(x) for x in args], 'seconds': elapsed,
            'peak_rss_kib': int(match.group(1)), 'stdout': out.strip()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=Path('target/release/arc'))
    p.add_argument('--output', type=Path, help='write JSON evidence here; default prints JSON')
    p.add_argument('--quick', action='store_true', help='smaller fixtures; full mode includes 96 MiB')
    p.add_argument('--timeout', type=float, default=300)
    a = p.parse_args()
    binary = a.binary.resolve()
    if not binary.is_file():
        p.error(f'Arc binary not found: {binary}')
    if a.output and a.output.exists():
        p.error('output already exists; preserve earlier evidence')
    small_count, large_size = (24, 8 * 1024 * 1024) if a.quick else (256, 96 * 1024 * 1024)
    if not a.timeout > 0:
        p.error('--timeout must be positive')
    results = []
    password = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='arc-benchmark-') as temp:
        root = Path(temp)
        node, source = root / 'node', root / 'source'
        source.mkdir()
        def run(*args):
            row = measured([str(binary), '--password-stdin', *map(str, args)], password, a.timeout)
            results.append(row)
            return row['stdout']
        genesis = re.search(r'^genesis ([0-9a-f]{64})$', run('init', node), re.M).group(1)
        for i in range(small_count):
            fixture(source / f'small-{i:04}.bin', 4096, i)
        large = source / 'large.bin'
        fixture(large, large_size, 9001)
        dataset_bytes = sum(x.stat().st_size for x in source.iterdir())
        def store_stats():
            files = [x for x in (node / 'objects').iterdir() if x.is_file()]
            return {'objects': len(files), 'bytes': sum(x.stat().st_size for x in files)}
        before_capture = store_stats()
        capture1 = run('capture', node, source)
        snap1 = capture1.split('snapshot ')[-1].splitlines()[0]
        first_capture_stats = store_stats()
        run('capture', node, source)
        unchanged_stats = store_stats()
        with (source / 'small-0000.bin').open('ab') as f:
            f.write(b'changed')
        capture3 = run('capture', node, source)
        snap3 = capture3.split('snapshot ')[-1].splitlines()[0]
        changed_stats = store_stats()
        kit = root / 'backup.arc'
        run('recovery-export', node, kit)
        restored_node = root / 'recovered'
        run('recover', restored_node, kit, '--trust-genesis', genesis)
        inventory_stats = changed_stats
        restored = root / 'restored'
        run('restore', restored_node, snap3, restored)
        expected_hashes = {str(path.relative_to(source)): digest(path) for path in source.rglob('*') if path.is_file()}
        actual_hashes = {str(path.relative_to(restored)): digest(path) for path in restored.rglob('*') if path.is_file()}
        if expected_hashes != actual_hashes:
            raise RuntimeError('restored collection paths or file bytes mismatch')
        actual = restored / 'large.bin'
        run('verify', restored_node, snap3, '--decrypt')
        metadata = {'binary': str(binary), 'os': platform.platform(), 'python': platform.python_version(),
                    'compiler': (subprocess.run(['rustc', '--version'], capture_output=True, text=True).stdout.strip() or 'unavailable') if shutil.which('rustc') else 'unavailable',
                    'build_profile': 'release (expected from default binary path; build provenance not embedded)',
                    'quick': a.quick, 'file_count': small_count + 1, 'fixture_bytes': dataset_bytes,
                    'large_file_bytes': large_size, 'large_sha256': digest(actual),
                    'backup_bytes': kit.stat().st_size, 'recovered_all_file_hashes_equal': True,
                    'binary_sha256': digest(binary),
                    'object_count': inventory_stats['objects'], 'object_bytes': inventory_stats['bytes'],
                    'initial_capture_object_delta': first_capture_stats['objects'] - before_capture['objects'],
                    'initial_capture_byte_delta': first_capture_stats['bytes'] - before_capture['bytes'],
                    'unchanged_capture_object_delta': unchanged_stats['objects'] - first_capture_stats['objects'],
                    'unchanged_capture_byte_delta': unchanged_stats['bytes'] - first_capture_stats['bytes'],
                    'changed_capture_object_delta': changed_stats['objects'] - unchanged_stats['objects'],
                    'changed_capture_byte_delta': changed_stats['bytes'] - unchanged_stats['bytes'],
                    'snapshot_ids': [snap1, snap3], 'commands': results,
                    'limitations': 'single-host CLI only; no radio, peer, or short-contact simulator; GNU time supplies each subprocess peak RSS'}
    encoded = json.dumps(metadata, indent=2, sort_keys=True) + '\n'
    if a.output:
        with a.output.open('x') as stream:
            stream.write(encoded)
    else:
        print(encoded, end='')

if __name__ == '__main__':
    main()
