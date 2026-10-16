#!/usr/bin/env python3
"""Build and package a clean Arc revision locally; never publishes a release."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New .tar.gz file; existing files are preserved')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve() != root:
        parser.error('run from the repository root')
    if args.output.exists():
        parser.error('output already exists')
    if command('git', 'status', '--porcelain=v1', '--untracked-files=all'):
        parser.error('package only a clean committed checkout')
    revision = command('git', 'rev-parse', 'HEAD')
    epoch = int(command('git', 'show', '-s', '--format=%ct', 'HEAD'))
    rustc = command('rustc', '-vV')
    host = next(line.removeprefix('host: ') for line in rustc.splitlines() if line.startswith('host: '))
    build = ['cargo', 'build', '--release', '--locked', '--bin', 'arc', '--target', host,
             '--message-format=json-render-diagnostics']
    result = subprocess.run(build, check=True, text=True, stdout=subprocess.PIPE)
    artifacts = [row for line in result.stdout.splitlines() if line.startswith('{')
                 and (row := json.loads(line)).get('reason') == 'compiler-artifact'
                 and row.get('target', {}).get('name') == 'arc' and row.get('executable')]
    if len(artifacts) != 1:
        raise RuntimeError('Cargo did not report exactly one Arc executable')
    binary = Path(artifacts[0]['executable']).resolve(strict=True)
    if binary.is_symlink() or not binary.is_file():
        raise RuntimeError('Cargo artifact is not a regular executable')
    with binary.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    manifest = {'kind': 'experimental-linux-binary', 'revision': revision,
                'source_date_epoch': epoch, 'architecture': platform.machine(), 'target': host,
                'rustc': rustc, 'cargo': command('cargo', '--version'),
                'binary_sha256': digest, 'build': build,
                'independent_security_audit': False, 'stable_protocol': False,
                'reproducibility': 'archive timestamps/ownership normalized; binary reproducibility not established'}
    paths = ['README.md', 'LICENSE', 'DESIGN.md', 'Cargo.toml', 'Cargo.lock']
    paths += command('git', 'ls-files', 'docs/*.md', 'tools/*.py').splitlines()
    label = f'arc-experimental-{revision[:12]}-{host}'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.arc-package-', dir=args.output.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            with gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    def add(name, data, mode=0o644):
                        info = tarfile.TarInfo(f'{label}/{name}')
                        info.size = len(data); info.mode = mode; info.mtime = epoch
                        info.uid = info.gid = 0; info.uname = info.gname = ''
                        archive.addfile(info, io.BytesIO(data))
                    add('bin/arc', binary.read_bytes(), 0o755)
                    add('manifest.json', (json.dumps(manifest, indent=2, sort_keys=True)+'\n').encode())
                    add('SHA256SUMS', f'{digest}  bin/arc\n'.encode())
                    for name in sorted(set(paths)):
                        path = root / name
                        if path.is_symlink() or not path.is_file():
                            raise RuntimeError(f'unsafe package input: {name}')
                        add(name, path.read_bytes(), 0o755 if name.startswith('tools/') else 0o644)
            stream.flush(); os.fsync(stream.fileno())
        # Exclude only our exact staging file, including when output is inside
        # the worktree; all other tracked/untracked source changes still count.
        status_args = ['git', 'status', '--porcelain=v1', '--untracked-files=all', '--', '.']
        try:
            own_path = Path(temporary).resolve().relative_to(root)
        except ValueError:
            pass
        else:
            status_args.append(f':(exclude,literal){own_path}')
        if command(*status_args) or command('git', 'rev-parse', 'HEAD') != revision:
            raise RuntimeError('source changed during packaging; artifact not published')
        os.link(temporary, args.output)
        with args.output.open('rb') as stream:
            package_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        print(f'{package_digest}  {args.output}')
    finally:
        os.unlink(temporary)


if __name__ == '__main__':
    main()
