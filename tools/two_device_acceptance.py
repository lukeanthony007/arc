#!/usr/bin/env python3
"""Disposable Arc acceptance on two Linux hosts over SSH, or explicitly local rehearsal.

SSH transports setup artifacts over an already trusted host connection. Arc snapshot
exchange itself uses pinned Noise over the requested LAN or prepared RFCOMM link.
No discovery, pairing, package installation or persistent service is performed.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import subprocess
import sys
import tempfile
import time

# This small allowlisted helper runs on the peer. Paths must stay within the
# private fixture directory created by this run; cleanup requires its random tag.
REMOTE = r'''
import base64, hashlib, json, os, pathlib, shutil, tempfile
p=json.load(__import__('sys').stdin)
op=p['op']
if op=='create':
    root=pathlib.Path(tempfile.mkdtemp(prefix='arc-acceptance-'))
    (root/'.owner').write_text(p['tag'])
    print(json.dumps(str(root)))
else:
    root=pathlib.Path(p['root'])
    assert root.is_absolute() and root.name.startswith('arc-acceptance-')
    assert (root/'.owner').read_text()==p['tag']
    def child(name):
        assert name and not pathlib.PurePath(name).is_absolute() and '..' not in pathlib.PurePath(name).parts
        result=root/name
        assert result.resolve().is_relative_to(root.resolve())
        return result
    if op=='write':
        name=child(p['name'])
        name.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f: f.write(base64.b64decode(p['data'],validate=True))
        result=True
    elif op=='read':
        name=child(p['name'])
        assert name.stat().st_size<=16*1024*1024
        result=base64.b64encode(name.read_bytes()).decode()
    elif op=='fixture':
        folder=child(p['name']); folder.mkdir()
        (folder/'note.txt').write_text(p['note'])
        with (folder/'payload.bin').open('wb') as f:
            for n in range(64): f.write(hashlib.shake_256(str(n).encode()).digest(8192))
        result=True
    elif op=='edit':
        child(p['name']).write_text(p['text']); result=True
    elif op=='remove':
        child(p['name']).unlink(); result=True
    elif op=='hashes':
        folder=child(p['name']); result={}
        for name in sorted(folder.rglob('*')):
            assert not name.is_symlink()
            if name.is_file():
                h=hashlib.sha256()
                with name.open('rb') as f:
                    while b:=f.read(65536): h.update(b)
                result[str(name.relative_to(folder))]=h.hexdigest()
    elif op=='cleanup':
        shutil.rmtree(root); result=True
    else: raise ValueError('unknown operation')
    print(json.dumps(result))
'''

# Keep the owned Arc child bounded even if SSH disconnects; signals terminate
# only its fresh process group. The password is never a command-line argument.
ARC_PROCESS = r'''
import json, os, signal, subprocess, sys
argv=json.loads(sys.argv[1])
secret=sys.stdin.buffer.readline(4098) if '--password-stdin' in argv else None
child=subprocess.Popen(argv,stdin=subprocess.PIPE if secret is not None else subprocess.DEVNULL,start_new_session=True)
def stop(signum=None, frame=None):
    if child.poll() is None:
        os.killpg(child.pid,signal.SIGTERM)
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL); child.wait()
    raise SystemExit(124)
for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT): signal.signal(sig,stop)
try:
    child.communicate(input=secret,timeout=80)
except subprocess.TimeoutExpired: stop()
raise SystemExit(child.returncode)
'''


class Host:
    def __init__(self, binary, peer=None):
        self.binary = str(binary)
        self.peer = peer
        self.root = None
        self.tag = secrets.token_hex(24)

    def command(self, argv):
        if self.peer:
            return ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '--',
                    self.peer, 'exec ' + shlex.join([str(a) for a in argv])]
        return [str(a) for a in argv]

    def helper(self, op, **values):
        payload = dict(op=op, root=self.root, tag=self.tag, **values)
        result = subprocess.run(self.command(['python3', '-c', REMOTE]),
                                input=json.dumps(payload), text=True,
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f'Peer fixture operation {op} failed: {result.stderr.strip()}')
        return json.loads(result.stdout)

    def create(self):
        self.root = self.helper('create')

    def path(self, name):
        return str(Path(self.root) / name)

    def arc_argv(self, args, private):
        argv = [self.binary] + (['--password-stdin'] if private else []) + list(args)
        return self.command(['python3', '-c', ARC_PROCESS, json.dumps(argv)])

    def call(self, password, *args, private=False, rejection=None):
        result = subprocess.run(self.arc_argv(args, private), text=True,
                                input=password + '\n' if private else None,
                                capture_output=True, timeout=90)
        if rejection is None:
            accepted = result.returncode == 0
        else:
            accepted = result.returncode == 1 and rejection in result.stderr
        if not accepted:
            raise RuntimeError(f'{args[0]} returned unexpected status {result.returncode}: {result.stderr.strip()}')
        return result.stdout


def token(output, label):
    match = re.search(rf'^{re.escape(label)} ([0-9a-f]{{64}})$', output, re.M)
    if not match:
        raise RuntimeError(f'Missing public {label} output')
    return match.group(1)


def copy(a, b, name):
    b.helper('write', name=name, data=a.helper('read', name=name))


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def exchange(a, b, password, pub_a, pub_b, address, endpoints):
    if endpoints:
        server_args = ('bluetooth-sync', b.path('node'), endpoints[1], b.path('network.key'), pub_a, '--respond')
    else:
        server_args = ('serve-once', b.path('node'), '0.0.0.0:0', b.path('network.key'), pub_a)
    process = subprocess.Popen(b.arc_argv(server_args, True), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        process.stdin.write(password + '\n')
        process.stdin.close()
        process.stdin = None
        if endpoints:
            # No readiness output for RFCOMM; the authenticated initiator and
            # responder may start concurrently on an already prepared stream.
            output = a.call(password, 'bluetooth-sync', a.path('node'), endpoints[0],
                            a.path('network.key'), pub_b, private=True)
        else:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(20):
                    raise RuntimeError('Peer listener did not report readiness')
                ready = process.stdout.readline().strip()
            match = re.fullmatch(r'listening 0\.0\.0\.0:(\d+)', ready)
            if not match:
                raise RuntimeError(f'Unexpected peer listener output: {ready}')
            output = a.call(password, 'sync', a.path('node'), f'{address}:{match.group(1)}',
                            a.path('network.key'), pub_b, private=True)
        _, error = process.communicate(timeout=35)
        if process.returncode:
            raise RuntimeError(f'Peer exchange failed: {error.strip()}')
        return output.strip()
    finally:
        stop(process)


def exercise(args, report):
    password = secrets.token_urlsafe(32)
    local = Host(args.binary.resolve(strict=True))
    peer = Host(args.peer_binary or local.binary, args.peer)
    report['scope'] = 'two-host SSH-orchestrated acceptance' if args.peer else 'single-host rehearsal'
    report['physical_two_device_qualification'] = False
    report['steps'] = {}
    steps = report['steps']
    try:
        local.create()
        peer.create()
        versions = [h.call(password, '--version').strip() for h in (local, peer)]
        if versions[0] != versions[1]:
            raise RuntimeError('CLI versions differ; build the same source revision on both hosts')
        report['versions'] = versions
        genesis = token(local.call(password, 'init', local.path('node'), private=True), 'genesis')
        local.call(password, 'enable-policy', local.path('node'), private=True)
        if 'freshness unknown' not in local.call(password, 'status', local.path('node')):
            raise RuntimeError('Status did not preserve unknown global freshness')
        local.call(password, 'doctor', local.path('node'))
        writer = token(peer.call(password, 'device-request', peer.path('writer.key'),
                                 peer.path('writer.req'), private=True), 'device_public')
        copy(peer, local, 'writer.req')
        local.call(password, 'grant', local.path('node'), local.path('writer.req'),
                   local.path('invitation'), 'writer', private=True)
        copy(local, peer, 'invitation')
        peer.call(password, 'join', peer.path('node'), peer.path('writer.key'),
                  peer.path('invitation'), '--trust-genesis', genesis, private=True)
        steps['independent_identities'] = 'passed'
        local.helper('fixture', name='source', note='base\n')
        base = token(local.call(password, 'capture', local.path('node'), local.path('source'), private=True), 'snapshot')
        local.call(password, 'export', local.path('node'), base, local.path('base.arc'))
        copy(local, peer, 'base.arc')
        peer.call(password, 'import', peer.path('node'), peer.path('base.arc'))
        peer.call(password, 'restore', peer.path('node'), base, peer.path('source'), private=True)
        peer.call(password, 'select', peer.path('node'), base)
        if local.helper('hashes', name='source') != peer.helper('hashes', name='source'):
            raise RuntimeError('Base restore mismatch')
        steps['bundle_and_exact_restore'] = 'passed over SSH; physical USB not exercised'
        local.helper('edit', name='source/note.txt', text='administrator offline change\n')
        peer.helper('edit', name='source/note.txt', text='writer offline change\n')
        heads = [token(h.call(password, 'capture', h.path('node'), h.path('source'), private=True), 'snapshot')
                 for h in (local, peer)]
        pubs = [token(h.call(password, 'network-identity', h.path('network.key'), private=True), 'transport_public')
                for h in (local, peer)]
        steps['carrier_exchange_output'] = exchange(local, peer, password, *pubs, args.address, args.rfcomm)
        history = local.call(password, 'history', local.path('node'))
        if not all(head in history for head in heads):
            raise RuntimeError('Offline branches were not both retained')
        local.helper('edit', name='source/note.txt', text='explicit resolution\n')
        merge = token(local.call(password, 'merge', local.path('node'), local.path('source'),
                                 '--parents', *heads, private=True), 'snapshot')
        steps['offline_branches_and_merge'] = 'passed'
        local.call(password, 'revoke', local.path('node'), writer, local.path('rotation'), private=True)
        current = token(local.call(password, 'capture', local.path('node'), local.path('source'), private=True), 'snapshot')
        peer.helper('edit', name='source/note.txt', text='late revoked writer change\n')
        late = token(peer.call(password, 'capture', peer.path('node'), peer.path('source'), private=True), 'snapshot')
        peer.call(password, 'export', peer.path('node'), late, peer.path('late.arc'))
        copy(peer, local, 'late.arc')
        local.call(password, 'import', local.path('node'), local.path('late.arc'))
        local.call(password, 'verify', local.path('node'), late,
                   rejection='snapshot outside accepted policy frontier')
        steps['revoked_writer_rejected'] = 'passed'
        local.call(password, 'recovery-export', local.path('node'), local.path('recovery.arc'), private=True)
        # Original administrator performs no more publication after backup.
        copy(local, peer, 'recovery.arc')
        peer.call(password, 'recover', peer.path('recovered'), peer.path('recovery.arc'),
                  '--trust-genesis', genesis, private=True)
        expected = local.helper('hashes', name='source')
        for label, snapshot in [('historical', merge), ('current', current)]:
            peer.call(password, 'verify', peer.path('recovered'), snapshot, '--decrypt', private=True)
            peer.call(password, 'restore', peer.path('recovered'), snapshot, peer.path(label), private=True)
            if peer.helper('hashes', name=label) != expected:
                raise RuntimeError(f'{label} recovered bytes mismatch')
        steps['recovery_on_peer_and_exact_history'] = 'passed'
        peer.call(password, 'status', peer.path('recovered'))
        peer.call(password, 'doctor', peer.path('recovered'))
        peer.helper('remove', name=f'recovered/objects/{genesis}')
        peer.call(password, 'doctor', peer.path('recovered'),
                  rejection='node diagnostics found errors')
        steps['diagnostics_and_missing_trust_rejection'] = 'passed; only disposable recovered fixture damaged'
        steps['physical_usb'] = 'not exercised'
        steps['interrupted_rfcomm_fragment_reuse'] = 'not exercised; use hardware runbook'
        steps['wrong_peer_pin'] = 'not exercised by this runner; covered separately by tests and hardware runbook'
        steps['bluetooth'] = ('exchange exercised on operator-prepared endpoints; radio provenance requires operator evidence'
                              if args.rfcomm else 'not exercised')
        report['result'] = 'passed scoped workflow; full hardware qualification remains separate'
    finally:
        clean = []
        for host in (peer, local):
            if host.root:
                try:
                    host.helper('cleanup')
                    clean.append(True)
                except Exception as error:
                    clean.append(False)
                    print(f'Fixture cleanup failed for {host.root}: {error}', file=sys.stderr)
        report['cleanup_complete'] = all(clean) and len(clean) == 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/arc'))
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--peer', help='Existing trusted SSH destination; BatchMode, no host-key bypass')
    scope.add_argument('--local-peer', action='store_true', help='Explicitly rehearse on one host; never qualifies hardware')
    parser.add_argument('--peer-binary', help='Absolute path to the same-revision Arc binary on peer')
    parser.add_argument('--address', default='127.0.0.1', help='Peer IPv4 LAN address; local rehearsal uses loopback')
    parser.add_argument('--rfcomm', nargs=2, metavar=('LOCAL_ENDPOINT', 'PEER_ENDPOINT'),
                        help='Use already prepared RFCOMM instead of LAN; never pairs or binds radios')
    parser.add_argument('--output', type=Path, required=True, help='New JSON evidence path; never overwritten')
    args = parser.parse_args()
    if args.peer and (not args.peer_binary or not Path(args.peer_binary).is_absolute()):
        parser.error('--peer requires absolute --peer-binary')
    if args.peer and not args.rfcomm and args.address == '127.0.0.1':
        parser.error('two-host LAN exchange requires --address PEER_IPV4')
    if args.peer and args.peer.startswith('-'):
        parser.error('SSH destination must not start with an option')
    if args.rfcomm and any(not re.fullmatch(r'/dev/rfcomm\d+', p) for p in args.rfcomm):
        parser.error('RFCOMM endpoints must be direct /dev/rfcommN paths')
    if args.output.exists():
        parser.error('evidence output already exists')
    report = {'schema': 1, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'result': 'failed', 'cleanup_complete': False}
    try:
        exercise(args, report)
    except Exception as error:
        report['error'] = str(error)
    report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(report['result'])
    if not report['cleanup_complete'] or report.get('error'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
