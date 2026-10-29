#!/usr/bin/env python3
"""Collect consistent VM and native-host snapshots without restarting services."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import tarfile

import deploy_control_plane as deploy
import vm_deploy_host as vm
import prepare_recovery_generation as recovery
from native_codex_ssh import load_profile as load_native_profile


def copy_private(source, target):
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError('Recovery source must be an operator-owned regular file')
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with source.open('rb') as original, target.open('xb') as result:
        shutil.copyfileobj(original, result)
    target.chmod(0o700 if metadata.st_mode & 0o111 else 0o600)


def unpack_snapshot(archive, destination):
    """Accept only bounded regular files/directories from the pinned VM."""
    with tarfile.open(archive, 'r:') as stream:
        members = stream.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 100 * 1024**3:
            raise ValueError('VM snapshot exceeds recovery limits')
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != 'vm-snapshot' or str(path) != member.name
                    or member.name in names or not (member.isfile() or member.isdir())):
                raise ValueError('VM snapshot contains an unsafe archive member')
            names.add(member.name)
        for member in members:
            path = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.chmod(0o700)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with stream.extractfile(member) as source, path.open('xb') as target:
                    shutil.copyfileobj(source, target)
                path.chmod(0o600)


def validate_memoryd_snapshot(snapshot_dir, descriptor):
    memoryd = snapshot_dir / 'memoryd'
    if descriptor == {'status': 'absent'}:
        if os.path.lexists(memoryd):
            raise ValueError('Absent MemoryD capture contains unexpected artifacts')
        return descriptor
    if (not isinstance(descriptor, dict) or descriptor.get('status') != 'captured'
            or descriptor.get('backend_image') != vm.MEMORYD_IMAGE
            or not isinstance(descriptor.get('adapter_image'), str)
            or not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}',
                                descriptor['adapter_image'])):
        raise ValueError('MemoryD capture descriptor is invalid')
    facts = vm._validate_memoryd_capture(memoryd)
    expected = {'status': 'captured', 'backend_image': descriptor['backend_image'],
                'adapter_image': descriptor['adapter_image'], **facts}
    if descriptor != expected:
        raise ValueError('Transported MemoryD artifacts do not match the capture descriptor')
    return descriptor


def collect(local_config, native_profile, instance_profile, output, tailnet_requirements=None):
    """Hold the existing deployment lock while snapshotting and transporting it."""
    output = Path(output)
    parent = output.parent.lstat()
    if (not output.is_absolute() or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
            or output.exists() or output.is_symlink()):
        raise ValueError('Recovery collection requires a new directory beneath a private parent')
    deploy.configure_local(Path(local_config), Path(instance_profile))
    deploy.trusted_context({}, local=True)
    native = load_native_profile(Path(native_profile))
    requirements = Path(tailnet_requirements) if tailnet_requirements else Path(instance_profile).parent / 'tailnet-requirements.json'
    metadata = requirements.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError('Private tailnet requirements must be an owned mode-0600 regular file')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    try:
        endpoint = output / 'native-endpoint'
        endpoint.mkdir(mode=0o700)
        state = Path(native['state_dir'])
        for name in ('ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'authorized_keys',
                     'sshd_config', 'native_codex_ssh.py'):
            copy_private(state / name, endpoint / name)
        unit = Path.home() / '.config/systemd/user/native-codex-ssh.service'
        copy_private(unit, endpoint / 'native-codex-ssh.service')
        profiles = output / 'instance-config'
        profiles.mkdir(mode=0o700)
        copy_private(Path(instance_profile), profiles / 'instance.json')
        copy_private(Path(native_profile), profiles / 'native-ssh.json')
        copy_private(requirements, profiles / 'tailnet-requirements.json')
        copy_private(Path(local_config), profiles / 'kamal-local.env')
        operator = output / 'operator-ssh'
        operator.mkdir(mode=0o700)
        for source, name in ((deploy.SSH, 'ssh_config'), (deploy.KEY, 'identity'), (deploy.KNOWN, 'known_hosts')):
            copy_private(source, operator / name)
        transport = output / '.vm-snapshot.tar'
        with deploy.lock():
            generation = deploy.remote('current')
            before = deploy.remote('snapshot')
            fields = ('authority', 'identity', 'source_sha')
            if (not isinstance(generation, dict)
                    or any(not generation.get(field) or generation.get(field) != before.get(field) for field in fields)):
                raise ValueError('Recorded generation differs from the live control plane; capture refused')
            snapshot = deploy.remote('backup', {'include_memoryd': True})
            expected = Path(deploy.INSTANCE['vm']['state_dir']) / 'deployment/backups'
            snapshot_path = Path(snapshot['backup'])
            if snapshot_path.parent != expected or not snapshot_path.name.isdigit():
                raise ValueError('VM returned an unexpected snapshot path')
            source = (
                'import os,pathlib,stat,sys,tarfile;'
                'p=pathlib.Path(sys.argv[1]);s=p.lstat();'
                'assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700;'
                't=tarfile.open(fileobj=sys.stdout.buffer,mode="w|");'
                't.add(p,arcname="vm-snapshot",recursive=True);t.close()'
            )
            command = deploy.ssh_args(shlex.join(['python3', '-c', source, str(snapshot_path)]))
            with transport.open('xb') as stream:
                result = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, timeout=900)
            if result.returncode:
                raise ValueError('Pinned VM snapshot transport failed; diagnostic withheld')
            after = deploy.remote('snapshot')
            if any(before.get(field) != after.get(field) for field in fields) or after['tunnel_count'] != 1:
                raise ValueError('Control-plane identity or tunnel ownership changed during backup')
        unpack_snapshot(transport, output)
        transport.unlink()
        executor = output / 'vm-snapshot/executor.tar'
        with executor.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != snapshot['executor_sha256']:
                raise ValueError('Transported Executor snapshot digest mismatch')
        memoryd = validate_memoryd_snapshot(output / 'vm-snapshot', snapshot.get('memoryd'))
        guard = snapshot.get('legacy_guard')
        essential = output / 'vm-snapshot/essential.tar'
        if guard is not None or essential.exists():
            try:
                entries = recovery._scan_tar(essential, guarded=guard is not None, essential=True)
                if guard is None:
                    recovery._reject_unguarded_legacy_artifacts(entries)
                else:
                    recovery._guard_archive(guard, entries, essential, memoryd, output / 'vm-snapshot/memoryd/backup.db')
            except recovery.GenerationError as error:
                raise ValueError('Transported legacy import guard is invalid') from error
        receipt = {'schema_version': 3 if guard is not None else 2, 'generation': generation,
                   'captured_at_utc': datetime.now(timezone.utc).isoformat(),
                   'executor_sha256': snapshot['executor_sha256'],
                   'identity_preserved': True, 'single_tunnel': True,
                   'capture_kind': 'executor-paused-copy-and-sqlite-online-backups',
                   'memoryd': memoryd}
        if guard is not None:
            receipt['legacy_guard'] = guard
        (output / 'capture-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        manifest = {'version': 1, 'bundle_id': output.name, 'members': [
            {'name': name, 'source': str(output / name), 'required': True}
            for name in ('native-endpoint', 'instance-config', 'operator-ssh', 'vm-snapshot')
        ] + [{'name': 'capture-receipt', 'source': str(output / 'capture-receipt.json'), 'required': True}]}
        (output / 'recovery-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        return output / 'recovery-manifest.json'
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-config', required=True)
    parser.add_argument('--native-profile', required=True)
    parser.add_argument('--instance-profile', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--tailnet-requirements', help='Private connectivity requirements; defaults beside the instance profile')
    args = parser.parse_args()
    try:
        manifest = collect(args.local_config, args.native_profile, args.instance_profile, args.output_dir, args.tailnet_requirements)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        parser.exit(1, 'Recovery collection refused; live services were not restarted.\n')
    print(json.dumps({'collected': True, 'manifest': str(manifest)}))


if __name__ == '__main__':
    main()
