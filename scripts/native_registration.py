"""Register native endpoints on an existing controller, under its deployment lock.

Only public descriptors cross the transport. Publication replaces individual bind
mount sources; callers MUST recreate CAS, verify it, then complete the transaction.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import struct
import subprocess
import tempfile
import uuid


FIELDS = {'schema_version', 'name', 'address', 'port', 'user', 'codex_bin', 'socket',
          'host_public_key', 'controller_fingerprint'}


def _key(value):
    if not isinstance(value, str) or '\n' in value or '\r' in value:
        raise ValueError('Invalid public key')
    parts = value.split()
    try:
        if len(parts) < 2 or parts[0] != 'ssh-ed25519':
            raise ValueError()
        blob = base64.b64decode(parts[1], validate=True)
        expected = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
        if len(blob) != len(expected) + 32 or not blob.startswith(expected):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Invalid ED25519 public key') from None
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode()


def _address(value):
    try:
        address = ipaddress.IPv4Address(value)
        if not isinstance(value, str) or str(address) != value or address not in ipaddress.IPv4Network('100.64.0.0/10'):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Expected an assigned Tailscale IPv4 address') from None
    return value


def validate_descriptor(value):
    if not isinstance(value, dict) or set(value) != FIELDS or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('Invalid native endpoint descriptor schema')
    result = dict(value)
    if not isinstance(result['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', result['name']) or result['name'].lower() == 'local':
        raise ValueError('Invalid or reserved target name')
    _address(result['address'])
    if type(result['port']) is not int or not 1024 <= result['port'] <= 65535:
        raise ValueError('Invalid endpoint port')
    if not isinstance(result['user'], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', result['user']):
        raise ValueError('Invalid endpoint user')
    for name in ('codex_bin', 'socket'):
        value = result[name]
        if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./+-]+', value) or '..' in PurePosixPath(value).parts or str(PurePosixPath(value)) != value:
            raise ValueError('Invalid endpoint path')
    result['host_public_key'] = _key(result['host_public_key'])
    if not isinstance(result['controller_fingerprint'], str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', result['controller_fingerprint']):
        raise ValueError('Invalid controller fingerprint')
    return result


def _directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('Unsafe registration directory')
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError('Symlink in registration path')


def _read(path):
    _directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError('Registration file unavailable or symlinked') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024:
            raise ValueError('Unsafe registration file ownership/mode/size')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(4 * 1024 * 1024 + 1)
    finally:
        os.close(fd)


def _write(path, content):
    _directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.native-registration-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


class Registration:
    def __init__(self, instance_profile):
        self.instance = instance_profile
        self.state = Path(instance_profile['vm']['state_dir'])
        self.native = Path(instance_profile['vm']['native_ssh_dir'])
        self.paths = {'targets': self.state / 'cas-targets.json',
                      'ssh_config': self.native / 'ssh_config.native',
                      'known_hosts': self.native / 'known_hosts.native'}
        self.store = self.state / 'native-registration'
        self.pending_path = self.store / 'pending.json'

    def _descriptor(self, descriptor):
        value = validate_descriptor(descriptor)
        if value['controller_fingerprint'] != self.instance['deploy_host']['host_key_fingerprint']:
            raise ValueError('Endpoint controller fingerprint mismatch')
        return value

    def info(self):
        _read(self.native / 'identity')
        result = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(self.native / 'identity')], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError('Controller native SSH identity unavailable')
        public_key = _key(result.stdout.strip())
        result = subprocess.run(['tailscale', 'ip', '-4'], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError('Controller Tailscale address unavailable')
        address = _address(result.stdout.strip())
        return {'address': address, 'public_key': public_key,
                'controller_fingerprint': self.instance['deploy_host']['host_key_fingerprint']}

    def _render(self, descriptor):
        value = self._descriptor(descriptor)
        before = {name: _read(path) for name, path in self.paths.items()}
        targets = json.loads(before['targets'])
        if not isinstance(targets, dict) or not isinstance(targets.get('targets'), dict) or not targets['targets']:
            raise ValueError('At least one existing target must be preserved')
        name, alias = value['name'], value['name'] + '-native'
        target = {'transport': 'ssh', 'destination': alias, 'codex_bin': value['codex_bin'],
                  'socket_path': value['socket'], 'ssh_config': '/run/codex-ssh/ssh_config',
                  'known_hosts': '/run/codex-ssh/known_hosts'}
        existing = targets['targets'].get(name)
        if existing is not None and existing != target:
            raise ValueError('Target name conflict')
        for other, entry in targets['targets'].items():
            if other != name and isinstance(entry, dict) and entry.get('destination', '').lower() == alias.lower():
                raise ValueError('Target alias conflict')
        expected = {'hostname': value['address'], 'port': str(value['port']), 'user': value['user'],
                    'identityfile': '/run/codex-ssh/identity', 'identitiesonly': 'yes',
                    'stricthostkeychecking': 'yes', 'userknownhostsfile': '/run/codex-ssh/known_hosts'}
        config = before['ssh_config'].decode()
        blocks = []
        current = None
        for line in config.splitlines():
            fields = shlex.split(line, comments=True)
            if not fields:
                continue
            option = fields[0].lower()
            if option == 'match':
                raise ValueError('Cannot safely register into SSH Match configuration')
            if option == 'host':
                current = {'patterns': fields[1:], 'options': {}}
                blocks.append(current)
            elif current is not None:
                if len(fields) != 2 or option in current['options']:
                    current['options'][option] = None
                else:
                    current['options'][option] = fields[1]
            else:
                raise ValueError('Cannot safely register with global SSH directives')
        matches = []
        import fnmatch
        for block in blocks:
            patterns = block['patterns']
            if any(fnmatch.fnmatchcase(alias.lower(), pattern.lower().lstrip('!')) for pattern in patterns):
                if patterns != [alias]:
                    raise ValueError('SSH alias pattern conflict')
                matches.append(block['options'])
        if len(matches) > 1:
            raise ValueError('Duplicate SSH alias conflict')
        if matches:
            options = matches[0]
            if any(options.get(key) != val for key, val in expected.items()):
                raise ValueError('SSH endpoint configuration conflict')
            permitted = set(expected) | {'batchmode', 'forwardagent', 'globalknownhostsfile', 'preferredauthentications', 'requesttty', 'connecttimeout', 'serveraliveinterval', 'serveralivecountmax', 'loglevel'}
            if set(options) - permitted or any(options.get(key, default) != default for key, default in {'batchmode': 'yes', 'forwardagent': 'no', 'globalknownhostsfile': '/dev/null', 'preferredauthentications': 'publickey', 'requesttty': 'no'}.items()):
                raise ValueError('Unsafe additional SSH endpoint options')
        else:
            config = config.rstrip('\n') + '\n\nHost ' + alias + '\n'
            labels = {'hostname': 'HostName', 'port': 'Port', 'user': 'User', 'identityfile': 'IdentityFile', 'identitiesonly': 'IdentitiesOnly', 'stricthostkeychecking': 'StrictHostKeyChecking', 'userknownhostsfile': 'UserKnownHostsFile'}
            config += ''.join('  ' + labels[key] + ' ' + val + '\n' for key, val in expected.items())
            config += '  GlobalKnownHostsFile /dev/null\n  BatchMode yes\n  ForwardAgent no\n  PreferredAuthentications publickey\n'
        known = before['known_hosts'].decode()
        endpoint = '[' + value['address'] + ']:' + str(value['port'])
        matching_key = False
        for line in known.splitlines():
            fields = line.split()
            if not fields or fields[0].startswith('#'):
                continue
            if len(fields) < 3:
                raise ValueError('Invalid existing known_hosts record')
            if endpoint in fields[0].split(','):
                if _key(' '.join(fields[1:3])) != value['host_public_key']:
                    raise ValueError('Host key conflict')
                matching_key = True
        if not matching_key:
            known = known.rstrip('\n') + '\n' + endpoint + ' ' + value['host_public_key'] + '\n'
        if existing is None:
            targets['targets'][name] = target
        after = {'targets': before['targets'] if existing is not None else _json(targets),
                 'ssh_config': config.encode(), 'known_hosts': known.encode()}
        return value, before, after

    def plan(self, descriptor):
        value, before, after = self._render(descriptor)
        pending = json.loads(_read(self.pending_path)) if self.pending_path.exists() or self.pending_path.is_symlink() else None
        return {'changed': before != after, 'name': value['name'],
                'pending_transaction_id': pending['transaction_id'] if pending else None,
                'pending_name': pending['name'] if pending else None,
                'files': [name for name in before if before[name] != after[name]],
                'cas_recreate_required': before != after}

    def probe(self, descriptor):
        value = self._descriptor(descriptor)
        _read(self.native / 'identity')
        with tempfile.TemporaryDirectory(prefix='native-endpoint-probe-') as directory:
            known = Path(directory) / 'known_hosts'
            _write(known, ('[' + value['address'] + ']:' + str(value['port']) + ' ' + value['host_public_key'] + '\n').encode())
            command = shlex.join([value['codex_bin'], 'app-server', 'daemon', 'version'])
            result = subprocess.run(['ssh', '-F', '/dev/null', '-T', '-i', str(self.native / 'identity'),
                                     '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                                     '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
                                     '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=10', '-p', str(value['port']),
                                     value['user'] + '@' + value['address'], command], capture_output=True, text=True, timeout=25)
            if result.returncode or not result.stdout.strip():
                raise ValueError('Native SSH daemon version probe failed')
            try:
                daemon = json.loads(result.stdout)
            except (ValueError, TypeError):
                raise ValueError('Native SSH daemon version response is not JSON') from None
            if not isinstance(daemon, dict) or daemon.get('status') != 'running':
                raise ValueError('Native SSH daemon is not running')
            if 'socketPath' in daemon and daemon['socketPath'] != value['socket']:
                raise ValueError('Native SSH daemon socket does not match the descriptor')
        return {'status': 'PASS', 'name': value['name']}

    def _init_store(self):
        _directory(self.state)
        self.store.mkdir(mode=0o700, exist_ok=True)
        _directory(self.store)

    def _journal(self, transaction_id):
        if not isinstance(transaction_id, str) or not re.fullmatch(r'[a-f0-9]{32}', transaction_id):
            raise ValueError('Invalid registration transaction id')
        source = self.pending_path if self.pending_path.exists() or self.pending_path.is_symlink() else self.store / transaction_id / 'receipt.json'
        journal = json.loads(_read(source))
        if journal.get('transaction_id') != transaction_id:
            raise ValueError('Registration transaction mismatch')
        return journal

    def apply(self, descriptor):
        value, before, after = self._render(descriptor)
        if self.pending_path.exists() or self.pending_path.is_symlink():
            raise ValueError('Registration pending; complete or rollback the existing transaction')
        self.probe(value)
        if before == after:
            return {'changed': False, 'transaction_id': None, 'name': value['name']}
        self._init_store()
        transaction_id = uuid.uuid4().hex
        directory = self.store / transaction_id
        directory.mkdir(mode=0o700)
        for name, content in before.items():
            _write(directory / (name + '.before'), content)
        journal = {'transaction_id': transaction_id, 'name': value['name'], 'status': 'pending',
                   'before': {key: _sha(content) for key, content in before.items()},
                   'after': {key: _sha(content) for key, content in after.items()}}
        _write(self.pending_path, _json(journal))
        for name, content in after.items():
            if before[name] != content:
                if _read(self.paths[name]) != before[name]:
                    raise ValueError('Registration source changed; rollback pending transaction')
                _write(self.paths[name], content)
        return {'changed': True, 'transaction_id': transaction_id, 'name': value['name'], 'cas_recreate_required': True}

    def rollback(self, transaction_id):
        journal = self._journal(transaction_id)
        if journal['status'] == 'rolled_back':
            return {'transaction_id': transaction_id, 'status': 'rolled_back', 'cas_recreate_required': False}
        if journal['status'] != 'pending':
            raise ValueError('Only a pending registration can be rolled back')
        before = {name: _read(self.store / transaction_id / (name + '.before')) for name in self.paths}
        current = {name: _read(path) for name, path in self.paths.items()}
        for name in self.paths:
            if _sha(before[name]) != journal['before'][name]:
                raise ValueError('Registration backup changed')
            if _sha(current[name]) not in (journal['before'][name], journal['after'][name]):
                raise ValueError('Registration file changed since transaction; refusing rollback')
        for name in self.paths:
            if current[name] != before[name]:
                _write(self.paths[name], before[name])
        self._finish(journal, 'rolled_back')
        return {'transaction_id': transaction_id, 'status': 'rolled_back', 'cas_recreate_required': True}

    def _finish(self, journal, status):
        journal['status'] = status
        _write(self.store / journal['transaction_id'] / 'receipt.json', _json(journal))
        self.pending_path.unlink()
        directory_fd = os.open(self.store, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def complete(self, transaction_id):
        journal = self._journal(transaction_id)
        if journal['status'] == 'complete':
            return {'transaction_id': transaction_id, 'status': 'complete'}
        if journal['status'] != 'pending':
            raise ValueError('Only a pending registration can be completed')
        if any(_sha(_read(path)) != journal['after'][name] for name, path in self.paths.items()):
            raise ValueError('Registration files changed before completion')
        self._finish(journal, 'complete')
        return {'transaction_id': transaction_id, 'status': 'complete'}

    def _lifecycle_request(self, request):
        if not isinstance(request, dict):
            raise ValueError('Invalid lifecycle request')
        operation = request.get('operation')
        expected = {'operation', 'name', 'controller_fingerprint', 'native_before', 'native_after'}
        if operation == 'rename':
            expected.add('new_name')
        if operation not in ('remove', 'rename') or set(request) != expected:
            raise ValueError('Invalid lifecycle request fields')
        name = request['name']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', name):
            raise ValueError('Invalid lifecycle target name')
        new_name = request.get('new_name')
        if operation == 'rename' and (not isinstance(new_name, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', new_name)
                or new_name.lower() == 'local' or new_name == name):
            raise ValueError('Invalid or reserved lifecycle destination name')
        self._lifecycle_identity(request)
        tuples = {}
        for key in ('native_before', 'native_after'):
            value = request[key]
            if not isinstance(value, dict) or set(value) != {'target', 'cwd', 'thread_id'}:
                raise ValueError('Invalid native acceptance tuple')
            target, cwd, thread_id = value['target'], value['cwd'], value['thread_id']
            if (not isinstance(target, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', target)
                    or not isinstance(cwd, str) or not cwd.startswith('/')
                    or any(ord(char) < 32 for char in cwd)
                    or str(PurePosixPath(cwd)) != cwd or '..' in PurePosixPath(cwd).parts
                    or not isinstance(thread_id, str)
                    or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', thread_id)):
                raise ValueError('Invalid native acceptance tuple')
            tuples[key] = dict(value)
        return {'operation': operation, 'name': name, **({'new_name': new_name} if operation == 'rename' else {}),
                'controller_fingerprint': request['controller_fingerprint'], **tuples}

    def _lifecycle_identity(self, request):
        if not isinstance(request, dict):
            raise ValueError('Invalid lifecycle request')
        operation = request.get('operation')
        expected = {'operation', 'name', 'controller_fingerprint'}
        if operation == 'rename':
            expected.add('new_name')
        if operation not in ('remove', 'rename') or set(request) not in (expected, expected | {'native_before', 'native_after'}):
            raise ValueError('Invalid lifecycle request identity')
        name = request.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', name):
            raise ValueError('Invalid lifecycle target name')
        if operation == 'rename':
            new_name = request.get('new_name')
            if (not isinstance(new_name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', new_name)
                    or new_name.lower() == 'local' or new_name == name):
                raise ValueError('Invalid or reserved lifecycle destination name')
        if request.get('controller_fingerprint') != self.instance['deploy_host']['host_key_fingerprint']:
            raise ValueError('Lifecycle controller fingerprint mismatch')
        return {key: request.get(key) for key in ('operation', 'name', 'new_name', 'controller_fingerprint')}

    def _lifecycle_state(self, request):
        value = self._lifecycle_request(request)
        before = {name: _read(path) for name, path in self.paths.items()}
        document = json.loads(before['targets'])
        targets = document.get('targets') if isinstance(document, dict) else None
        if not isinstance(targets, dict) or not targets:
            raise ValueError('At least one existing target is required')
        if any(not isinstance(k, str) or not isinstance(v, dict) for k, v in targets.items()):
            raise ValueError('Invalid target map')
        operation, name = value['operation'], value['name']
        after_targets = dict(targets)
        source = targets.get(name)
        if operation == 'rename':
            destination = value['new_name']
            if source is None:
                receipt = self._completed_rename(value)
                if receipt is not None and destination in targets and targets[destination] == receipt['renamed_entry']:
                    return value, before, before, targets, targets
                raise ValueError('Rename source missing without a matching completed receipt')
            if destination in targets:
                raise ValueError('Rename destination conflict')
            del after_targets[name]
            after_targets[destination] = source
        elif source is not None:
            del after_targets[name]
        if not after_targets:
            raise ValueError('Cannot remove the last target')
        if operation == 'remove' and source is not None and value['native_before']['target'] == name:
            raise ValueError('Cannot remove the acceptance target')
        if value['native_before']['target'] not in targets:
            raise ValueError('Native before target must exist in targets_before')
        if value['native_after']['target'] not in after_targets:
            raise ValueError('Native after target must exist in targets_after')
        after_document = dict(document)
        after_document['targets'] = after_targets
        after = dict(before)
        after['targets'] = _json(after_document) if after_targets != targets else before['targets']
        return value, before, after, targets, after_targets

    def _completed_rename(self, value):
        if not self.store.exists():
            return None
        for receipt_path in self.store.glob('*/receipt.json'):
            receipt = json.loads(_read(receipt_path))
            if (receipt.get('status') == 'complete' and receipt.get('operation') == 'rename'
                    and receipt.get('name') == value['name'] and receipt.get('new_name') == value['new_name']
                    and receipt.get('controller_fingerprint') == value['controller_fingerprint']
                    and receipt.get('native_before') == value['native_before']
                    and receipt.get('native_after') == value['native_after']):
                return receipt
        return None

    def lifecycle_plan(self, request):
        value, before, after, targets_before, targets_after = self._lifecycle_state(request)
        pending = json.loads(_read(self.pending_path)) if self.pending_path.exists() or self.pending_path.is_symlink() else None
        changed = before != after
        return self._lifecycle_result(value, before, after, targets_before, targets_after, pending, None)

    def _lifecycle_result(self, value, before, after, targets_before, targets_after, pending, transaction_id):
        return {'changed': before != after, 'operation': value['operation'], 'name': value['name'],
                'new_name': value.get('new_name'), 'targets_before': targets_before,
                'targets_after': targets_after,
                'pending_transaction_id': pending.get('transaction_id') if pending else None,
                'pending_name': pending.get('name') if pending else None,
                'pending_operation': pending.get('operation') if pending else None,
                'native_before': value['native_before'], 'native_after': value['native_after'],
                'files': [name for name in before if before[name] != after[name]],
                'retained_assets': ['operator/shared SSH configuration', 'native SSH identity and known-host pins'],
                'transaction_id': transaction_id}

    def lifecycle_apply(self, request):
        value, before, after, targets_before, targets_after = self._lifecycle_state(request)
        if self.pending_path.exists() or self.pending_path.is_symlink():
            raise ValueError('Lifecycle pending; complete or rollback the existing transaction')
        files = [name for name in before if before[name] != after[name]]
        if not files:
            return self._lifecycle_result(value, before, after, targets_before, targets_after, None, None)
        self._init_store()
        transaction_id = uuid.uuid4().hex
        directory = self.store / transaction_id
        directory.mkdir(mode=0o700)
        for name, content in before.items():
            _write(directory / (name + '.before'), content)
        journal = {'transaction_id': transaction_id, 'name': value['name'], 'new_name': value.get('new_name'),
                   'operation': value['operation'], 'controller_fingerprint': value['controller_fingerprint'],
                   'native_before': value['native_before'], 'native_after': value['native_after'],
                   'targets_before': targets_before, 'targets_after': targets_after, 'status': 'pending',
                   'before': {key: _sha(content) for key, content in before.items()},
                   'after': {key: _sha(content) for key, content in after.items()},
                   'renamed_entry': targets_before.get(value['name']) if value['operation'] == 'rename' else None}
        _write(self.pending_path, _json(journal))
        for name in files:
            if _read(self.paths[name]) != before[name]:
                raise ValueError('Lifecycle source changed; rollback pending transaction')
            _write(self.paths[name], after[name])
        return self._lifecycle_result(value, before, after, targets_before, targets_after, journal, transaction_id)

    def pending(self, request):
        identity = self._lifecycle_identity(request)
        if not self.pending_path.exists() and not self.pending_path.is_symlink():
            return None
        journal = json.loads(_read(self.pending_path))
        if (journal.get('operation') not in ('remove', 'rename')
                or any(journal.get(key) != value for key, value in identity.items())):
            raise ValueError('A different registration transaction is pending')
        return journal


def dispatch(action, data, instance):
    registration = Registration(instance)
    if action == 'info':
        return registration.info()
    if action in ('plan', 'probe', 'apply'):
        return getattr(registration, action)(data)
    if action in ('rollback', 'complete'):
        return getattr(registration, action)(data['transaction_id'])
    if action == 'lifecycle-plan':
        return registration.lifecycle_plan(data)
    if action == 'lifecycle-apply':
        return registration.lifecycle_apply(data)
    if action == 'pending':
        return {'pending': registration.pending(data)}
    raise ValueError('Unknown native registration action')
