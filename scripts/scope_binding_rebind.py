"""One-use incident repair of one owner provider digest, never of capability policy."""
import fcntl
import hashlib
import hmac
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.request


class RebindError(ValueError):
    """Fixed, credential-free refusal."""


def digest(content):
    return hashlib.sha256(content).hexdigest()


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024):
            raise RebindError('Private repair input ownership or mode changed.')
        return stream.read()


def approved_update(raw, provider_path, bound, approval, document):
    if digest(raw) != approval['scope_before_sha256']:
        raise RebindError('One-time scope snapshot changed or already consumed.')
    scope = json.loads(raw)
    if any(scope.get(k) != v for k, v in document.items() if k != 'enabled'):
        raise RebindError('Approved lifecycle policy changed.')
    expiry = scope.get('expires_at', 0)
    if (scope.get('enabled') is not True or expiry is not None and (
            isinstance(expiry, bool) or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry) or expiry <= time.time())
            or not re.fullmatch('[a-f0-9]{64}', scope.get('capability_sha256', ''))):
        raise RebindError('Owner capability is invalid, revoked or expired.')
    bindings = scope.get('bindings', {})
    if (bindings.get(provider_path) != approval['provider_before_sha256']
            or set(bound) != set(bindings)
            or digest(bound[provider_path]) != approval['provider_after_sha256']):
        raise RebindError('Approved provider transition changed.')
    if any(digest(bound[path]) != want for path, want in bindings.items() if path != provider_path):
        raise RebindError('Another frozen binding changed.')
    scope['bindings'][provider_path] = approval['provider_after_sha256']
    return (json.dumps(scope, sort_keys=True) + '\n').encode()


def verify_records(scoped, legacy):
    for record in scoped:
        if (record.get('status') not in {'retired', 'failed'}
                or record.get('operation') != 'create'
                or record.get('new_request_allowed') is not True):
            raise RebindError('Existing lifecycle state is active or unresolved.')
    if any(record.get('status') != 'reconciled_scoped' for record in legacy):
        raise RebindError('Existing legacy creation is unresolved.')


def atomic_private(path, content):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            fd = os.open(path.parent, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)


class ScopeBindingRebind:
    def __init__(self, bootstrap, approval, document, control_plane_probe=None):
        self.bootstrap, self.approval, self.document = bootstrap, approval, document
        self.control_plane_probe = control_plane_probe
        self.state = Path(bootstrap.profile['state_dir'])
        self.store = self.state / 'deployment'
        self.journal = self.store / 'issue27-scope-binding-rebind'

    def inspect(self):
        b, a = self.bootstrap, self.approval
        if self.journal.exists() or self.journal.is_symlink():
            raise RebindError('One-time binding repair was already attempted; inspect its receipt.')
        config = json.loads(private_bytes(self.state / 'devsy-bridge/config.json'))
        scope_path = Path(config['scope_source'])
        info = scope_path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or scope_path.parent.is_symlink()
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise RebindError('Owner scope directory is not private.')
        raw = private_bytes(scope_path)
        scope = json.loads(raw)
        bound = {p: private_bytes(Path(p)) for p in scope['bindings']}
        provider = b.profile['devsy']['config_source']
        replacement = approved_update(raw, provider, bound, a, self.document)
        receipt_raw = private_bytes(self.store / 'devsy-host-current.json')
        receipt = json.loads(receipt_raw)
        if (digest(receipt_raw) != a['host_apply_receipt_sha256']
                or receipt['source_sha'] != a['host_apply_source_sha']
                or digest(private_bytes(Path(receipt['backup_dir']) / 'devsy_config.bin')) != a['provider_before_sha256']
                or digest(private_bytes(self.state / 'cas-targets.json')) != a['cas_mapping_sha256']):
            raise RebindError('Host apply receipt, backup or protected mapping changed.')
        snapshots = {}
        records, legacy = [], []
        for directory, output in ((self.state / 'devsy-bridge/scoped-jobs', records),
                                  (self.state / 'devsy-bridge/creation-receipts', legacy)):
            for path in directory.glob('*.json'):
                content = private_bytes(path)
                snapshots[path] = digest(content)
                # Histories and identity pins remain byte-bound but are not current jobs.
                if directory.name == 'scoped-jobs' and (path.name.startswith(('history-', 'identity-'))):
                    continue
                output.append(json.loads(content))
        verify_records(records, legacy)
        tokens = []
        for path in scope_path.parent.iterdir():
            if path == scope_path or path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
                continue
            token = private_bytes(path).decode().strip()
            if hmac.compare_digest(digest(token.encode()), scope['capability_sha256']):
                tokens.append(token)
        if len(tokens) != 1:
            raise RebindError('Owner capability identity is ambiguous.')
        b.assert_current()  # Includes canonical ROR resources, namespace, selector and admission.
        process = json.loads(private_bytes(self.state / 'devsy-bridge/process.json'))
        if not b.process_probe(config, process) or not b.health_probe(config):
            raise RebindError('Managed Devsy bridge is not healthy.')
        return {'scope_path': scope_path, 'before': raw, 'after': replacement,
                'bound': {p: digest(content) for p, content in bound.items()},
                'records': snapshots, 'config': config, 'token': tokens[0]}

    def plan(self):
        value = self.inspect()
        return {'operation': 'devsy-scope-rebind-check', 'ready': True,
                'approval_id': self.approval['approval_id'],
                'scope_before_sha256': digest(value['before']),
                'scope_after_sha256': digest(value['after']),
                'provider_before_sha256': self.approval['provider_before_sha256'],
                'provider_after_sha256': self.approval['provider_after_sha256'],
                'other_bindings_unchanged': True, 'records_reconciled': True,
                'owner_capability_verified': True, 'mutated': False}

    def authenticate(self, value):
        spec = importlib.util.spec_from_file_location('scope_rebind_native',
            Path(self.bootstrap.profile['repo_dir']) / 'scripts/worker_scope.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        manager = module.WorkerScope(value['scope_path'], self.state / 'devsy-bridge/scoped-jobs',
                                    None, None, None)
        manager.authenticate('Bearer ' + value['token'])  # Actual unmodified scope.load gate.
        spec = importlib.util.spec_from_file_location('scope_rebind_bridge',
            Path(self.bootstrap.profile['repo_dir']) / 'scripts/devsy_bridge.py')
        bridge = importlib.util.module_from_spec(spec); spec.loader.exec_module(bridge)
        process = json.loads(private_bytes(self.state / 'devsy-bridge/process.json'))
        if (not self.bootstrap.process_probe(value['config'], process)
                or not self.bootstrap.health_probe(value['config'])
                or process.get('configuration') != bridge.fingerprint(value['config'])):
            raise RebindError('Restarted Devsy process or scope fingerprint differs.')
        request = urllib.request.Request('http://' + value['config']['gateway'] + ':8089/scope/health',
                                         headers={'Authorization': 'Bearer ' + value['token']})
        with bridge.host_opener().open(request, timeout=15) as response:
            if json.loads(response.read(4096)) != {'authorized': True}:
                raise RebindError('Running owner scope authentication refused.')

    def unit(self, operation):
        self.bootstrap._command(['sudo', '-n', 'systemctl', operation, 'codex-control-plane-devsy'])

    def apply(self, *, approved, controller_sha):
        if approved is not True or not re.fullmatch('[a-f0-9]{40}', controller_sha or ''):
            raise RebindError('Explicit protected one-time binding approval is required.')
        lock_path = self.state / 'devsy-bridge/scoped-jobs/admission.lock'
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise RebindError('Unsafe lifecycle admission lock.')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = self.inspect()
            control_before = self.control_plane_probe() if self.control_plane_probe else None
            self.journal.mkdir(mode=0o700)
            directory_fd = os.open(self.store, os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
            atomic_private(self.journal / 'scope-before.json', value['before'])
            atomic_private(self.journal / 'before-snapshot.json', (json.dumps({
                'control_plane': control_before, 'bound_digests': value['bound'],
                'record_digests': {str(p): want for p, want in value['records'].items()},
            }, sort_keys=True) + '\n').encode())
            manifest = {'approval_id': self.approval['approval_id'], 'controller_sha': controller_sha,
                        'scope_before_sha256': digest(value['before']),
                        'scope_after_sha256': digest(value['after']), 'status': 'prepared'}
            atomic_private(self.journal / 'receipt.json', (json.dumps(manifest) + '\n').encode())
            try:
                self.unit('stop')
                if private_bytes(value['scope_path']) != value['before']:
                    raise RebindError('Scope changed during repair.')
                atomic_private(value['scope_path'], value['after'])
                self.unit('start')
                self.authenticate(value)
                self.bootstrap.assert_current()
                if (private_bytes(value['scope_path']) != value['after']
                        or any(digest(private_bytes(Path(p))) != want for p, want in value['bound'].items())
                        or any(digest(private_bytes(p)) != want for p, want in value['records'].items())
                        or digest(private_bytes(self.state / 'cas-targets.json')) != self.approval['cas_mapping_sha256']
                        or self.control_plane_probe and self.control_plane_probe() != control_before):
                    raise RebindError('Post-repair immutable inputs changed.')
                manifest['status'] = 'applied'
                atomic_private(self.journal / 'receipt.json', (json.dumps(manifest) + '\n').encode())
                return {**manifest, 'operation': 'devsy-scope-rebind', 'authenticated_scope_load': 'PASS',
                        'owner_policy_unchanged': True, 'records_unchanged': True, 'rollback_ready': True}
            except Exception:
                try:
                    self.unit('stop')
                    atomic_private(value['scope_path'], value['before'])
                    self.unit('start')
                    if private_bytes(value['scope_path']) != value['before']:
                        raise RebindError('Rollback digest mismatch.')
                    process = json.loads(private_bytes(self.state / 'devsy-bridge/process.json'))
                    if (not self.bootstrap.process_probe(value['config'], process)
                            or not self.bootstrap.health_probe(value['config'])
                            or self.control_plane_probe and self.control_plane_probe() != control_before):
                        raise RebindError('Rollback process or control-plane verification failed.')
                    manifest['status'] = 'rolled-back'
                    atomic_private(self.journal / 'receipt.json', (json.dumps(manifest) + '\n').encode())
                except Exception:
                    raise RebindError('Binding repair failed; rollback FAILED; operator recovery required.') from None
                raise RebindError('Binding repair failed; prior scope restored; no retry authorized.') from None
        finally:
            os.close(fd)
