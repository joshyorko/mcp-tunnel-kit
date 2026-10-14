"""One fixed systemd drop-in makes the already verified kubectl visible to Devsy."""
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import time

from scope_binding_rebind import atomic_private, digest, private_bytes

UNIT = 'codex-control-plane-devsy'
DROPIN = Path('/etc/systemd/system/codex-control-plane-devsy.service.d/30-pinned-kubectl-path.conf')


class PathRepairError(ValueError):
    """Fixed diagnostics; never return raw environment or private records."""


def path_value(old, kubectl, approval):
    if (digest(old.encode()) != approval['bridge_path_before_sha256']
            or any(ord(c) < 32 or c in '\\"%' for c in old + str(kubectl))
            or any(not p.startswith('/') for p in old.split(':'))
            or not kubectl.is_absolute()):
        raise PathRepairError('Approved bridge PATH changed or is unsafe.')
    return str(kubectl.parent) + ':' + old


def dropin_bytes(path):
    return ('[Service]\nEnvironment="PATH=' + path + '"\n').encode()


def root_dropin_matches(expected):
    fd = os.open(DROPIN, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o644 and stream.read() == expected)


class BridgeKubectlPath:
    def __init__(self, bootstrap, approval, document=None, control_plane_probe=None):
        self.b, self.approval = bootstrap, approval
        self.probe = control_plane_probe
        self.state = Path(bootstrap.profile['state_dir'])
        self.store = self.state / 'deployment'
        self.journal = self.store / 'issue27-bridge-kubectl-path'

    def native_module(self, name):
        spec = importlib.util.spec_from_file_location('path_repair_' + name,
            Path(self.b.profile['repo_dir']) / 'scripts' / (name + '.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def runtime(self):
        config = json.loads(private_bytes(self.state / 'devsy-bridge/config.json'))
        process = json.loads(private_bytes(self.state / 'devsy-bridge/process.json'))
        if not self.b.process_probe(config, process) or not self.b.health_probe(config):
            raise PathRepairError('Managed bridge process or health differs.')
        data = Path('/proc/' + str(process['pid']) + '/environ').read_bytes().split(b'\0')
        env = {v.split(b'=', 1)[0].decode(): v.split(b'=', 1)[1].decode() for v in data if b'=' in v}
        if not self.b.process_probe(config, process):
            raise PathRepairError('Bridge identity changed during environment inspection.')
        env['DEVSY_HOME'] = config['home']  # Same assignment as the running bridge's serve().
        scope = self.native_module('worker_scope').WorkerScope(config['scope_source'],
            self.state / 'devsy-bridge/scoped-jobs', None, None, None).load()
        return config, env, scope

    def records(self):
        values = {str(p.relative_to(self.state)): digest(private_bytes(p))
            for directory in ('devsy-bridge/scoped-jobs', 'devsy-bridge/creation-receipts')
            for p in (self.state / directory).glob('*.json')}
        return digest(json.dumps(values, sort_keys=True).encode())

    def absence(self, config, env, scope):
        module = self.native_module('devsy_reconciliation')
        try:
            rows = module._query([config['binary'], '--context', scope['context'],
                '--result-format', 'json', 'workspace', 'list', '--skip-pro'], config['cwd'], env)
            if rows != []:
                raise PathRepairError('Workspace inventory is not empty; no bridge restart authorized.')
            for name in scope['allowed_new_names']:
                record = json.loads(private_bytes(self.state / 'devsy-bridge/scoped-jobs' / (name + '.json')))
                if record.get('status') not in {'retired', 'failed'}:
                    raise PathRepairError('Current lifecycle work is active or unresolved.')
                cutoffs = [record.get(k) for k in ('accepted_at', 'started_at', 'grant_issued_at', 'recovery_cutoff')]
                cutoffs = [v for v in cutoffs if isinstance(v, (int, float)) and not isinstance(v, bool)
                           and math.isfinite(v) and 0 < v <= time.time()]
                module.absence_proof(config['binary'], config['cwd'], env,
                    {**scope, 'recovery_cutoff': min(cutoffs) if cutoffs else None}, name)
        except module.ReconciliationError as error:
            raise PathRepairError('Native absence proof refused at ' + error.phase + '.') from None

    def baseline(self):
        a = self.approval
        if self.journal.exists() or self.journal.is_symlink():
            raise PathRepairError('One-time bridge PATH repair already attempted; inspect receipt.')
        if DROPIN.parent.exists() or DROPIN.parent.is_symlink():
            raise PathRepairError('Existing bridge drop-in directory requires operator inspection.')
        if self.b._command(['systemctl', 'show', UNIT, '--property=DropInPaths', '--value']).stdout.strip():
            raise PathRepairError('Existing systemd drop-ins are outside this approval.')
        self.b.assert_current()
        config, env, scope = self.runtime()
        if (digest(private_bytes(Path(config['scope_source']))) != a['scope_sha256']
                or digest(private_bytes(self.store / 'devsy-host-current.json')) != a['host_apply_receipt_sha256']
                or digest(private_bytes(self.store / 'issue27-scope-binding-rebind/receipt.json')) != a['scope_rebind_receipt_sha256']
                or digest(self.b.unit_path.read_bytes()) != a['unit_sha256']
                or self.records() != a['records_sha256']):
            raise PathRepairError('Approved scope, deployment, unit or lifecycle snapshot changed.')
        kubectl = self.b._kubectl_state()
        if kubectl['status'] != 'verified' or kubectl['sha256'] != a['kubectl_sha256']:
            raise PathRepairError('Pinned private kubectl checksum or ownership is unverified.')
        new_path = path_value(env['PATH'], kubectl['path'], a)
        changed = dict(env, PATH=new_path)
        self.absence(config, changed, scope)  # Read-only prospective environment; no scope changes.
        return {'config': config, 'old_path': env['PATH'], 'new_path': new_path,
                'scope': scope, 'kubectl': kubectl['path'], 'dropin': dropin_bytes(new_path)}

    def plan(self):
        value = self.baseline()
        return {'operation': 'devsy-bridge-path-check', 'ready': True, 'mutated': False,
                'approval_id': self.approval['approval_id'], 'kubectl_verified': True,
                'native_prospective_absence': 'PASS', 'scope_unchanged': True,
                'path_before_sha256': digest(value['old_path'].encode()),
                'path_after_sha256': digest(value['new_path'].encode()),
                'dropin_sha256': digest(value['dropin'])}

    def command(self, *args):
        self.b._command(['sudo', '-n', *args])

    def unit(self, operation):
        self.command('systemctl', operation, UNIT)

    def apply(self, *, approved, controller_sha):
        if approved is not True or not re.fullmatch('[a-f0-9]{40}', controller_sha or ''):
            raise PathRepairError('Explicit protected bridge PATH approval is required.')
        fd = os.open(self.state / 'devsy-bridge/scoped-jobs/admission.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise PathRepairError('Unsafe lifecycle admission lock.')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = self.baseline()
            before = self.probe() if self.probe else None
            self.journal.mkdir(mode=0o700)
            parent_fd = os.open(self.store, os.O_DIRECTORY)
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
            atomic_private(self.journal / 'dropin.conf', value['dropin'])
            atomic_private(self.journal / 'before-snapshot.json', json.dumps({
                'control_plane': before, 'approval': self.approval,
                'old_path': value['old_path'], 'new_path': value['new_path']}, sort_keys=True).encode())
            receipt = {'approval_id': self.approval['approval_id'], 'controller_sha': controller_sha,
                       'dropin_sha256': digest(value['dropin']), 'status': 'prepared'}
            self.save(receipt)
            try:
                self.unit('stop')
                self.command('install', '-d', '-o', 'root', '-g', 'root', '-m', '0755', str(DROPIN.parent))
                self.command('install', '-o', 'root', '-g', 'root', '-m', '0644',
                             str(self.journal / 'dropin.conf'), str(DROPIN))
                if not root_dropin_matches(value['dropin']):
                    raise PathRepairError('Fixed bridge drop-in readback failed.')
                self.command('systemctl', 'daemon-reload')
                self.unit('start')
                config, env, scope = self.runtime()
                if (env.get('PATH') != value['new_path']
                        or shutil.which('kubectl', path=env['PATH']) != str(value['kubectl'])
                        or self.b._kubectl_state().get('sha256') != self.approval['kubectl_sha256']):
                    raise PathRepairError('Actual bridge PATH does not resolve the pinned verified kubectl.')
                self.absence(config, env, scope)  # Exact real process environment, not the probe environment.
                self.b.assert_current()
                if (self.records() != self.approval['records_sha256']
                        or digest(private_bytes(Path(config['scope_source']))) != self.approval['scope_sha256']
                        or self.probe and self.probe() != before):
                    raise PathRepairError('Records, scope or control-plane snapshot changed.')
                receipt.update(status='applied', operation='devsy-bridge-path-apply',
                    native_actual_environment_absence='PASS', scope_unchanged=True,
                    records_unchanged=True, rollback_ready=True)
                self.save(receipt)
                return receipt
            except Exception:
                try:
                    self.unit('stop')
                    if DROPIN.exists() or DROPIN.is_symlink():
                        if not root_dropin_matches(value['dropin']):
                            raise PathRepairError('Unrecognized drop-in cannot be removed by rollback.')
                        self.command('rm', '--', str(DROPIN))
                    if DROPIN.parent.exists():
                        self.command('rmdir', '--', str(DROPIN.parent))
                    self.command('systemctl', 'daemon-reload')
                    self.unit('start')
                    _, env, _ = self.runtime()
                    if env.get('PATH') != value['old_path'] or self.probe and self.probe() != before:
                        raise PathRepairError('Prior bridge environment or control plane was not restored.')
                    receipt['status'] = 'rolled-back'; self.save(receipt)
                except Exception:
                    raise PathRepairError('Bridge PATH repair failed; rollback FAILED; operator recovery required.') from None
                raise PathRepairError('Bridge PATH repair failed; prior environment restored; no retry authorized.') from None
        finally:
            os.close(fd)

    def save(self, receipt):
        atomic_private(self.journal / 'receipt.json', (json.dumps(receipt, sort_keys=True) + '\n').encode())
