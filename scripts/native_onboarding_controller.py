#!/usr/bin/env python3
"""Pinned controller transport and CAS-only native registration transaction."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import zlib

import deploy_control_plane as deploy
import instance_profile


def action_result(response):
    """Require actual structured action success, including nested errors."""
    structured = response.get('structuredContent')
    if (response.get('isError') or not isinstance(structured, dict)
            or structured.get('error') or structured.get('result') is None):
        raise RuntimeError('Native onboarding action verification failed')
    return structured['result']


def verify_remote(instance, descriptor):
    """Read through the real CAS and Executor; never start a native turn."""
    sys.path.insert(0, str(Path(instance['vm']['repo_dir']) / 'scripts'))
    import compose_control as control

    origin = 'http://' + instance['vm']['network']['gateway'] + ':8088'
    cas = control.Mcp(control.Http(origin), '/mcp')
    targets = action_result(cas.call('tools/call', {'name': 'list_targets', 'arguments': {}}))
    names = {item['name'] for item in targets['targets']}
    if not {'local', descriptor['name']} <= names:
        raise RuntimeError('Native onboarding target inventory verification failed')
    for name, payload in [('inspect_target', {'target': descriptor['name']}),
                          ('list_models', {'target': descriptor['name'], 'limit': 1})]:
        result = action_result(cas.call('tools/call', {'name': name, 'arguments': {'payload': payload}}))
        if name == 'inspect_target' and (
                result.get('destination') != descriptor['name'] + '-native'
                or result.get('codex_bin') != descriptor['codex_bin']
                or result.get('socket') != descriptor['socket']):
            raise RuntimeError('CAS resolved an unexpected native endpoint')
    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312', EXECUTOR_PAT_FILE=str(
        Path(instance['vm']['state_dir']) / 'secrets/executor-pat'))
    _, executor = control.executor_session()
    for name, arguments in [('list_targets', {}), ('list_models', {
            'payload': {'target': descriptor['name'], 'limit': 1}})]:
        response = control.execution(executor.call('tools/call', {'name': 'execute', 'arguments': {
            'code': 'return await tools.codex.' + name + '(' + json.dumps(arguments) + ');'}}))
        execution = response.get('execution', {})
        if response.get('status') != 'completed' or execution.get('ok') is not True:
            raise RuntimeError('Executor native verification did not complete')
        value = action_result(execution.get('value', {}))
        if name == 'list_targets' and descriptor['name'] not in {x['name'] for x in value['targets']}:
            raise RuntimeError('Executor did not expose the registered target')
    return {'verified': True, 'target': descriptor['name'], 'cas': 'PASS', 'executor': 'PASS'}


def _remote_source():
    # Ship checked-out helpers rather than assuming the deployed VM checkout is current.
    source = 'import sys,types,json\n'
    for name in ('instance_profile', 'native_registration'):
        module = (deploy.ROOT / 'scripts' / (name + '.py')).read_text()
        source += ('m=types.ModuleType(' + repr(name) + ');sys.modules[' + repr(name) + ']=m\n'
                   'm.__file__=' + repr(str(deploy.ROOT / 'scripts' / (name + '.py'))) + '\n'
                   'exec(' + repr(module) + ',m.__dict__)\n')
    # Include only the verification function, not controller imports or CLI side effects.
    import inspect
    source += 'import os\nfrom pathlib import Path\n' + inspect.getsource(action_result) + '\n'
    source += inspect.getsource(verify_remote) + '\n'
    source += '''
from instance_profile import decode
from native_registration import dispatch, validate_descriptor
profile=decode(sys.argv[2]); action=sys.argv[1]; data=json.load(sys.stdin)
if action == 'verify':
    descriptor=validate_descriptor(data)
    if descriptor['controller_fingerprint'] != profile['deploy_host']['host_key_fingerprint']:
        raise ValueError('Controller identity mismatch')
    result=verify_remote(profile,descriptor)
else:
    result=dispatch(action,data,profile)
print(json.dumps(result))
'''
    payload = base64.b64encode(zlib.compress(source.encode(), 9)).decode()
    return 'import base64,zlib;exec(zlib.decompress(base64.b64decode(' + repr(payload) + ')))'


class Connection:
    def _call(self, action, data=None):
        command = shlex.join(['python3', '-c', _remote_source(), action,
                              instance_profile.encode(deploy.INSTANCE)])
        result = subprocess.run(deploy.ssh_args(command), input=json.dumps(data or {}),
                                text=True, capture_output=True, timeout=600)
        if result.returncode:
            # Registration errors contain paths and fixed reasons, never private key bytes.
            reason = result.stderr.strip().splitlines()[-1:] or ['remote request failed']
            raise RuntimeError('Native registration ' + action + ' failed: ' + reason[0][:400])
        return json.loads(result.stdout)

    def info(self):
        return self._call('info')

    def _native(self, native):
        if native is None:
            raise ValueError('A changed registration requires the existing local native acceptance '
                             'tuple: --native-cwd and --native-thread-id')
        return deploy.native_codex_tuple(argparse.Namespace(
            native_target=native.get('target'), native_cwd=native.get('cwd'),
            native_thread_id=native.get('thread_id')))

    def _bundle(self):
        if deploy.LOCAL_CONFIGURED:
            from local_kamal import bundle_environment
            bundle_environment()
        try:
            check = subprocess.run(['bundle', '_2.6.9_', 'check'], capture_output=True, text=True, timeout=30)
            if check.returncode:
                # The existing setup confines gems to the user's isolated Kamal bundle.
                subprocess.run(['bundle', '_2.6.9_', 'install'], check=True, timeout=300)
        except (OSError, subprocess.SubprocessError):
            raise ValueError('Kamal setup failed; provide Ruby 3.4.8 and run bin/kamal setup-local') from None

    def _refresh(self, config):
        deploy.kamal(config, 'reboot', 'cas')
        deploy.remote('wait', {'owner': 'kamal', 'service': 'cas'})

    def _recover(self, transaction, current, native):
        with tempfile.TemporaryDirectory(prefix='native-kamal-recovery-') as directory:
            config = deploy.configuration(directory, current['manifest'])
            try:
                self._call('rollback', {'transaction_id': transaction})
                self._refresh(config)
                deploy.smoke(native, require_native=True)
            except Exception:
                raise RuntimeError('Native registration automatic rollback FAILED. '
                                   'Retain the transaction journal for recovery.') from None

    def register(self, descriptor, native=None):
        with deploy.lock():
            plan = self._call('plan', descriptor)
            pending = plan.get('pending_transaction_id')
            if pending:
                if plan.get('pending_name') != descriptor['name']:
                    raise ValueError('Another native target has an unfinished transaction; recover that target first')
                native = self._native(native)
                deploy.remote('lifecycle-check')
                current = deploy.remote('current')
                self._bundle()
                self._recover(pending, current, native)
                plan = self._call('plan', descriptor)
            if not plan['changed']:
                applied = self._call('apply', descriptor)
                verified = self._call('verify', descriptor)
                return {**applied, **verified}
            # Keep the existing original-target native-read gate for every CAS recreation.
            native = self._native(native)
            deploy.remote('lifecycle-check')
            before = deploy.remote('snapshot')
            current = deploy.remote('current')
            if (current.get('authority') != 'kamal' or before.get('authority') != 'kamal'
                    or current.get('identity') != before.get('identity') or before.get('tunnel_count') != 1):
                raise ValueError('Registration requires the healthy recorded Kamal generation')
            deploy.smoke(native, require_native=True)
            self._bundle()
            try:
                applied = self._call('apply', descriptor)
            except Exception:
                # The VM may have journaled or partially published before transport failed.
                pending = self._call('plan', descriptor).get('pending_transaction_id')
                if pending:
                    self._recover(pending, current, native)
                raise
            transaction = applied.get('transaction_id')
            if not transaction:
                raise RuntimeError('Changed registration did not return a transaction receipt')
            with tempfile.TemporaryDirectory(prefix='native-kamal-') as directory:
                config = deploy.configuration(directory, current['manifest'])
                try:
                    self._refresh(config)
                    verified = self._call('verify', descriptor)
                    deploy.smoke(native, require_native=True)
                    after = deploy.remote('snapshot')
                    if after.get('identity') != before['identity'] or after.get('tunnel_count') != 1:
                        raise RuntimeError('Control-plane identity changed during registration')
                    if after.get('inventory') != before.get('inventory'):
                        raise RuntimeError('Pinned image or accessory configuration changed during registration')
                    self._call('complete', {'transaction_id': transaction})
                except Exception:
                    try:
                        self._call('rollback', {'transaction_id': transaction})
                        self._refresh(config)
                        deploy.smoke(native, require_native=True)
                    except Exception:
                        raise RuntimeError('Native registration failed; automatic rollback FAILED. '
                                           'Retain the transaction journal for recovery.') from None
                    raise RuntimeError('Native registration failed; previous CAS configuration restored') from None
            return {**applied, **verified}


def connect(local_env, instance_profile=None):
    """Bootstrap a missing profile only through the already pinned SSH configuration."""
    env_path = Path(local_env).absolute()
    if not env_path.exists():
        raise ValueError('Copy config/kamal-local.env.example to .env.kamal.local and set the existing pinned SSH paths')
    values = {}
    for raw in deploy._read_private_file(env_path).splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        fields = shlex.split(value, comments=True)
        if (not separator or key in values or key not in {
                'KAMAL_SSH_CONFIG', 'KAMAL_SSH_KEY', 'KAMAL_KNOWN_HOSTS', 'KAMAL_INSTANCE_PROFILE'}
                or len(fields) != 1 or not Path(fields[0]).is_absolute()):
            raise ValueError('Invalid local Kamal configuration')
        values[key] = Path(fields[0])
    required = {'KAMAL_SSH_CONFIG', 'KAMAL_SSH_KEY', 'KAMAL_KNOWN_HOSTS'}
    if not required <= values.keys():
        raise ValueError('Copy config/kamal-local.env.example to .env.kamal.local and set existing SSH paths')
    for key in required:
        deploy._read_private_file(values[key])
    destination = Path(instance_profile or values.get('KAMAL_INSTANCE_PROFILE',
                                                     globals()['instance_profile'].DEFAULT_PATH))
    if not destination.exists():
        entries = {}
        for line in values['KAMAL_SSH_CONFIG'].read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if not fields:
                continue
            if len(fields) != 2 or fields[0].lower() in entries:
                raise ValueError('Ambiguous pinned controller SSH config')
            entries[fields[0].lower()] = fields[1]
        known = values['KAMAL_KNOWN_HOSTS'].read_text().split()
        if len(known) != 3 or known[1] != 'ssh-ed25519':
            raise ValueError('Controller requires one verified Ed25519 host pin')
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(
            base64.b64decode(known[2], validate=True)).digest()).decode().rstrip('=')
        host = {'alias': entries.get('host'), 'address': entries.get('hostname'),
                'user': entries.get('user'), 'host_key_fingerprint': fingerprint}
        deploy.validate_ssh_config(values['KAMAL_SSH_CONFIG'], values['KAMAL_SSH_KEY'],
                                   values['KAMAL_KNOWN_HOSTS'], {'deploy_host': host})
        command = 'python3 -c ' + shlex.quote(
            'from pathlib import Path;print((Path.home()/".config/mcp-control-plane/instance.json").read_text())')
        result = subprocess.run(['ssh', '-F', str(values['KAMAL_SSH_CONFIG']),
                                 '-o', 'ConnectTimeout=15', host['alias'], command],
                                capture_output=True, text=True, timeout=30, check=True)
        profile = globals()['instance_profile'].validate(json.loads(result.stdout))
        if profile['deploy_host'] != host:
            raise ValueError('Remote profile does not match the pinned controller connection')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(profile, stream, indent=2)
            stream.write('\n')
    deploy.configure_local(env_path, profile_path=destination)
    deploy.trusted_context(os.environ, local=True)
    return Connection()


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--descriptor', type=Path, required=True)
    cli.add_argument('--native-cwd', required=True)
    cli.add_argument('--native-thread-id', required=True)
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    deploy.configure_instance(None)
    deploy.trusted_context(os.environ)
    from native_registration import validate_descriptor
    descriptor = validate_descriptor(json.loads(deploy._read_private_file(args.descriptor)))
    result = Connection().register(descriptor, {'target': 'local', 'cwd': args.native_cwd,
                                               'thread_id': args.native_thread_id})
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
