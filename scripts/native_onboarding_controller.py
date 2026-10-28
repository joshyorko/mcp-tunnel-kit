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
    if descriptor['name'] not in names:
        raise RuntimeError('Native onboarding target inventory verification failed')
    expected = descriptor.get('expected_target') or descriptor['name'] + '-native'
    target = descriptor['name']
    for name, payload in [('inspect_target', {'target': descriptor['name']}),
                          ('list_models', {'target': descriptor['name'], 'limit': 1})]:
        result = action_result(cas.call('tools/call', {'name': name, 'arguments': {'payload': payload}}))
        if name == 'inspect_target' and (
                result.get('destination') != expected
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
        if name == 'list_targets' and target not in {x['name'] for x in value['targets']}:
            raise RuntimeError('Executor did not expose the registered target')
    return {'verified': True, 'target': descriptor['name'], 'cas': 'PASS', 'executor': 'PASS'}


def verify_lifecycle_remote(instance, plan):
    """Compare the planned target inventory through CAS and Executor reads."""
    sys.path.insert(0, str(Path(instance['vm']['repo_dir']) / 'scripts'))
    import compose_control as control

    if (not isinstance(plan, dict) or plan.get('operation') not in ('remove', 'rename')
            or not isinstance(plan.get('targets_after'), dict)):
        raise ValueError('Invalid native lifecycle verification plan')
    expected = plan['targets_after']
    operation, logical_name, new_name = plan['operation'], plan.get('name'), plan.get('new_name')
    if not isinstance(logical_name, str) or (operation == 'rename' and not isinstance(new_name, str)):
        raise ValueError('Invalid native lifecycle verification identity')
    origin = 'http://' + instance['vm']['network']['gateway'] + ':8088'
    cas = control.Mcp(control.Http(origin), '/mcp')

    def cas_targets():
        value = action_result(cas.call('tools/call', {'name': 'list_targets', 'arguments': {}}))
        return {item['name'] for item in value['targets']}

    def check_inventory(actual, source):
        missing = set(expected) - actual
        if missing:
            raise RuntimeError(source + ' omitted planned native targets: ' + ', '.join(sorted(missing)))
        if operation == 'remove' and logical_name in actual:
            raise RuntimeError(source + ' still exposes the removed native target')
        if operation == 'rename' and logical_name in actual:
            raise RuntimeError(source + ' still exposes the renamed source target')

    check_inventory(cas_targets(), 'CAS')
    if operation == 'rename':
        entry = expected.get(new_name)
        if not isinstance(entry, dict):
            raise RuntimeError('Planned renamed target is missing its endpoint entry')
        inspected = action_result(cas.call('tools/call', {'name': 'inspect_target', 'arguments': {
            'payload': {'target': new_name}}}))
        for key, expected_key in (('destination', 'destination'), ('codex_bin', 'codex_bin'),
                                  ('socket', 'socket_path')):
            if inspected.get(key) != entry.get(expected_key):
                raise RuntimeError('CAS resolved an unexpected renamed native endpoint')
        action_result(cas.call('tools/call', {'name': 'list_models', 'arguments': {
            'payload': {'target': new_name, 'limit': 1}}}))

    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312', EXECUTOR_PAT_FILE=str(
        Path(instance['vm']['state_dir']) / 'secrets/executor-pat'))
    _, executor = control.executor_session()
    response = control.execution(executor.call('tools/call', {'name': 'execute', 'arguments': {
        'code': 'return await tools.codex.list_targets({});'}}))
    execution = response.get('execution', {})
    if response.get('status') != 'completed' or execution.get('ok') is not True:
        raise RuntimeError('Executor target inventory verification did not complete')
    value = action_result(execution.get('value', {}))
    executor_names = {item['name'] for item in value['targets']}
    check_inventory(executor_names, 'Executor')
    if operation == 'rename':
        for name, arguments in (
                ('inspect_target', {'payload': {'target': new_name}}),
                ('list_models', {'payload': {'target': new_name, 'limit': 1}})):
            result = control.execution(executor.call('tools/call', {'name': 'execute', 'arguments': {
                'code': 'return await tools.codex.' + name + '(' + json.dumps(arguments) + ');'}}))
            execution = result.get('execution', {})
            if result.get('status') != 'completed' or execution.get('ok') is not True:
                raise RuntimeError('Executor renamed-target verification did not complete')
            value = action_result(execution.get('value', {}))
            if name == 'inspect_target' and any(
                    value.get(field) != entry.get(expected_field)
                    for field, expected_field in (('destination', 'destination'),
                                                  ('codex_bin', 'codex_bin'),
                                                  ('socket', 'socket_path'))):
                raise RuntimeError('Executor resolved an unexpected renamed native endpoint')
    return {'verified': True, 'operation': operation, 'name': logical_name,
            'new_name': new_name, 'cas': 'PASS', 'executor': 'PASS'}


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
    source += inspect.getsource(verify_lifecycle_remote) + '\n'
    source += '''
from instance_profile import decode
from native_registration import dispatch, validate_descriptor
profile=decode(sys.argv[2]); action=sys.argv[1]; data=json.load(sys.stdin)
if action == 'verify':
    descriptor=validate_descriptor(data)
    if descriptor['controller_fingerprint'] != profile['deploy_host']['host_key_fingerprint']:
        raise ValueError('Controller identity mismatch')
    result=verify_remote(profile,descriptor)
elif action == 'verify-lifecycle':
    if data.get('controller_fingerprint') != profile['deploy_host']['host_key_fingerprint']:
        raise ValueError('Controller identity mismatch')
    result=verify_lifecycle_remote(profile,data)
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
            raise ValueError('A changed native lifecycle operation requires a native acceptance '
                             'tuple: --native-target, --native-cwd, and --native-thread-id')
        return deploy.native_codex_tuple(argparse.Namespace(
            native_target=native.get('target'), native_cwd=native.get('cwd'),
            native_thread_id=native.get('thread_id')))

    def _pending(self, identity):
        result = self._call('pending', identity)
        pending = result.get('pending')
        if pending is None:
            return None
        if not isinstance(pending, dict):
            raise RuntimeError('Controller returned an invalid pending lifecycle journal')
        for key in ('operation', 'name', 'new_name', 'controller_fingerprint'):
            if pending.get(key) != identity.get(key):
                raise ValueError('Another native target has an unfinished transaction; recover that target first')
        if not isinstance(pending.get('transaction_id'), str):
            raise RuntimeError('Controller returned a pending lifecycle journal without a transaction id')
        return pending

    def verify_lifecycle(self, plan):
        return self._call('verify-lifecycle', plan)

    def lifecycle(self, request, native=None):
        """Remove or rename one logical target under the existing Kamal lock."""
        operation, name = request.get('operation'), request.get('name')
        new_name = request.get('new_name')
        if (operation not in ('remove', 'rename') or not isinstance(name, str)
                or (operation == 'rename' and (not isinstance(new_name, str) or not new_name))
                or (operation == 'remove' and new_name is not None)):
            raise ValueError('Invalid native lifecycle request')
        info = self.info()
        if (request.get('controller_fingerprint') is not None
                and request['controller_fingerprint'] != info['controller_fingerprint']):
            raise ValueError('Lifecycle controller identity mismatch')
        identity = {'operation': operation, 'name': name,
                    'controller_fingerprint': info['controller_fingerprint']}
        if operation == 'rename':
            identity['new_name'] = new_name
        recovered = None
        with deploy.lock():
            pending = self._pending(identity)
            if pending:
                # The recorded before tuple survives a rename whose source key is now absent.
                native_before = self._native(pending.get('native_before'))
                native_after = self._native(pending.get('native_after'))
                recovered = (native_before, native_after)
                deploy.remote('lifecycle-check')
                current = deploy.remote('current')
                self._bundle()
                self._recover(pending['transaction_id'], current, native_before)

            accepted = self._native(native) if native is not None else (recovered[1] if recovered else None)
            if accepted is None:
                raise ValueError('A native acceptance tuple is required for a new lifecycle operation')
            if operation == 'remove' and accepted['target'] == name:
                raise ValueError('Native acceptance target must survive removal')
            if recovered and native is None:
                native_before = recovered[0]
            elif operation == 'rename' and accepted['target'] == new_name:
                native_before = {**accepted, 'target': name}
            else:
                native_before = accepted
            full_request = {**identity, 'native_before': native_before, 'native_after': accepted}
            plan = self._call('lifecycle-plan', full_request)
            if plan.get('pending_transaction_id'):
                raise ValueError('Another native target has an unfinished transaction; recover that target first')
            plan = {**plan, 'controller_fingerprint': identity['controller_fingerprint']}
            if not plan.get('changed'):
                return {**plan, **self.verify_lifecycle(plan)}

            deploy.remote('lifecycle-check')
            before = deploy.remote('snapshot')
            current = deploy.remote('current')
            if (current.get('authority') != 'kamal' or before.get('authority') != 'kamal'
                    or current.get('identity') != before.get('identity') or before.get('tunnel_count') != 1):
                raise ValueError('Native lifecycle change requires the healthy recorded Kamal generation')
            deploy.smoke(native_before, require_native=True)
            self._bundle()
            try:
                applied = self._call('lifecycle-apply', full_request)
            except Exception:
                # Recover from the durable journal before planning: a rename source may be gone.
                pending = self._pending(identity)
                if pending:
                    self._recover(pending['transaction_id'], current, self._native(pending.get('native_before')))
                raise
            transaction = applied.get('transaction_id')
            if not transaction:
                raise RuntimeError('Changed native lifecycle operation did not return a transaction receipt')
            with tempfile.TemporaryDirectory(prefix='native-kamal-lifecycle-') as directory:
                config = deploy.configuration(directory, current['manifest'])
                try:
                    self._refresh(config)
                    verified = self.verify_lifecycle(plan)
                    deploy.smoke(accepted, require_native=True)
                    after = deploy.remote('snapshot')
                    if after.get('identity') != before['identity'] or after.get('tunnel_count') != 1:
                        raise RuntimeError('Control-plane identity changed during native lifecycle operation')
                    if after.get('inventory') != before.get('inventory'):
                        raise RuntimeError('Pinned image or accessory configuration changed during native lifecycle operation')
                    try:
                        self._call('complete', {'transaction_id': transaction})
                    except Exception:
                        final_pending = self._pending(identity)
                        if final_pending:
                            raise
                        final_plan = self._call('lifecycle-plan', full_request)
                        if final_plan.get('changed'):
                            raise
                except Exception:
                    try:
                        self._call('rollback', {'transaction_id': transaction})
                        self._refresh(config)
                        deploy.smoke(native_before, require_native=True)
                    except Exception:
                        raise RuntimeError('Native lifecycle operation failed; automatic rollback FAILED. '
                                           'Retain the transaction journal for recovery.') from None
                    raise RuntimeError('Native lifecycle operation failed; previous CAS configuration restored') from None
            return {**applied, **verified}

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
                    try:
                        self._call('complete', {'transaction_id': transaction})
                    except Exception:
                        # A lost SSH response is not evidence that commit failed remotely.
                        final = self._call('plan', descriptor)
                        if final['changed'] or final.get('pending_transaction_id'):
                            raise
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
    cli.add_argument('--operation', choices=('register', 'remove', 'rename'), default='register')
    cli.add_argument('--descriptor', type=Path)
    cli.add_argument('--name')
    cli.add_argument('--new-name')
    cli.add_argument('--native-target', default='local')
    cli.add_argument('--native-cwd', required=True)
    cli.add_argument('--native-thread-id', required=True)
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    deploy.configure_instance(None)
    deploy.trusted_context(os.environ)
    native = {'target': args.native_target, 'cwd': args.native_cwd,
              'thread_id': args.native_thread_id}
    if args.operation == 'register':
        if not args.descriptor:
            raise ValueError('Registration requires --descriptor')
        from native_registration import validate_descriptor
        descriptor = validate_descriptor(json.loads(deploy._read_private_file(args.descriptor)))
        result = Connection().register(descriptor, native)
    else:
        if args.descriptor or not args.name:
            raise ValueError('Removal and rename require --name and do not accept --descriptor')
        if args.operation == 'rename' and not args.new_name:
            raise ValueError('Rename requires --new-name')
        if args.operation == 'remove' and args.new_name:
            raise ValueError('Removal does not accept --new-name')
        result = Connection().lifecycle({'operation': args.operation, 'name': args.name,
                                         'new_name': args.new_name}, native)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
