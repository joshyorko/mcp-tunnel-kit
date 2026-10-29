"""Direct workstation -> Kamal -> VM operations; uses the deployment controller."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import deploy_control_plane as deploy

HELP = '''Usage:
  bin/kamal accessory deploy [all|cas|memoryd] Redeploy pinned images or add isolated MemoryD
  bin/kamal accessory start [NAME|all]   Start existing containers in health order
  bin/kamal accessory stop [NAME|all]    Stop containers, tunnel first
  bin/kamal accessory details [NAME|all] Show current service health
  bin/kamal accessory transfer memoryd   Import the prepared private portable bundles
  bin/kamal accessory network memoryd    Allow the owned bridge to reach MemoryD
  bin/kamal accessory register memoryd   Register the imported read-only app
  bin/kamal accessory reconcile-registration memoryd --confirm-import-quiescent
                                       Reconcile a quiescent interrupted import
  bin/kamal deploy | rollback | preflight | status
  bin/kamal setup-local                 Install the isolated Kamal bundle

NAME: executor, schema-proxy, cas, tunnel, memoryd. Loads .env.kamal.local.
Deploy/rollback reuse recorded image pins. No application image is built locally.
'''


def bundle_environment():
    """Reuse installed Ruby; keep deployment gems separate from Fizzy's bundle."""
    if shutil.which('mise'):
        result = subprocess.run(['mise', 'where', 'ruby@3.4.8'], capture_output=True,
                                text=True, timeout=15)
        if result.returncode == 0:
            os.environ['PATH'] = str(Path(result.stdout.strip()) / 'bin') + ':' + os.environ['PATH']
    os.environ.update(
        BUNDLE_GEMFILE=str(deploy.ROOT / 'Gemfile.deploy'),
        BUNDLE_PATH=str(Path.home() / '.local/share/bundle/mcp-control-plane-local'),
        BUNDLE_APP_CONFIG=str(deploy.ROOT / '.state/kamal/bundle'),
        BUNDLE_FROZEN='true',
    )


def parse_command(argv):
    if argv and argv[0] == 'accessory':
        if len(argv) not in (2, 3):
            raise ValueError(HELP)
        operation = argv[1]
        target = argv[2] if len(argv) == 3 else 'all'
        if operation == 'reboot':
            operation = 'deploy'
        if operation not in ('deploy', 'start', 'stop', 'details', 'transfer', 'network', 'register', 'reconcile-registration'):
            raise ValueError(HELP)
    elif len(argv) == 1 and argv[0] in ('deploy', 'rollback', 'preflight', 'status', 'setup-local'):
        operation, target = argv[0], 'all'
        if operation == 'status':
            operation = 'details'
    else:
        raise ValueError(HELP)
    if target != 'all' and target not in (*deploy.ORDER, 'memoryd'):
        raise ValueError('Unknown control-plane accessory')
    if operation == 'deploy' and target not in ('all', 'cas', 'memoryd'):
        raise ValueError('Use deploy cas, deploy memoryd, or deploy all to retain coordinated state and identity checks')
    if operation in ('transfer','network','register','reconcile-registration') and target != 'memoryd':
        raise ValueError('Only managed MemoryD transfer, network, and registration are supported')
    return operation, target


def memoryd_stopped(inventory):
    return all(item['state'] in ('exited', 'created') for item in inventory['services'].values())


def lifecycle(operation, target):
    """Stop/start existing containers only; never create another writer/client."""
    with deploy.lock(), tempfile.TemporaryDirectory(prefix='mcp-local-kamal-') as directory:
        if target == 'memoryd' and operation == 'stop':
            current = deploy.remote('current')
            if not current or current.get('authority') != 'kamal':
                raise ValueError('MemoryD stop requires accepted Kamal ownership')
            state = deploy.remote('memoryd-inventory')
            if memoryd_stopped(state):
                return {'operation': operation, **state}
            config = deploy.configuration(directory, current['manifest'])
            for name in reversed(deploy.MEMORYD_ORDER):
                item = state['services'].get('mcp-control-plane-' + name)
                if item and item['state'] not in ('exited', 'created'):
                    deploy.kamal(config, 'stop', name)
            after = deploy.remote('memoryd-inventory')
            if not memoryd_stopped(after):
                raise RuntimeError('MemoryD accessories did not stop; persistent data was retained')
            return {'operation': operation, **after}
        before = deploy.remote('lifecycle-check')
        if target == 'memoryd':
            state = deploy.remote('memoryd-status')
            if operation == 'details':
                return state
            if operation == 'start' and state['status'] == 'HEALTHY':
                return {'operation': operation, **state}
            current = deploy.remote('current')
            config = deploy.configuration(directory, current['manifest'])
            if state['status'] != 'STOPPED' or state['volume_exists'] is not True:
                raise ValueError('MemoryD start requires both existing stopped accessories and their persistent volume')
            for name in deploy.MEMORYD_ORDER:
                deploy.kamal(config, 'start', name)
            deploy.remote('memoryd-wait')
            after = deploy.remote('memoryd-status')
            if after['status'] != 'HEALTHY':
                raise RuntimeError('MemoryD accessories did not return healthy')
            return {'operation': operation, **after}
        if operation == 'details':
            return before if target == 'all' else before['inventory'][target]
        if target == 'all' and operation == 'stop':
            memoryd = deploy.remote('memoryd-inventory')
            if not memoryd_stopped(memoryd):
                raise ValueError('Stop MemoryD first: bin/kamal accessory stop memoryd')
        current = deploy.remote('current')
        config = deploy.configuration(directory, current['manifest'])
        names = list(deploy.ORDER) if target == 'all' else [target]
        if operation == 'stop':
            for name in reversed(names):
                deploy.kamal(config, 'stop', name)
            if target == 'all':
                deploy.remote('devsy-stop')
        else:
            if target == 'all':
                deploy.remote('devsy-ensure')
            for name in names:
                if name == 'tunnel':
                    deploy.remote('lifecycle-check')
                    deploy.remote('identity-check')
                deploy.kamal(config, 'start', name)
                deploy.remote('wait', {'owner': 'kamal', 'service': name})
            if target == 'all':
                if deploy.remote('snapshot')['identity'] != current['identity']:
                    raise RuntimeError('Started services do not match the recorded Executor identity')
        after = deploy.remote('status')
        if operation == 'stop' and any(after['inventory'][name]['state'] not in ('exited', 'created') for name in names):
            raise RuntimeError('A requested accessory did not stop')
        if target == 'all' and operation == 'stop':
            memoryd = deploy.remote('memoryd-inventory')
            if not memoryd_stopped(memoryd):
                raise RuntimeError('MemoryD is running; stop-all did not complete')
            after['memoryd'] = memoryd
        return {'operation': operation, **after}


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    if argv in ([], ['--help'], ['help']):
        print(HELP)
        return 0
    try:
        confirmed = False
        if argv and argv[-1] == '--confirm-import-quiescent':
            if argv[:-1] != ['accessory','reconcile-registration','memoryd']:
                raise ValueError('--confirm-import-quiescent is only valid for MemoryD registration reconciliation')
            argv.pop()
            confirmed = True
        operation, target = parse_command(argv)
        bundle_environment()
        if operation == 'setup-local':
            return subprocess.run(['bundle', '_2.6.9_', 'install'], cwd=deploy.ROOT).returncode
        deploy.configure_local(deploy.ROOT / '.env.kamal.local')
        deploy.trusted_context(os.environ, local=True)
        if operation in ('start', 'stop', 'details'):
            result = lifecycle(operation, target)
        else:
            result = deploy.execute(argparse.Namespace(
                operation='cas' if operation == 'deploy' and target == 'cas' else
                          'memoryd' if operation == 'deploy' and target == 'memoryd' else
                          'memoryd-transfer' if operation == 'transfer' and target == 'memoryd' else
                          'memoryd-network' if operation == 'network' and target == 'memoryd' else
                          'memoryd-register' if operation == 'register' and target == 'memoryd' else
                          'memoryd-registration-reconcile' if operation == 'reconcile-registration' else operation,
                confirm_import_quiescent=confirmed,
                local=True, approve_full_stack=True, cas_digest='', cas_revision='',
            ))
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
