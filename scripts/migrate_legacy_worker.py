#!/usr/bin/env python3
"""Reconcile an observed legacy RCC creation; never creates or deletes resources."""
import argparse
import json
import os
from pathlib import Path

from devsy_bridge import Devsy, state_lock
from compose_control import read_private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--capability-file', required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--workspace-uid', required=True)
    parser.add_argument('--created-at', required=True, type=float)
    args = parser.parse_args()
    config = json.loads(read_private(Path(args.config)))
    state = Path(config['state'])
    # Exclude the live bridge throughout scope migration. Caller stops it first.
    with state_lock(state, 'daemon.lock', nonblocking=True):
        env = dict(os.environ)
        env['DEVSY_HOME'] = config['home']
        devsy = Devsy(config['binary'], config['cwd'], env,
                      creation_state=state / 'creation-receipts', scope_source=config['scope_source'])
        _, receipts = devsy.receipts()
        result = devsy.scope.migrate_legacy_creation(
            receipts=receipts, name='rcc-worker-01', operation_id=args.operation_id,
            fingerprint=args.fingerprint, source='git:https://github.com/joshyorko/rcc.git',
            workspace_uid=args.workspace_uid, created_at=args.created_at,
            credential='Bearer ' + read_private(Path(args.capability_file)).strip())
        print(json.dumps({key: result.get(key) for key in
                          ('name', 'operation_id', 'status', 'retry_safe', 'new_request_allowed', 'reconciliation')}))
        return 0 if result.get('new_request_allowed') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
