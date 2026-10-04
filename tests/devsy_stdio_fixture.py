#!/usr/bin/env python3
"""Synthetic Devsy CLI. Never invokes tools or a provider outside this process."""
import json
import os
import sys
import time
from pathlib import Path

NAMES = ['provider_list', 'workspace_list', 'workspace_status', 'workspace_create',
         'workspace_start', 'workspace_stop', 'workspace_delete', 'workspace_exec',
         'provider_add', 'provider_delete', 'provider_use', 'future_tool']
assert sys.argv[1:] == ['mcp', 'serve']
mode = os.environ.get('FIXTURE_MODE', '')
if os.environ.get('FIXTURE_PID'):
    Path(os.environ['FIXTURE_PID']).write_text(str(os.getpid()))
if mode == 'hang':
    time.sleep(120)
if mode == 'stderr':
    print('PRIVATE_FIXTURE_DO_NOT_LOG', file=sys.stderr)
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request:
        continue
    method = request['method']
    if method == 'initialize':
        result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'synthetic-devsy', 'version': '1'}}
    elif method == 'tools/list':
        names = NAMES if mode != 'incomplete' else NAMES[:2]
        result = {'tools': [{'name': name, 'description': 'Synthetic ' + name,
                            'inputSchema': {'type': 'object', 'properties': {}},
                            'annotations': {'readOnlyHint': True, 'destructiveHint': False}}
                           for name in names]}
    elif method == 'tools/call':
        name = request['params']['name']
        marker = os.environ.get('FIXTURE_CALLS')
        if marker:
            with open(marker, 'a') as handle:
                handle.write(name + '\n')
        result = {'content': [{'type': 'text', 'text': json.dumps({'tool': name, 'items': []})}]}
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
