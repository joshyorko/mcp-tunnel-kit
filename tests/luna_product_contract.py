#!/usr/bin/env python3
"""Probe a compiled Luna artifact in isolated temporary state, without inference."""
import argparse
import json
from pathlib import Path
import sys

from luna_fixture import real_runtime, adapter, contract, seed_large_history
import luna_bridge as bridge
import compose_control as control


def verify(binary, ui, snapshot=None):
    with real_runtime(binary, ui, seed_large_history) as upstream:
        discovery = upstream.rpc('server/discover', {})
        tools = upstream.rpc('tools/list', {})['tools']
        by_name = {tool['name']: tool for tool in tools}
        assert set(by_name) == bridge.MODEL_TOOLS | bridge.APP_TOOLS
        assert discovery['capabilities']['extensions']['io.modelcontextprotocol/ui']['mimeTypes'] == ['text/html;profile=mcp-app']
        assert discovery['capabilities']['extensions']['openai/settings'] == {
            'readTool': 'read_factory_settings', 'updateTool': 'update_factory_settings'}
        for name, kind in [('open_factory', 'global'), ('open_factory_panel', 'thread')]:
            assert by_name[name]['_meta']['ui']['resourceUri'] == bridge.APP_URI
            assert by_name[name]['_meta']['openai/ui']['entrypoints'] == [{'type': kind}]
        for name in bridge.APP_TOOLS:
            assert by_name[name]['_meta']['ui']['visibility'] == ['app']
        resource = upstream.rpc('resources/read', {'uri': bridge.APP_URI})['contents'][0]
        assert resource['uri'] == bridge.APP_URI and resource['mimeType'] == 'text/html;profile=mcp-app'
        assert '<html' in resource['text'].lower() and '<script' in resource['text'].lower()
        with adapter(upstream) as url:
            session = control.Mcp(control.Http(url.removesuffix('/executor/mcp'), max_response_bytes=bridge.MAX_RESPONSE), '/executor/mcp')
            control.verify_luna_catalog(session.tools())
            for name, arguments in [('get_factory_capabilities', {}), ('list_factory_runs', {'limit': 1}),
                                    ('get_factory_run', {'run_id': 'fixture-history-0'}),
                                    ('get_factory_run', {'run_id': 'isolated-missing-run'})]:
                direct = upstream.call(name, arguments)
                forwarded = session.call('tools/call', {'name': name, 'arguments': arguments})
                assert direct == forwarded, name
            capabilities = upstream.call('get_factory_capabilities', {})['structuredContent']
            assert capabilities['status_inference_calls'] == 0
            assert capabilities['repositories'] == [] and capabilities['profiles'] == []
            unicode_args = {'repository': 'not-authorized', 'objective': 'UTF-8 transport boundary',
                'acceptance': ['é' * 400] * 32, 'non_goals': [], 'finish': 'local_candidate',
                'profile': 'not-authorized', 'capacity': 1, 'repair_attempts': 0, 'wall_seconds': 30,
                'idempotency_key': 'isolated-unicode-transport'}
            direct = upstream.call('start_factory', unicode_args)
            forwarded = session.call('tools/call', {'name': 'start_factory', 'arguments': unicode_args})
            assert direct == forwarded and direct['isError'] is True
            assert direct['content'][0]['text'] == 'unknown_repository'
            direct = upstream.call('list_factory_runs', {'limit': 100})
            assert len(json.dumps(direct).encode()) > 2 * 1024 * 1024
            assert len(direct['structuredContent']['runs']) == 100
            assert session.call('tools/call', {'name': 'list_factory_runs', 'arguments': {'limit': 100}}) == direct
        actual = {'discovery': discovery, 'tools': tools}
        if snapshot:
            Path(snapshot).write_text(json.dumps(actual, indent=2) + '\n')
        else:
            expected = contract()
            assert actual == {key: expected[key] for key in actual}, 'Compiled product contract changed; inspect and explicitly refresh the snapshot'
    print('Compiled Luna: twelve canonical tools, native resource/entrypoints, seven-tool adapter, exact read results, zero inference verified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--ui', required=True)
    parser.add_argument('--write-snapshot')
    args = parser.parse_args()
    verify(args.binary, args.ui, args.write_snapshot)
