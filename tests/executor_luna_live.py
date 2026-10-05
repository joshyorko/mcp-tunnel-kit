#!/usr/bin/env python3
"""Disposable pinned Executor + compiled Luna; no operator state or native inference.

All approvals below target only an isolated Luna with no authorized repositories,
no profiles, and a deliberately absent native executable. Real product domain
errors must survive the complete approved path. This is not live factory proof.
"""
import argparse
import contextlib
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import uuid

from executor_devsy_live import (disposable_executor, fixture_servers, successful, require, docker,
                                 CODEX_CONTROLS, CODEX_RESULT, READ_RESULT)
from luna_fixture import real_runtime, adapter, seed_large_history
from luna_product_contract import verify
import compose_control as control
import luna_bridge as bridge

STAGE = 'setup'
MUTATIONS = {
    'start_factory': {'repository': 'not-authorized', 'objective': 'Isolated integration test',
        'acceptance': ['No inference'], 'non_goals': ['No native process'], 'finish': 'local_candidate',
        'profile': 'not-authorized', 'capacity': 1, 'repair_attempts': 0, 'wall_seconds': 30,
        'idempotency_key': 'isolated-executor-luna'},
    'steer_factory_run': {'run_id': 'missing-isolated-run', 'expected_turn_id': 'missing-isolated-turn', 'message': 'Isolated integration test'},
    'cancel_factory_run': {'run_id': 'missing-isolated-run'},
    'resume_factory_run': {'run_id': 'missing-isolated-run', 'message': 'Isolated integration test',
                           'expected_decision_id': 'missing-isolated-decision'},
}


class RecordingRuntime:
    def __init__(self, upstream):
        self.upstream, self.calls = upstream, []
    def catalog(self):
        return self.upstream.catalog()
    def call(self, name, arguments):
        self.calls.append({'name': name, 'arguments': arguments})
        return self.upstream.call(name, arguments)


def executor_result(result):
    # beta.8 McpToolResult retains content/structuredContent/isError/_meta.
    # resultType is a 2026 transport discriminator, absent in its legacy SDK.
    require(result.get('resultType') == 'complete', 'Unexpected canonical result type')
    return {key: value for key, value in result.items() if key != 'resultType'}


def readiness(session):
    deadline = time.monotonic() + 45
    while True:
        try:
            control.search_luna(session)
            return
        except control.ControlError:
            require(time.monotonic() < deadline, 'Luna catalog failed to become available')
            time.sleep(0.5)  # Only read-only discovery is repeated.


def retained_approval_policy(session, fixtures):
    """Luna import must not change main's distinct Codex and Devsy policies."""
    for name in sorted(CODEX_CONTROLS | {'list_targets', 'discover_threads'}):
        before = list(fixtures['codex_calls'])
        result = successful(control, session, 'return await tools.codex.' + name + '({});')
        require(result == CODEX_RESULT, 'Trusted Codex call did not finish without Executor approval')
        require(fixtures['codex_calls'] == before + [{'name': name, 'arguments': {}}],
                'Codex call was changed or repeated')
    for name in ('provider_list', 'workspace_list'):
        result = successful(control, session, 'return await tools.devsy.' + name + '({});')
        require(result == READ_RESULT, 'Devsy read unexpectedly required approval')
    before = fixtures['calls']()
    pending = control.execution(session.call('tools/call', {'name': 'execute', 'arguments': {
        'code': 'return await tools.devsy.workspace_delete({});'}}))
    require(pending.get('status') == 'approval-required', 'Devsy mutation lost its Executor approval gate')
    require(fixtures['calls']() == before, 'Devsy mutation reached its fixture without approval')


@contextlib.contextmanager
def private_network():
    """Own a disposable Docker bridge; never attach to an operator network."""
    name = 'executor-luna-fixture-' + uuid.uuid4().hex
    # Let Docker choose a collision-free private range from its own address pools.
    docker('network', 'create', '--driver', 'bridge', name)
    try:
        details = json.loads(docker('network', 'inspect', name))[0]
        require(details['Driver'] == 'bridge' and details['Name'] == name, 'Unexpected fixture network')
        ipam = details['IPAM']['Config']
        require(len(ipam) == 1, 'Expected one fixture subnet')
        subnet, gateway = ipam[0]['Subnet'], ipam[0]['Gateway']
        require(ipaddress.ip_address(gateway).is_private, 'Fixture gateway is not private')
        yield name, gateway, subnet
    finally:
        docker('network', 'rm', name)


def exercise(origin, restart, fixtures, url, runtime):
    global STAGE
    STAGE = 'disposable owner setup'
    browser = control.Http(origin)
    browser.deadline = time.monotonic() + 900
    require(browser.request('GET', '/api/auth/self-host/config')[0].get('setup') is True,
            'Refusing to initialize an existing Executor')
    _, headers = browser.request('POST', '/api/auth/self-host/setup', {
        'name': 'Luna CI Owner', 'email': 'luna-ci@example.test',
        'password': 'Disposable-' + secrets.token_hex(24), 'organizationName': 'Luna CI lab',
    }, {'Origin': origin})
    cookie = '; '.join(value.split(';', 1)[0] for value in headers.get_all('Set-Cookie', []))
    require(bool(cookie), 'Fixture setup did not issue browser session')
    browser_headers = {'Origin': origin, 'Cookie': cookie}
    organizations = browser.request('GET', '/api/auth/organization/list', headers=browser_headers)[0]
    require(len(organizations) == 1, 'Expected one disposable organization')
    organization = organizations[0]['id']
    token = browser.request('POST', '/api/auth/api-key/create', {
        'name': 'Disposable Luna CI', 'expiresIn': 1200, 'metadata': {'organization': organization},
    }, browser_headers)[0]
    try:
        http = control.Http(origin, 'Bearer ' + token['key'])
        http.deadline = time.monotonic() + 900
        prefix = '/api/organizations/' + urllib.parse.quote(organization, safe='')
        STAGE = 'retained Codex and Devsy imports'
        retained = [(name, control.ensure_mcp_app(http, fixtures[name.lower()], name)) for name in ('Codex', 'Devsy')]
        before = {name: http.request('GET', prefix + '/apps/' + receipt['id'] + '/source')[0]
                  for name, receipt in retained}
        STAGE = 'Luna import and scoped read-only discovery'
        receipt = control.ensure_mcp_app(http, url, 'LunaFactory')
        session = control.Mcp(http, '/mcp?elicitation_mode=browser')
        control.verify_compact(session)
        readiness(session)
        STAGE = 'Codex and Devsy approval policy after Luna import'
        retained_approval_policy(session, fixtures)
        STAGE = 'Luna read-only discovery and results'
        control.read_luna(session, 'fixture-history-0')
        large = successful(control, session, '''
const result = await tools.lunafactory.list_factory_runs({limit: 100});
const runs = result.structuredContent.runs;
return {count: runs.length, unique: new Set(runs.map(run => run.id)).size,
  exact: runs.every(run => run.objective === 'x'.repeat(1000) &&
    run.acceptance.length === 32 && run.acceptance.every(item => item === 'a'.repeat(700)))};
''')
        require(large == {'count': 100, 'unique': 100, 'exact': True}, 'Executor lost bounded large-history content')
        for name, arguments in [('get_factory_capabilities', {}), ('list_factory_runs', {'limit': 1}),
                                ('get_factory_run', {'run_id': 'fixture-history-0'}),
                                ('get_factory_run', {'run_id': 'missing-isolated-run'})]:
            expected = executor_result(runtime.upstream.call(name, arguments))
            actual = successful(control, session, 'return await tools.lunafactory.' + name + '(' + json.dumps(arguments) + ');')
            require(actual == expected, 'Real Luna result changed through Executor: ' + name)
        for method in ('resources/list', 'resources/templates/list'):
            try:
                result = session.call(method, {})
            except control.ControlError:
                continue
            require(not result.get('resources') and not result.get('resourceTemplates'), 'Executor unexpectedly exposes native resources')
        for name in bridge.APP_TOOLS:
            before_calls = list(runtime.calls)
            hidden = control.execution(session.call('tools/call', {'name': 'execute', 'arguments': {
                'code': 'return await tools.lunafactory.' + name + '({});'}}))
            require(not hidden.get('execution', {}).get('ok') and hidden.get('status') != 'approval-required',
                    'An app-only tool was exposed by Executor')
            require(runtime.calls == before_calls, 'An app-only tool reached the canonical runtime')

        for index, (name, arguments) in enumerate(MUTATIONS.items()):
            STAGE = 'browser approval and real runtime rejection: ' + name
            before_calls = list(runtime.calls)
            pending = control.execution(session.call('tools/call', {'name': 'execute', 'arguments': {
                'code': 'return await tools.lunafactory.' + name + '(' + json.dumps(arguments) + ');'}}))
            require(pending.get('status') == 'approval-required', 'Luna mutation bypassed browser approval: ' + name)
            require(runtime.calls == before_calls, 'Luna mutation dispatched before approval')
            require(pending.get('invocation', {}).get('app') == receipt['id']
                    and pending['invocation']['tool'] == name, 'Approval identifies the wrong invocation')
            parsed = urllib.parse.urlsplit(pending['approvalUrl'])
            require(parsed.scheme + '://' + parsed.netloc == origin, 'Approval left disposable origin')
            require(token['key'] not in pending['approvalUrl'], 'Approval URL disclosed PAT')
            review_path = '/api/mcp/approvals/' + urllib.parse.quote(pending['requestId'], safe='') + '?' + parsed.query
            try:
                browser.request('GET', review_path)
            except urllib.error.HTTPError as error:
                require(error.code in {401, 403}, 'Unexpected anonymous approval result')
            else:
                raise AssertionError('Anonymous approval access succeeded')
            if index == 0:
                STAGE = 'repeat import and pending-request retention without restart'
                for _ in range(2):
                    require(control.ensure_mcp_app(http, url, 'LunaFactory', receipt) == receipt, 'Luna identity changed')
                require(control.ensure_mcp_app(http, url, 'LunaFactory', receipt, allow_import=False) == receipt,
                        'Read-only verification changed Luna identity')
                for retained_name, retained_receipt in retained:
                    require(control.ensure_mcp_app(http, fixtures[retained_name.lower()], retained_name,
                            retained_receipt, allow_import=False) == retained_receipt, 'Existing app identity changed')
                    require(http.request('GET', prefix + '/apps/' + retained_receipt['id'] + '/source')[0] == before[retained_name],
                            'Luna changed existing app source/deployment')
                require(runtime.calls == before_calls, 'Reimport/verification dispatched a pending mutation')
            review = browser.request('GET', review_path, headers=browser_headers)[0]
            require(review.get('status') == 'pending', 'Original browser approval was not retained')
            browser.request('POST', review_path, {'response': {'action': 'accept'}}, browser_headers)
            resumed = control.execution(session.call('tools/call', {'name': 'resume', 'arguments': {'requestId': pending['requestId']}}))
            require(resumed.get('status') == 'completed' and resumed.get('execution', {}).get('ok'),
                    'Approved isolated mutation did not finish')
            result = resumed['execution']['value']
            require(result.get('isError') is True, 'Unconfigured runtime accepted a mutation')
            require(runtime.calls == before_calls + [{'name': name, 'arguments': arguments}],
                    'Approved mutation was not forwarded exactly once')
            require(result == executor_result(runtime.upstream.call(name, arguments)), 'Product authorization error was not preserved')
        STAGE = 'restart preserves apps but loses beta.8 in-memory continuations'
        before_calls = list(runtime.calls)
        pending = control.execution(session.call('tools/call', {'name': 'execute', 'arguments': {
            'code': 'return await tools.lunafactory.cancel_factory_run({run_id:"restart-unapproved"});'}}))
        require(pending.get('status') == 'approval-required', 'Restart fixture did not pause before dispatch')
        parsed = urllib.parse.urlsplit(pending['approvalUrl'])
        review_path = '/api/mcp/approvals/' + urllib.parse.quote(pending['requestId'], safe='') + '?' + parsed.query
        saved_session = session.session_state()
        restart()
        session = control.Mcp(http, '/mcp?elicitation_mode=browser', state=saved_session)
        require(control.ensure_mcp_app(http, url, 'LunaFactory', receipt, allow_import=False) == receipt,
                'Restart changed Luna identity')
        for retained_name, retained_receipt in retained:
            require(control.ensure_mcp_app(http, fixtures[retained_name.lower()], retained_name,
                    retained_receipt, allow_import=False) == retained_receipt, 'Restart changed existing app identity')
            require(http.request('GET', prefix + '/apps/' + retained_receipt['id'] + '/source')[0] == before[retained_name],
                    'Restart changed existing app source/deployment')
        require(browser.request('GET', review_path, headers=browser_headers)[0].get('status') == 'unavailable',
                'Pinned beta.8 restart continuation behavior changed; review the operator contract')
        STAGE = 'old MCP session cannot resume after process restart'
        try:
            unavailable = control.execution(session.call('tools/call', {'name': 'resume', 'arguments': {'requestId': pending['requestId']}}))
            require(unavailable.get('status') == 'unavailable', 'Lost continuation was unexpectedly resumed')
        except urllib.error.HTTPError as error:
            require(error.code == 404, 'Unexpected old-session restart response: ' + str(error.code))
        require(runtime.calls == before_calls, 'An unapproved mutation dispatched during restart/recovery')
        print('Verified beta.8 limitation: process restart loses suspended approvals/sessions; original resume is unavailable and no mutation is replayed.')
        STAGE = 'fresh read-only session after restart'
        session = control.Mcp(http, '/mcp?elicitation_mode=browser')
        readiness(session)
        STAGE = 'Codex and Devsy approval policy after restart'
        retained_approval_policy(session, fixtures)
        require(runtime.upstream.call('get_factory_capabilities', {})['structuredContent']['status_inference_calls'] == 0,
                'Isolated status probe triggered inference')
    finally:
        browser.request('POST', '/api/auth/api-key/delete', {'keyId': token['id']}, browser_headers)


def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--ui', required=True)
    args = parser.parse_args()
    verify(args.binary, args.ui)
    with tempfile.TemporaryDirectory(prefix='executor-luna-ci-') as directory, private_network() as (network, gateway, subnet):
        with real_runtime(args.binary, args.ui, seed_large_history) as upstream, fixture_servers(Path(directory), gateway, subnet) as fixtures:
            runtime = RecordingRuntime(upstream)
            with adapter(runtime, gateway, subnet) as url:
                with disposable_executor(control, [url, fixtures['codex'], fixtures['devsy']], network) as (origin, restart):
                    exercise(origin, restart, fixtures, url, runtime)
    print('Pinned Executor + compiled Luna: scoped reads, app-only filtering, four approval-gated calls, exact errors, import/pending retention, app retention and distinct Codex/Devsy approval policies across restart verified.')
    print('No real repository, native process, inference, credentials, or production service was used.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            detail += ' status=' + str(error.code)
        print(STAGE + ': ' + detail, file=sys.stderr)
        raise SystemExit(1)
