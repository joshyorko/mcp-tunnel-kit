"""Opt-in restored MemoryD -> stock Executor test on a disposable outbound network."""

import email.message
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
import uuid

import pytest

import executor_devsy_live as live
import test_memoryd_restore_docker as recovery
import vm_deploy_host as host


pytestmark = pytest.mark.skipif(
    os.environ.get('MCP_MEMORYD_EXECUTOR_INTEGRATION') != '1',
    reason='set MCP_MEMORYD_EXECUTOR_INTEGRATION=1 for the disposable Executor fixture',
)

ADAPTER_IMAGE = ('ghcr.io/joshyorko/codex-action-server@sha256:'
                 'a2c4b43376f11285c0226d81c1edc68b040fb7c10b9cb165c25b5e0cb628e328')
BRIDGE_PATH = Path(__file__).resolve().parents[1] / 'scripts/codex_memoryd_mcp.py'
EXECUTOR_ORIGIN = 'http://127.0.0.1:4312'
MEMORYD_ORIGIN = 'http://127.0.0.1:8090'

# This runs inside the isolated adapter container. Request headers and generated
# fixture credentials arrive over stdin, never as a command-line argument.
HTTP_CLIENT = r'''
import json,sys,urllib.error,urllib.request
request=json.load(sys.stdin)
body=request.get('body')
encoded=None if body is None else json.dumps(body).encode()
headers=request['headers']
if encoded is not None: headers['Content-Type']='application/json'
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
req=urllib.request.Request(request['url'],data=encoded,headers=headers,method=request['method'])
try:
    response=opener.open(req,timeout=60)
except urllib.error.HTTPError as error:
    print('fixture-http-status '+str(error.code),file=sys.stderr)
    sys.exit(2)
with response:
    sse='text/event-stream' in response.headers.get('Content-Type','')
    raw=b''; event=[]; total=0
    while True:
        chunk=response.read1(4096)
        if not chunk: break
        total+=len(chunk)
        if total>2*1024*1024: raise ValueError('response too large')
        raw+=chunk
        if sse:
            while b'\n' in raw:
                line,raw=raw.split(b'\n',1)
                line=line.rstrip(b'\r').decode()
                if not line and event:
                    data=json.loads('\n'.join(event))
                    if 'result' in data or 'error' in data:
                        print(json.dumps({'data':data,'headers':list(response.headers.items())}));sys.exit(0)
                    event=[]
                elif line.startswith('data:'): event.append(line[5:].lstrip())
    if sse: raise ValueError('incomplete stream')
    data={} if request.get('empty') and not raw else json.loads(raw)
    print(json.dumps({'data':data,'headers':list(response.headers.items())}))
'''


class OutboundFixture(recovery.DisposableDocker):
    def __init__(self, activation_id, volume, network):
        super().__init__(activation_id, volume)
        self.network = network

    def assert_owned(self, name, *, helper=False):
        if name != self.names['daemon'] or helper:
            return super().assert_owned(name, helper=helper)
        row = self.container(name)
        if row is None:
            return None
        labels = row['Config'].get('Labels') or {}
        live.require(row['Id'] == self.ids.get(name) and row['Name'].lstrip('/') == name
                     and labels.get('mcp-control-plane.fixture') == self.activation_id
                     and labels.get('mcp-control-plane.recovery-activation') == self.activation_id
                     and row['Config'].get('Image') == host.MEMORYD_IMAGE
                     and row['HostConfig'].get('NetworkMode') == self.network
                     and row['HostConfig'].get('PortBindings') in ({}, None)
                     and row['HostConfig'].get('PublishAllPorts') is False,
                     'Fixture daemon identity or isolation changed')
        mounts = {(m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'], m['Destination'])
                  for m in row['Mounts']}
        live.require(mounts == self.expected_mounts[name], 'Fixture daemon mounts changed')
        return row

    def create_daemon(self):
        name = self.names['daemon']
        live.require(self.container(name) is None, 'Fixture daemon already exists')
        cid = self.docker('create', '--pull', 'never', '--name', name, '--network', self.network,
                          '--no-healthcheck', '--user', '10001:10001',
                          '--label', 'mcp-control-plane.fixture=' + self.activation_id,
                          '--label', 'mcp-control-plane.recovery-activation=' + self.activation_id,
                          '--mount', f'type=volume,source={self.volume},target=/data',
                          '--env', 'CODEX_MEMORYD_DB=/data/memory.db',
                          '--env', 'CODEX_MEMORYD_BIND=127.0.0.1:8787',
                          '--entrypoint', '/usr/local/bin/codex-memoryd', host.MEMORYD_IMAGE, 'serve').decode().strip()
        self.ids[name] = cid
        self.expected_mounts[name] = {('volume', self.volume, '/data')}
        row = self.assert_owned(name)
        live.require(row is not None and row['State']['Running'] is False, 'Fixture daemon create failed')
        return cid


class DisposableNetwork:
    def __init__(self, fixture, name):
        self.fixture = fixture
        self.name = name
        self.identifier = None

    def inspect(self):
        rows = json.loads(self.fixture.docker('network', 'inspect', self.name))
        live.require(len(rows) == 1 and rows[0]['Name'] == self.name and rows[0]['Id'] == self.identifier
                     and rows[0]['Driver'] == 'bridge' and rows[0]['Internal'] is False
                     and (rows[0].get('Labels') or {}).get('mcp-control-plane.fixture') == self.fixture.activation_id
                     and (rows[0].get('Labels') or {}).get('mcp-control-plane.recovery-activation') == self.fixture.activation_id,
                     'Fixture network ownership changed')
        return rows[0]

    def create(self):
        names = self.fixture.docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()
        live.require(self.name not in names, 'Fixture network already exists')
        self.identifier = self.fixture.docker('network', 'create', '--driver', 'bridge',
                                               '--label', 'mcp-control-plane.fixture=' + self.fixture.activation_id,
                                               '--label', 'mcp-control-plane.recovery-activation=' + self.fixture.activation_id,
                                               self.name).decode().strip()
        live.require(not self.inspect().get('Containers'), 'Fixture network is not empty')

    def cleanup(self):
        if self.identifier is None:
            return
        live.require(not self.inspect().get('Containers'), 'Fixture network still has endpoints; retained')
        self.fixture.docker('network', 'rm', self.identifier)


class Sidecars:
    def __init__(self, fixture, daemon_id):
        self.fixture = fixture
        self.daemon_id = daemon_id
        self.namespace = 'container:' + daemon_id
        self.names = {kind: fixture.prefix + '-' + kind for kind in ('adapter', 'executor')}
        self.images = {'adapter': ADAPTER_IMAGE, 'executor': live.IMAGE}
        self.ids = {}
        self.mounts = {}
        self.volume = 'mcp-executor-fixture-' + fixture.activation_id
        self.volume_created = False
        self.uncertain = False
        self.last_request = None
        self.phase = None

    def owned(self, kind):
        name = self.names[kind]
        row = self.fixture.container(name)
        if row is None:
            return None
        labels = row['Config'].get('Labels') or {}
        live.require(row['Id'] == self.ids.get(kind) and row['Name'].lstrip('/') == name,
                     'Fixture sidecar identity changed')
        live.require(labels.get('mcp-control-plane.fixture') == self.fixture.activation_id
                     and labels.get('mcp-control-plane.recovery-activation') == self.fixture.activation_id,
                     'Fixture sidecar ownership changed')
        live.require(row['Config'].get('Image') == self.images[kind]
                     and row['HostConfig'].get('NetworkMode') == self.namespace
                     and row['HostConfig'].get('PortBindings') in ({}, None)
                     and row['HostConfig'].get('PublishAllPorts') is False,
                     'Fixture sidecar isolation changed')
        actual = {(m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'],
                   m['Destination'], m['RW']) for m in row['Mounts']}
        live.require(actual == self.mounts[kind], 'Fixture sidecar mounts changed')
        return row

    def create(self, kind, arguments, mounts):
        live.require(self.fixture.container(self.names[kind]) is None, 'Fixture sidecar already exists')
        command = ['create', '--pull', 'never', '--name', self.names[kind], '--network', self.namespace,
                   '--label', 'mcp-control-plane.fixture=' + self.fixture.activation_id,
                   '--label', 'mcp-control-plane.recovery-activation=' + self.fixture.activation_id,
                   *arguments]
        self.uncertain = True
        cid = self.fixture.docker(*command).decode().strip()
        self.ids[kind] = cid
        self.mounts[kind] = mounts
        row = self.owned(kind)
        live.require(row is not None and row['State']['Running'] is False, 'Fixture sidecar create failed')
        self.uncertain = False
        self.fixture.docker('start', cid)
        live.require(self.owned(kind)['State']['Running'] is True, 'Fixture sidecar did not start')

    def create_volume(self):
        names = self.fixture.docker('volume', 'ls', '--format', '{{.Name}}').decode().splitlines()
        live.require(self.volume not in names, 'Fixture Executor volume already exists')
        self.uncertain = True
        self.fixture.docker('volume', 'create', '--driver', 'local', '--label',
                            'mcp-control-plane.fixture=' + self.fixture.activation_id, self.volume)
        self.volume_created = True
        self.verify_volume()
        self.uncertain = False

    def verify_volume(self):
        rows = json.loads(self.fixture.docker('volume', 'inspect', self.volume))
        live.require(len(rows) == 1 and rows[0].get('Name') == self.volume
                     and rows[0].get('Driver') == 'local'
                     and (rows[0].get('Labels') or {}).get('mcp-control-plane.fixture') == self.fixture.activation_id,
                     'Fixture Executor volume ownership changed')

    def start(self):
        self.create_volume()
        self.create('adapter', ['--user', '1000:1000', '--entrypoint', 'python3',
                               '--mount', f'type=bind,source={BRIDGE_PATH},target=/fixture/bridge.py,readonly',
                               '--env', 'CODEX_MEMORYD_URL=http://127.0.0.1:8787',
                               '--env', 'CODEX_MEMORYD_MCP_BIND=127.0.0.1:8090',
                               ADAPTER_IMAGE, '/fixture/bridge.py'],
                    {('bind', str(BRIDGE_PATH), '/fixture/bridge.py', False)})
        env = ['DO_NOT_TRACK=1', 'HOST=127.0.0.1', 'PORT=4312', 'BETTER_AUTH_URL=' + EXECUTOR_ORIGIN,
               'EXECUTOR_APPS_ALLOW_PRIVATE_FETCH=true', 'EXECUTOR_URL_ALLOW_LOOPBACK_HTTP=false',
               'EXECUTOR_URL_ALLOW_HTTP_ORIGINS=' + json.dumps([MEMORYD_ORIGIN])]
        arguments = ['--init', '--mount', f'type=volume,source={self.volume},target=/app/data']
        for item in env:
            arguments.extend(['--env', item])
        arguments.append(live.IMAGE)
        self.create('executor', arguments, {('volume', self.volume, '/app/data', True)})

    def restart_executor(self):
        row = self.owned('executor')
        live.require(row is not None and row['State']['Running'], 'Fixture Executor is unavailable')
        self.fixture.docker('restart', '--time', '10', row['Id'])
        live.require(self.owned('executor')['State']['Running'], 'Fixture Executor restart failed')

    def http(self, request):
        adapter = self.owned('adapter')
        live.require(adapter is not None and adapter['State']['Running'], 'Fixture adapter is unavailable')
        parsed = urllib.parse.urlsplit(request['url'])
        self.last_request = {'method': request['method'], 'path': parsed.path}
        self.uncertain = True
        try:
            result = subprocess.run(['docker', 'exec', '-i', adapter['Id'], 'python3', '-c', HTTP_CLIENT],
                                    input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=75)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Fixture HTTP command timed out; containers retained') from None
        self.uncertain = False
        status = re.search(rb'fixture-http-status ([0-9]{3})', result.stderr)
        if status:
            self.last_request['status'] = status.group(1).decode()
        elif b'ConnectionRefusedError' in result.stderr:
            self.last_request['status'] = 'connection-refused'
        live.require(result.returncode == 0, 'Fixture HTTP request failed; response withheld')
        return json.loads(result.stdout)

    def cleanup(self):
        if self.uncertain:
            return False
        for kind in ('executor', 'adapter'):
            row = self.owned(kind)
            if row is None:
                continue
            if row['State']['Running']:
                self.fixture.docker('stop', '--time', '10', row['Id'])
                row = self.owned(kind)
                live.require(row is not None and not row['State']['Running'], 'Fixture sidecar did not stop')
            self.owned(kind)
            self.fixture.docker('rm', row['Id'])
            live.require(self.fixture.container(self.names[kind]) is None, 'Fixture sidecar was retained')
        if self.volume_created:
            self.verify_volume()
            for row in self.fixture.existing():
                live.require(not any(m.get('Name') == self.volume for m in row.get('Mounts', [])),
                             'Fixture Executor volume still has a container')
            self.verify_volume()
            self.fixture.docker('volume', 'rm', self.volume)
        return True


def netns_http(sidecars, control):
    class NamespaceHttp:
        def __init__(self, origin, authorization=None):
            live.require(origin.rstrip('/') in (EXECUTOR_ORIGIN, MEMORYD_ORIGIN), 'Unexpected fixture HTTP origin')
            self.origin = origin.rstrip('/')
            self.authorization = authorization
            self.deadline = time.monotonic() + 600

        def request(self, method, path, body=None, headers=None, empty=False):
            live.require(time.monotonic() < self.deadline, 'Fixture HTTP deadline expired')
            request_headers = {'Accept': 'application/json, text/event-stream'}
            if self.authorization:
                request_headers['Authorization'] = self.authorization
            if headers:
                request_headers.update(headers)
            result = sidecars.http({'method': method, 'url': self.origin + path, 'body': body,
                                    'headers': request_headers, 'empty': empty})
            response_headers = email.message.Message()
            for name, value in result['headers']:
                response_headers.add_header(name, value)
            return result['data'], response_headers

    return NamespaceHttp


def wait_executor(control):
    http = control.Http(EXECUTOR_ORIGIN)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            value, _ = http.request('GET', '/api/auth/self-host/config')
            return value
        except (RuntimeError, AssertionError):
            time.sleep(0.5)
    raise ValueError('Synthetic Executor did not become ready')


def executor_proof(control, origin, restart, sidecars):
    sidecars.phase = 'Executor first-owner setup'
    browser = control.Http(origin)
    configuration = wait_executor(control)
    live.require(configuration.get('setup') is True, 'Fixture Executor is not empty')
    password = 'Synthetic-' + secrets.token_hex(24)
    _, headers = browser.request('POST', '/api/auth/self-host/setup', {
        'name': 'Synthetic Owner', 'email': 'memoryd-fixture@example.test',
        'password': password, 'organizationName': 'Synthetic MemoryD lab',
    }, {'Origin': origin})
    cookie = '; '.join(value.split(';', 1)[0] for value in headers.get_all('Set-Cookie', []))
    live.require(bool(cookie), 'Fixture setup did not issue a session')
    browser_headers = {'Origin': origin, 'Cookie': cookie}
    organizations, _ = browser.request('GET', '/api/auth/organization/list', headers=browser_headers)
    live.require(len(organizations) == 1, 'Fixture organization is ambiguous')
    token, _ = browser.request('POST', '/api/auth/api-key/create', {
        'name': 'Disposable MemoryD fixture', 'expiresIn': 600,
        'metadata': {'organization': organizations[0]['id']},
    }, browser_headers)
    http = control.Http(origin, 'Bearer ' + token['key'])
    url = MEMORYD_ORIGIN + '/mcp'
    sidecars.phase = 'Executor MemoryD app import'
    receipt = control.ensure_memoryd_app(http, url)
    sidecars.phase = 'MemoryD write and scope denials'
    live.require(control.probe_memoryd_denials(url) == {'write_blocked': True, 'scope_override_blocked': True},
                 'Fixture bridge did not block write and scope overrides')

    def check(label):
        sidecars.phase = label + ' Executor MemoryD discovery'
        session = control.Mcp(control.Http(origin, 'Bearer ' + token['key']), '/mcp?elicitation_mode=browser')
        search = live.successful(control, session, 'return await tools.search({namespace:"memoryd",query:"",limit:100});')
        paths = {item['path'] for item in search['items']}
        live.require(paths == {'tools.memoryd.memory_status', 'tools.memoryd.memory_search', 'tools.memoryd.memory_recall'},
                     'Executor MemoryD catalog is not exactly the three read-only tools')
        active = 'mr_' + hashlib.sha256(b'mr_\x1fsynthetic-0').hexdigest()[:32]
        archived = 'mr_' + hashlib.sha256(b'mr_\x1fsynthetic-1').hexdigest()[:32]
        for name, args in (('memory_status', '{}'), ('memory_search', '{query:"synthetic",limit:10}'),
                           ('memory_recall', '{query:"synthetic"}')):
            sidecars.phase = label + ' Executor ' + name
            value = live.successful(control, session, 'return await tools.memoryd.' + name + '(' + args + ');')
            live.require(value.get('isError') is not True and bool(value.get('content')), 'Fixture MemoryD read failed')
            payload = json.loads(value['content'][0]['text'])
            live.require(payload.get('ok') is True, 'Fixture MemoryD returned an unsuccessful read')
            if name == 'memory_search':
                matches = payload.get('data', {}).get('matches')
                live.require(isinstance(matches, list) and {item.get('id') for item in matches} == {active}
                             and archived not in {item.get('id') for item in matches}
                             and all(item.get('archived') is False and item.get('scope') == 'workspace'
                                     and item.get('workspace_id') == 'dakota-codex-only' for item in matches),
                             'Fixture scoped search did not preserve the active/archived boundary')
            elif name == 'memory_recall':
                data = payload.get('data', {})
                facts, citations = data.get('facts'), data.get('citations')
                live.require(isinstance(facts, list) and {fact.get('id') for fact in facts} == {active}
                             and isinstance(citations, list)
                             and {citation.get('memory_id') for citation in citations} == {active}
                             and all(fact.get('scope') == 'workspace'
                                     and fact.get('policy', {}).get('provenance', {}).get('profile_id') == 'personal'
                                     and fact.get('policy', {}).get('provenance', {}).get('workspace_id') == 'dakota-codex-only'
                                     for fact in facts),
                             'Fixture recall did not return the scoped active record and citation')
    check('Before restart')
    sidecars.phase = 'Executor restart'
    restart()
    wait_executor(control)
    sidecars.phase = 'Executor app identity after restart'
    live.require(control.ensure_memoryd_app(http, url, receipt) == receipt, 'Fixture app identity changed on restart')
    check('After restart')


def test_restored_memoryd_through_isolated_executor(tmp_path, monkeypatch):
    live.require(os.getuid() != 0 and Path('/var/run/docker.sock').is_socket(), 'Local Linux Docker is required')
    tmp_path.chmod(0o700)
    config = tmp_path / 'docker-config'
    config.mkdir(mode=0o700)
    (config / 'config.json').write_text('{}\n')
    (config / 'config.json').chmod(0o600)
    monkeypatch.setenv('DOCKER_CONFIG', str(config))
    monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    monkeypatch.delenv('DOCKER_AUTH_CONFIG', raising=False)
    activation_id = uuid.uuid4().hex
    volume = 'mcp-memoryd-fixture-' + activation_id
    monkeypatch.setattr(host, 'MEMORYD_VOLUME', volume)
    state = tmp_path / 'state'
    store = state / 'deployment'
    store.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    monkeypatch.setattr(host, 'STATE', state)
    monkeypatch.setattr(host, 'STORE', store)
    network_name = 'mcp-memoryd-outbound-' + activation_id
    fixture = OutboundFixture(activation_id, volume, network_name)
    network = DisposableNetwork(fixture, network_name)
    host._memoryd_restore_inventory()
    sidecars = None
    stage = 'synthetic backup'
    try:
        prepared, data, _ = recovery.prepared_fixture(tmp_path, fixture)
        data['memoryd']['adapter_image'] = ADAPTER_IMAGE
        data['memoryd']['adapter_sha256'] = hashlib.sha256(BRIDGE_PATH.read_bytes()).hexdigest()
        manifest = prepared / 'prepared-manifest.json'
        manifest.write_text(json.dumps(data) + '\n')
        manifest_sha = recovery.sha(manifest)
        monkeypatch.setattr(host, '_recovery_validator', lambda: lambda _path: data)
        host.write(store / 'activation-in-progress.json', {
            'schema_version': 1, 'activation_id': activation_id, 'status': 'installing', 'source_sha': 'd' * 40,
            'expected_identity': 'synthetic-identity', 'memoryd': data['memoryd'],
            'prepared_manifest_sha256': manifest_sha, 'original_stopped_attested': True})
        fixture.restore_uncertain = True
        stage = 'guarded restore'
        try:
            result = host.activation_memoryd_restore(str(prepared), manifest_sha, activation_id)
        finally:
            path = store / f'memoryd-restore-{activation_id}.json'
            if path.is_file():
                restore_receipt = json.loads(host.private(path))
                fixture.helper_name = restore_receipt['helper_name']
                fixture.nonce = restore_receipt['owner_nonce']
        live.require(result['memoryd_restored'] is True and restore_receipt['status'] == 'verified',
                     'Fixture recovery did not verify')
        fixture.restore_uncertain = False
        stage = 'fixture network connectivity'
        network.create()
        fixture.create_daemon()
        daemon_id = fixture.start('daemon')
        recovery.wait_health(fixture)
        fixture.docker('restart', '--time', '10', daemon_id)
        recovery.wait_health(fixture)
        fixture.exec('daemon', '/usr/bin/curl', '-fsS', '--max-time', '15', '-o', '/dev/null',
                     'https://registry.npmjs.org/')
        stage = 'isolated Executor startup'
        sidecars = Sidecars(fixture, daemon_id)
        sidecars.start()
        previous_control = sys.modules.get('compose_control')
        with monkeypatch.context() as isolated:
            isolated.setitem(sys.modules, 'compose_control', previous_control)
            control = live.load_script('compose_control')
            control.Http = netns_http(sidecars, control)
            stage = 'Executor MemoryD discovery and reads'
            executor_proof(control, EXECUTOR_ORIGIN, sidecars.restart_executor, sidecars)
        live.require(sys.modules.get('compose_control') is previous_control,
                     'Fixture did not restore the control module')
    except Exception as error:
        diagnostic = ''
        if sidecars is not None and sidecars.last_request is not None:
            item = sidecars.last_request
            path = item['path']
            if path.startswith('/api/organizations/'):
                path = '/api/organizations/<fixture>/' + '/'.join(path.split('/')[4:])
            diagnostic = ' after ' + item['method'] + ' ' + path + ' (' + item.get('status', 'response withheld') + ')'
        failed_stage = sidecars.phase if sidecars is not None and sidecars.phase else stage
        pytest.fail('Synthetic Executor integration failed at ' + failed_stage + ' (' + type(error).__name__ + ')' + diagnostic, pytrace=False)
    finally:
        if sidecars is None or sidecars.cleanup():
            fixture.cleanup()
            network.cleanup()
