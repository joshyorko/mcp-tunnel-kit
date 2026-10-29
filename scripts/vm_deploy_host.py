#!/usr/bin/env python3
"""Private VM deployment boundary. JSON output contains no credential values."""
import fcntl
import argparse
from datetime import datetime
import hashlib
import importlib.util
import io
import ipaddress
import json
import math
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from instance_profile import decode, load as load_instance_profile, validate

ROOT = None
STATE = None
STORE = None
PUBLIC_DOCKER_CONFIG = None
NETWORK = None
NATIVE_SSH = None
DEVSY = None
NAMES = {'compose': {'executor':'codex-control-plane-executor-1','schema-proxy':'codex-control-plane-executor-schema-proxy-1','cas':'codex-control-plane-codex-action-server-1','tunnel':'codex-control-plane-tunnel-client-1'},
         'kamal': {name:'mcp-control-plane-'+name for name in ('executor','schema-proxy','cas','tunnel')}}
MEMORYD_MIN_AVAILABLE_KB = 1_572_864
MEMORYD_SERVICES = {'mcp-control-plane-memoryd', 'mcp-control-plane-memoryd-mcp'}
MEMORYD_VOLUME = 'codex-memoryd-data'
MEMORYD_IMAGE = ('ghcr.io/joshyorko/codex-memoryd@sha256:'
                 '70465d5250f693d15408fe904d30e3035360d8a46ac6f1caea8c3660eac09996')
MEMORYD_CAPTURE_MAX_BYTES = 32 * 1024 * 1024
MEMORYD_CAPTURE_MIN_AVAILABLE_KB = 512 * 1024
MEMORYD_CAPTURE_TABLES = ('memory_records', 'conclusions', 'checkpoints', 'subjects', 'episodes',
                          'subject_aliases', 'relations', 'evidence_ledger', 'procedures',
                          'memory_sources', 'dream_runs', 'policy_events')
MEMORYD_READONLY_SNAPSHOT_CODE = r'''
import os, pathlib, shutil, sqlite3, stat, sys, tempfile, time
source = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
if not stat.S_ISREG(source.lstat().st_mode):
    raise SystemExit(1)
for suffix in ('-wal', '-shm'):
    sidecar = pathlib.Path(str(source) + suffix)
    if os.path.lexists(sidecar) and not stat.S_ISREG(sidecar.lstat().st_mode):
        raise SystemExit(1)
deadline = time.monotonic() + 150
def progress(_status, _remaining, _total):
    if time.monotonic() > deadline:
        raise TimeoutError('snapshot deadline')
with tempfile.TemporaryDirectory(prefix='memoryd-readonly-', dir='/tmp') as directory:
    target = pathlib.Path(directory) / 'source.db'
    src = sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst, pages=128, progress=progress, sleep=0.05)
        if dst.execute('PRAGMA integrity_check(1)').fetchone() != ('ok',):
            raise ValueError('integrity check')
    finally:
        dst.close()
        src.close()
    if not 0 < target.stat().st_size <= limit:
        raise ValueError('snapshot exceeds size bound')
    with target.open('rb') as data:
        shutil.copyfileobj(data, sys.stdout.buffer, 1024 * 1024)
'''


def configure_profile(profile):
    """Bind this standalone remote script to validated instance paths."""
    global ROOT,STATE,STORE,PUBLIC_DOCKER_CONFIG,NETWORK,NATIVE_SSH,DEVSY
    profile=validate(profile)
    ROOT=Path(profile['vm']['repo_dir'])
    STATE=Path(profile['vm']['state_dir'])
    STORE=STATE/'deployment'
    PUBLIC_DOCKER_CONFIG=STORE/'anonymous-docker-config'
    NETWORK=profile['vm']['network']
    NATIVE_SSH=Path(profile['vm']['native_ssh_dir'])
    DEVSY=profile['vm']['devsy']


def run(args, timeout=180, env=None):
    r = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
    if r.returncode:
        raise RuntimeError('VM operation failed: '+Path(args[0]).name+'; output withheld')
    return r.stdout


def ensure_anonymous_docker_config():
    """Create/validate an empty private config, isolated from ~/.docker."""
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    store_stat = STORE.lstat()
    if (not STORE.is_dir() or STORE.is_symlink() or store_stat.st_uid != os.getuid()
            or store_stat.st_mode & 0o777 != 0o700):
        raise ValueError('Deployment directory is not private')
    PUBLIC_DOCKER_CONFIG.mkdir(mode=0o700, exist_ok=True)
    directory_stat = PUBLIC_DOCKER_CONFIG.lstat()
    if (not PUBLIC_DOCKER_CONFIG.is_dir() or PUBLIC_DOCKER_CONFIG.is_symlink()
            or directory_stat.st_uid != os.getuid() or directory_stat.st_mode & 0o777 != 0o700):
        raise ValueError('Anonymous Docker config directory is unsafe')

    config = PUBLIC_DOCKER_CONFIG / 'config.json'
    try:
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(b'{}\n')
            stream.flush()
            os.fsync(stream.fileno())
    try:
        metadata = config.lstat()
        entries = {entry.name for entry in PUBLIC_DOCKER_CONFIG.iterdir()}
        if (entries != {'config.json'} or not config.is_file() or config.is_symlink()
                or metadata.st_uid != os.getuid() or metadata.st_mode & 0o777 != 0o600):
            raise ValueError('Anonymous Docker config is unsafe')
        read_fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
        opened_stat = os.fstat(read_fd)
        if (not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_uid != os.getuid()
                or opened_stat.st_mode & 0o777 != 0o600):
            os.close(read_fd)
            raise ValueError('Anonymous Docker config is unsafe')
        with os.fdopen(read_fd, 'rb') as stream:
            valid_config = stream.read(1024) == b'{}\n' and stream.read(1) == b''
    except OSError as exc:
        raise ValueError('Anonymous Docker config is unsafe') from exc
    if not valid_config:
        raise ValueError('Anonymous Docker config is unsafe')
    return PUBLIC_DOCKER_CONFIG


def anonymous_docker_environment():
    env = os.environ.copy()
    env.pop('DOCKER_AUTH_CONFIG', None)
    env['DOCKER_CONFIG'] = str(ensure_anonymous_docker_config())
    return env


def private(path):
    s = path.lstat()
    if not path.is_file() or path.is_symlink() or s.st_uid != os.getuid() or s.st_mode & 0o777 != 0o600:
        raise ValueError('Private file ownership/mode mismatch')
    return path.read_bytes()


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def write(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_mode & 0o077: raise ValueError('Deployment directory is not private')
    fd,tempname=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(value,f);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tempname,path)
        directory_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    finally:
        if os.path.exists(tempname):os.unlink(tempname)


def inspect():
    ids = run(['docker','ps','-aq']).decode().split()
    rows = json.loads(run(['docker','inspect',*ids])) if ids else []
    groups = {owner:{key:next((r for r in rows if r['Name'].lstrip('/')==name),None) for key,name in names.items()} for owner,names in NAMES.items()}
    live = lambda r: r and (r['State']['Running'] or r['State'].get('Paused'))
    if any(live(r) for r in groups['compose'].values()) and any(live(r) for r in groups['kamal'].values()):
        raise ValueError('Competing Compose/Kamal owners')
    writers = [r for r in rows if live(r) and any(m.get('Name')=='codex-control-plane_executor-data' for m in r.get('Mounts',[]))]
    if len(writers)>1: raise ValueError('Duplicate Executor writers')
    tunnel_id = private(STATE/'secrets/control-plane-tunnel-id').strip()
    matching = []
    for r in rows:
        if live(r) and ('tunnel-client' in r['Config'].get('Image','')):
            env = run(['docker','exec',r['Id'],'cat','/proc/1/environ'],timeout=10)
            d = dict(x.split(b'=',1) for x in env.split(b'\0') if b'=' in x)
            if d.get(b'CONTROL_PLANE_TUNNEL_ID')==tunnel_id: matching.append(r['Name'])
    if len(matching)>1: raise ValueError('Duplicate production tunnel identity')
    owner = 'kamal' if any(live(r) for r in groups['kamal'].values()) else 'compose'
    return owner,groups,matching


def _valid_memoryd_receipt(receipt):
    return (isinstance(receipt,dict) and set(receipt)=={'organization','id','url'}
            and all(isinstance(value,str) and value for value in receipt.values()))


def _memoryd_require_recorded_base(base):
    current=json.loads(private(STORE/'current.json'))
    if current.get('authority')!='kamal' or current.get('identity')!=base:
        raise ValueError('Executor identity drift prevents MemoryD registration')


def _memoryd_base_apps(apps,org,marker,gateway):
    matches=[app for app in apps if app.get('slug')=='memoryd' or app.get('name')=='MemoryD']
    if matches or marker:
        if (len(matches)!=1 or not marker or matches[0].get('slug')!='memoryd'
                or matches[0].get('name')!='MemoryD' or matches[0].get('id')!=marker.get('id')
                or marker.get('organization')!=org
                or marker.get('url')!=f"http://{gateway}:8090/mcp"):
            raise ValueError('MemoryD app identity does not match its private receipt')
        return [app for app in apps if app.get('id')!=marker['id']]
    return apps


def _memoryd_require_active_app(apps):
    matches = [app for app in apps if app.get('slug') == 'memoryd' or app.get('name') == 'MemoryD']
    if len(matches) != 1 or not matches[0].get('activeDeployment'):
        raise ValueError('MemoryD app is not uniquely active; capture refused')


def _memoryd_pending_app(intent,org,apps,get):
    """Validate an ambiguous import before treating it as our app."""
    import compose_control as c
    from urllib.parse import quote
    url=f"http://{NETWORK['gateway']}:8090/mcp"
    keys={'status','organization','url','transfer_manifest_sha256','transfer_receipt_sha256',
          'source_sha256','base_identity'}
    if (not isinstance(intent,dict) or set(intent)!=keys or intent['status'] not in ('prepared','importing')
            or intent['organization']!=org or intent['url']!=url
            or not isinstance(org,str) or not org
            or any(not isinstance(intent[key],str) or not re.fullmatch(r'[a-f0-9]{64}',intent[key])
                   for key in ('transfer_manifest_sha256','transfer_receipt_sha256','source_sha256','base_identity'))):
        raise ValueError('MemoryD pending registration identity changed')
    _memoryd_require_recorded_base(intent['base_identity'])
    transfer_id=intent['transfer_manifest_sha256']
    _require_completed_memoryd_transfer({'transfer_manifest_sha256':transfer_id})
    if hashlib.sha256(private(_memoryd_receipt_path(transfer_id))).hexdigest()!=intent['transfer_receipt_sha256']:
        raise ValueError('MemoryD pending registration transfer receipt changed')
    source=c.devsy_app_source(url)
    if hashlib.sha256(source.strip().encode()).hexdigest()!=intent['source_sha256']:
        raise ValueError('MemoryD pending registration source changed')
    matches=[app for app in apps if app.get('slug')=='memoryd' or app.get('name')=='MemoryD']
    if not matches:
        return None
    if intent['status']=='prepared':
        raise ValueError('MemoryD app appeared before the pending import was attempted')
    if (len(matches)!=1 or matches[0].get('slug')!='memoryd' or matches[0].get('name')!='MemoryD'
            or not isinstance(matches[0].get('id'),str) or not matches[0]['id']
            or not matches[0].get('activeDeployment')
            or sum(app.get('id')==matches[0]['id'] for app in apps)!=1):
        raise ValueError('MemoryD pending registration app is ambiguous')
    app=matches[0]
    path='/api/organizations/'+quote(org,safe='')+'/apps/'+quote(app['id'],safe='')+'/source'
    actual=get(path)
    files=actual.get('files',[]) if isinstance(actual,dict) else []
    if not isinstance(files,list) or sum(isinstance(file,dict) and file.get('path')=='index.ts' for file in files)!=1:
        raise ValueError('MemoryD pending registration source is ambiguous')
    c.verify_generated_source(actual,source,'MemoryD')
    return {'organization':org,'id':app['id'],'url':url}


def identity(executor, *, exclude_memoryd=False, require_memoryd_absent=False, require_memoryd_active=False):
    from urllib.request import Request,urlopen
    pat = private(STATE/'secrets/executor-pat').decode().strip()
    def get(path):
        with urlopen(Request('http://127.0.0.1:4312'+path,headers={'Authorization':'Bearer '+pat}),timeout=15) as r: return json.load(r)
    context=get('/api/context');org=context['organization'];apps=get('/api/organizations/'+org+'/inventory')['apps']
    if require_memoryd_absent and any(app.get('slug')=='memoryd' or app.get('name')=='MemoryD' for app in apps):
        raise ValueError('MemoryD registration reconciliation requires no matching apps')
    if require_memoryd_active:
        _memoryd_require_active_app(apps)
    intent=None
    has_intent=False
    if exclude_memoryd:
        marker_path=STATE/'bootstrap/memoryd-integration.json'
        has_marker=marker_path.exists() or marker_path.is_symlink()
        marker=json.loads(private(marker_path)) if has_marker else None
        if has_marker and not _valid_memoryd_receipt(marker):
            raise ValueError('MemoryD app receipt is invalid')
        intent_path=STATE/'bootstrap/memoryd-registration-pending.json'
        has_intent=intent_path.exists() or intent_path.is_symlink()
        intent=json.loads(private(intent_path)) if has_intent else None
        if has_intent:
            pending_app=_memoryd_pending_app(intent,org,apps,get)
            if marker is not None and marker!=pending_app:
                raise ValueError('MemoryD pending registration differs from its private receipt')
            if marker is None:
                marker=pending_app
        apps=_memoryd_base_apps(apps,org,marker,NETWORK['gateway'])
    proof={'organization':org,'apps':sorted((x['id'],x['slug']) for x in apps),'keys':{},'secrets':{}}
    for name in ('auth-secret.key','encryption.key','install-id'):
        raw=run(['docker','cp',executor+':/app/data/'+name,'-'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive: data=archive.extractfile(archive.getmembers()[0]).read()
        proof['keys'][name]=hashlib.sha256(data).hexdigest()
    for name in ('control-plane-api-key','control-plane-tunnel-id','executor-auth-header','executor-pat'):
        proof['secrets'][name]=hashlib.sha256(private(STATE/'secrets'/name)).hexdigest()
    digest=hashlib.sha256(json.dumps(proof,sort_keys=True).encode()).hexdigest()
    if has_intent and digest!=intent['base_identity']:
        raise ValueError('Executor identity drift prevents MemoryD registration recovery')
    return digest


def snapshot():
    owner,groups,tunnels=inspect()
    for name in ('control-plane-api-key','control-plane-tunnel-id','executor-auth-header','executor-pat'): private(STATE/'secrets'/name)
    inventory={key:{'name':r['Name'].lstrip('/'),'state':r['State']['Status'],'health':r['State'].get('Health',{}).get('Status'),'image':r['Image'],'restart':r['HostConfig']['RestartPolicy']['Name']} for key,r in groups[owner].items() if r}
    if set(inventory)!=set(NAMES[owner]): raise ValueError('Incomplete current control-plane inventory')
    if any(r['health']!='healthy' for r in inventory.values()): raise ValueError('Current production health failed; do not stop it')
    if len(tunnels)!=1: raise ValueError('Production tunnel count must be exactly one')
    return {'authority':owner,'inventory':inventory,'identity':identity(NAMES[owner]['executor']),'source_sha':run(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),'tunnel_count':1}


def status():
    owner,groups,tunnels=inspect()
    if (STORE/'current.json').exists():owner=json.loads(private(STORE/'current.json'))['authority']
    inventory={key:{'name':r['Name'].lstrip('/'),'state':r['State']['Status'],'health':r['State'].get('Health',{}).get('Status'),'image':r['Image'],'restart':r['HostConfig']['RestartPolicy']['Name']} for key,r in groups[owner].items() if r}
    return {'authority':owner,'inventory':inventory,'tunnel_count':len(tunnels),'healthy':len(inventory)==4 and all(x['health']=='healthy' and x['state']=='running' for x in inventory.values())}


def memoryd_resource_gate(raw_meminfo):
    fields = {}
    for line in raw_meminfo.splitlines():
        name, separator, value = line.partition(':')
        if separator:
            match = re.fullmatch(r'\s*(\d+)\s+kB\s*', value)
            if match:
                fields[name] = int(match.group(1))
    total = fields.get('MemTotal')
    available = fields.get('MemAvailable')
    if total is None or available is None:
        raise ValueError('VM memory inventory is incomplete')
    ready = available >= MEMORYD_MIN_AVAILABLE_KB
    return {
        'ready': ready,
        'reason': 'ready' if ready else 'insufficient_available_memory',
        'mem_total_kb': total,
        'mem_available_kb': available,
        'required_available_kb': MEMORYD_MIN_AVAILABLE_KB,
        'swap_total_kb': fields.get('SwapTotal', 0),
        'minimum_vm_ram_gib': None if ready else math.ceil(total / 1_048_576) + 1,
    }


def memoryd_listener_addresses(raw_ss):
    addresses=set()
    for line in raw_ss.splitlines():
        columns=line.split()
        if len(columns)>=5 and columns[0].startswith('tcp') and columns[1]=='LISTEN':
            local=columns[4]
            if local.endswith(':8787') or local.endswith(':8090'):
                addresses.add(local)
    return addresses


def memoryd_preflight():
    existing = status()
    memory = memoryd_resource_gate(Path('/proc/meminfo').read_text())
    containers = run(['docker', 'ps', '-aq']).decode().split()
    rows = json.loads(run(['docker', 'inspect', *containers])) if containers else []
    owned = [row for row in rows if (row.get('Config', {}).get('Labels') or {}).get('service') in MEMORYD_SERVICES]
    volumes = set(run(['docker', 'volume', 'ls', '--format', '{{.Name}}']).decode().split())
    listeners=sorted(memoryd_listener_addresses(run(['ss','-Hln']).decode()))
    blockers = []
    if existing.get('authority') != 'kamal' or not existing.get('healthy'):
        blockers.append('existing_control_plane_unhealthy_or_unowned')
    if existing.get('tunnel_count') != 1:
        blockers.append('expected_exactly_one_existing_tunnel')
    if not memory['ready']:
        blockers.append(memory['reason'])
    if owned:
        blockers.append('memoryd_container_state_already_exists')
    if MEMORYD_VOLUME in volumes:
        blockers.append('memoryd_volume_already_exists')
    if listeners:
        blockers.append('memoryd_listener_port_already_in_use')
    return {
        **memory,
        'ready': not blockers,
        'reason': blockers[0] if blockers else 'ready',
        'blockers': blockers,
        'existing_services_healthy': existing.get('healthy') is True,
        'tunnel_count': existing.get('tunnel_count'),
        'target_container_count': len(owned),
        'target_volume_exists': MEMORYD_VOLUME in volumes,
        'target_listeners': listeners,
        'mutated': False,
    }


def _memoryd_adapter_image(current, receipt):
    if receipt is None:
        cas=current['manifest']['images']['cas']
        image=cas['repository']+'@'+cas['digest']
    else:
        if (not isinstance(receipt,dict) or set(receipt)!={'schema_version','image','adapter_sha256'}
                or receipt.get('schema_version')!=1
                or not isinstance(receipt.get('adapter_sha256'),str)
                or not re.fullmatch(r'[a-f0-9]{64}',receipt['adapter_sha256'])):
            raise ValueError('MemoryD adapter image receipt is invalid')
        image=receipt.get('image')
    if not isinstance(image,str) or not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}',image):
        raise ValueError('MemoryD adapter image receipt is invalid')
    return image


def _memoryd_recovery_baseline(activation_id):
    marker=_activation_marker(activation_id)
    if marker.get('status')!='activating' or marker.get('original_stopped_attested') is not True:
        raise ValueError('MemoryD recovery requires an active, attested activation')
    _verified_memoryd_restore(marker)
    owner,groups,tunnels=inspect()
    if owner!='kamal' or tunnels:
        raise ValueError('MemoryD recovery requires no active tunnel')
    for name in ('executor','schema-proxy','cas'):
        row=groups.get('kamal',{}).get(name)
        state=row.get('State',{}) if row else {}
        if (not row or state.get('Status')!='running' or state.get('Health',{}).get('Status')!='healthy'
                or (row.get('Config',{}).get('Labels') or {}).get('service')!=NAMES['kamal'][name]):
            raise ValueError('MemoryD recovery requires healthy owned core services')
    return {'authority':'kamal','healthy':True,'tunnel_count':0}


def memoryd_health(*, activation_id=None):
    baseline=_memoryd_recovery_baseline(activation_id) if activation_id else status()
    if (baseline.get('authority') != 'kamal' or not baseline.get('healthy')
            or baseline.get('tunnel_count') != (0 if activation_id else 1)):
        raise ValueError('Existing control-plane health or tunnel identity is not acceptable')
    ids = run(['docker', 'ps', '-aq']).decode().split()
    rows = json.loads(run(['docker', 'inspect', *ids])) if ids else []
    services = {}
    for row in rows:
        service = (row.get('Config', {}).get('Labels') or {}).get('service')
        if service in MEMORYD_SERVICES:
            if service in services:
                raise ValueError('Duplicate MemoryD accessory identity')
            services[service] = row
    if set(services) != MEMORYD_SERVICES:
        raise ValueError('MemoryD accessories are incomplete')

    current = json.loads(private(STORE / 'current.json'))
    image_path=STATE/'bootstrap/memoryd-adapter-image.json'
    image_receipt=json.loads(private(image_path)) if image_path.exists() or image_path.is_symlink() else None
    expected_bridge_image=_memoryd_adapter_image(current,image_receipt)
    gateway = NETWORK['gateway']
    memoryd = services['mcp-control-plane-memoryd']
    bridge = services['mcp-control-plane-memoryd-mcp']

    def assert_container(row, *, image, memory, nano_cpus):
        state = row.get('State', {})
        config = row.get('Config', {})
        host = row.get('HostConfig', {})
        if (state.get('Status') != 'running' or state.get('Health', {}).get('Status') != 'healthy'
                or config.get('Image') != image or host.get('NetworkMode') != 'host'
                or host.get('ReadonlyRootfs') is not True or not (host.get('Tmpfs') or {}).get('/tmp')
                or host.get('Memory') != memory or host.get('NanoCpus') != nano_cpus
                or host.get('PortBindings')):
            raise ValueError('MemoryD accessory runtime contract failed')
        return dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)

    memory_env = assert_container(
        memoryd, image=MEMORYD_IMAGE, memory=268_435_456, nano_cpus=500_000_000
    )
    bridge_env = assert_container(
        bridge, image=expected_bridge_image, memory=134_217_728, nano_cpus=250_000_000
    )
    if (memory_env.get('CODEX_MEMORYD_BIND') != '127.0.0.1:8787'
            or memory_env.get('CODEX_MEMORYD_DB') != '/data/memory.db'
            or bridge_env.get('CODEX_MEMORYD_URL') != 'http://127.0.0.1:8787'
            or bridge_env.get('CODEX_MEMORYD_MCP_BIND') != f'{gateway}:8090'):
        raise ValueError('MemoryD bind or scope contract failed')
    if memoryd.get('Config', {}).get('User') != '10001:10001':
        raise ValueError('MemoryD container must retain its non-root image user')
    volume_mounts = [mount for mount in memoryd.get('Mounts', [])
                     if mount.get('Name') == MEMORYD_VOLUME and mount.get('Destination') == '/data']
    bridge_mounts = [mount for mount in bridge.get('Mounts', [])
                     if mount.get('Destination') == '/opt/tunnel-kit/codex_memoryd_mcp.py'
                     and mount.get('Source','').startswith(str(STATE / 'memoryd-adapter') + '/')
                     and mount.get('RW') is False]
    if len(volume_mounts) != 1 or len(bridge_mounts) != 1:
        raise ValueError('MemoryD persistence or read-only source mount failed')
    adapter_path=Path(bridge_mounts[0]['Source'])
    if (adapter_path.name!='codex_memoryd_mcp.py'
            or not re.fullmatch(r'[a-f0-9]{64}',adapter_path.parent.name)):
        raise ValueError('MemoryD bridge source path is not content-addressed')
    adapter_root=STATE/'memoryd-adapter'
    for directory in (adapter_root,adapter_path.parent):
        directory_info=directory.lstat()
        if (directory.is_symlink() or not directory.is_dir() or directory_info.st_uid!=os.getuid()
                or stat.S_IMODE(directory_info.st_mode)!=0o700):
            raise ValueError('MemoryD adapter artifact directories must be private')
    adapter_stat=adapter_path.lstat()
    if (adapter_path.is_symlink() or not adapter_path.is_file()
            or adapter_stat.st_uid!=os.getuid() or stat.S_IMODE(adapter_stat.st_mode)!=0o600
            or file_sha256(adapter_path)!=adapter_path.parent.name):
        raise ValueError('Staged MemoryD bridge source does not match its private content address')
    adapter_receipt=json.loads(private(adapter_path.parent/'artifact.json'))
    if adapter_receipt.get('adapter_sha256')!=adapter_path.parent.name:
        raise ValueError('Staged MemoryD bridge receipt does not match its content address')
    if image_receipt and image_receipt['adapter_sha256']!=adapter_path.parent.name:
        raise ValueError('MemoryD adapter image receipt does not match its artifact')
    listeners=memoryd_listener_addresses(run(['ss','-Hln']).decode())
    if listeners != {'127.0.0.1:8787', f'{gateway}:8090'}:
        raise ValueError('MemoryD listeners do not match the private bind contract')
    return {
        'status': 'PASS',
        'memoryd_image': MEMORYD_IMAGE,
        'adapter_image': expected_bridge_image,
        'adapter_sha256': adapter_path.parent.name,
        'backend_bind': '127.0.0.1:8787',
        'mcp_bind': f'{gateway}:8090',
        'persistent_volume': MEMORYD_VOLUME,
        'existing_tunnel_count': baseline['tunnel_count'],
        'existing_control_plane_healthy': baseline['healthy'],
    }


def memoryd_pin_adapter_image():
    health=memoryd_health()
    path=STATE/'bootstrap/memoryd-adapter-image.json'
    expected={'schema_version':1,'image':health['adapter_image'],
              'adapter_sha256':health['adapter_sha256']}
    if path.exists() or path.is_symlink():
        if json.loads(private(path))!=expected:
            raise ValueError('MemoryD adapter image receipt changed')
        return {'adapter_image_pinned':True,'created':False}
    write(path,expected)
    return {'adapter_image_pinned':True,'created':True}


def memoryd_adapter_pin_check():
    path=STATE/'bootstrap/memoryd-adapter-image.json'
    if not path.exists() and not path.is_symlink():return {'pinned':False}
    receipt=json.loads(private(path))
    image=_memoryd_adapter_image(None,receipt)
    rows=json.loads(run(['docker','inspect','mcp-control-plane-memoryd-mcp']))
    if len(rows)!=1:
        raise ValueError('MemoryD adapter container identity is ambiguous')
    row=rows[0]
    artifact=STATE/'memoryd-adapter'/receipt['adapter_sha256']/'codex_memoryd_mcp.py'
    for directory in (artifact.parent.parent,artifact.parent):
        info=directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o700):
            raise ValueError('MemoryD adapter artifact directory is unsafe')
    mounts=[item for item in row.get('Mounts',[]) if item.get('Destination')=='/opt/tunnel-kit/codex_memoryd_mcp.py'
            and item.get('Source')==str(artifact) and item.get('RW') is False]
    info=artifact.lstat()
    if (row.get('Name','').lstrip('/')!='mcp-control-plane-memoryd-mcp'
            or (row.get('Config',{}).get('Labels') or {}).get('service')!='mcp-control-plane-memoryd-mcp'
            or row.get('Config',{}).get('Image')!=image or len(mounts)!=1
            or artifact.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or stat.S_IMODE(info.st_mode)!=0o600 or file_sha256(artifact)!=receipt['adapter_sha256']):
        raise ValueError('MemoryD adapter does not match its pinned image and artifact')
    return {'pinned':True}


def memoryd_executor_origin_check():
    owner,groups,_=inspect()
    row=groups.get('kamal',{}).get('executor')
    if owner!='kamal' or not row:
        raise ValueError('Managed Executor is unavailable')
    environment=dict(item.split('=',1) for item in row.get('Config',{}).get('Env',[]) if '=' in item)
    try:
        origins=json.loads(environment.get('EXECUTOR_URL_ALLOW_HTTP_ORIGINS','[]'))
    except json.JSONDecodeError:
        raise ValueError('Executor HTTP origin policy is invalid') from None
    return {'memoryd_origin_allowed':f"http://{NETWORK['gateway']}:8090" in origins}


def memoryd_wait(timeout=180, *, activation_id=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ids = run(['docker', 'ps', '-aq']).decode().split()
        rows = json.loads(run(['docker', 'inspect', *ids])) if ids else []
        services = {}
        for row in rows:
            service = (row.get('Config', {}).get('Labels') or {}).get('service')
            if service in MEMORYD_SERVICES:
                if service in services:
                    raise ValueError('Duplicate MemoryD accessory identity')
                services[service] = row
        if len(services) == len(MEMORYD_SERVICES):
            states = [row.get('State', {}) for row in services.values()]
            if any(state.get('Status') in ('exited', 'dead') for state in states):
                raise ValueError('A MemoryD accessory exited before becoming healthy')
            if all(state.get('Status') == 'running'
                   and state.get('Health', {}).get('Status') == 'healthy' for state in states):
                return memoryd_health(activation_id=activation_id) if activation_id else memoryd_health()
        time.sleep(2)
    raise ValueError('MemoryD accessories did not become healthy before the deadline')


def _memoryd_adapter_dir(adapter_sha256):
    if not isinstance(adapter_sha256,str) or not re.fullmatch(r'[a-f0-9]{64}',adapter_sha256):
        raise ValueError('MemoryD adapter checksum is invalid')
    return STATE/'memoryd-adapter'/adapter_sha256


def memoryd_adapter_prepare(data):
    if (not isinstance(data,dict) or set(data)!={'adapter_sha256','size_bytes','controller_sha'}
            or not isinstance(data.get('controller_sha'),str)
            or not re.fullmatch(r'[a-f0-9]{40}',data['controller_sha'])
            or type(data.get('size_bytes')) is not int or not 0<data['size_bytes']<=1024*1024):
        raise ValueError('MemoryD adapter staging request is invalid')
    root=STATE/'memoryd-adapter'
    if not root.exists():root.mkdir(mode=0o700)
    root_info=root.lstat()
    if root.is_symlink() or not root.is_dir() or root_info.st_uid!=os.getuid() or stat.S_IMODE(root_info.st_mode)!=0o700:
        raise ValueError('MemoryD adapter staging root must be private')
    directory=_memoryd_adapter_dir(data['adapter_sha256'])
    if not directory.exists():directory.mkdir(mode=0o700)
    info=directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('MemoryD adapter artifact directory must be private')
    path=directory/'codex_memoryd_mcp.py'
    present=False
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if (path.is_symlink() or not path.is_file() or info.st_uid!=os.getuid()
                or info.st_size!=data['size_bytes'] or file_sha256(path)!=data['adapter_sha256']):
            raise ValueError('Existing MemoryD adapter artifact does not match its immutable digest')
        if stat.S_IMODE(info.st_mode)!=0o600:path.chmod(0o600)
        present=True
    metadata={'adapter_sha256':data['adapter_sha256'],'size_bytes':data['size_bytes'],
              'controller_sha':data['controller_sha']}
    marker=directory/'artifact.json'
    if marker.exists() or marker.is_symlink():
        existing=json.loads(private(marker))
        if (existing.get('adapter_sha256')!=data['adapter_sha256']
                or existing.get('size_bytes')!=data['size_bytes']):
            raise ValueError('MemoryD adapter receipt does not match the immutable artifact')
        if existing.get('controller_sha')!=data['controller_sha']:
            write(marker,metadata)
    else:
        write(marker,metadata)
    return {'directory':str(directory),'path':str(path),'present':present,
            'needs_upload':not present,'adapter_sha256':data['adapter_sha256']}


def memoryd_adapter_finalize(data):
    if (not isinstance(data,dict) or set(data)!={'adapter_sha256','size_bytes','controller_sha'}
            or type(data.get('size_bytes')) is not int
            or not isinstance(data.get('controller_sha'),str)
            or not re.fullmatch(r'[a-f0-9]{40}',data['controller_sha'])):
        raise ValueError('MemoryD adapter finalization request is invalid')
    directory=_memoryd_adapter_dir(data['adapter_sha256'])
    path=directory/'codex_memoryd_mcp.py'
    info=path.lstat()
    if (path.is_symlink() or not path.is_file() or info.st_uid!=os.getuid()
            or info.st_size!=data['size_bytes'] or file_sha256(path)!=data['adapter_sha256']):
        raise ValueError('Staged MemoryD adapter failed its SHA-256 check')
    path.chmod(0o600)
    marker=directory/'artifact.json'
    metadata={'adapter_sha256':data['adapter_sha256'],'size_bytes':data['size_bytes'],
              'controller_sha':data['controller_sha']}
    if json.loads(private(marker))!=metadata:
        raise ValueError('MemoryD adapter receipt does not match its staged file')
    return {'staged':True,'adapter_sha256':data['adapter_sha256'],'size_bytes':data['size_bytes']}


def memoryd_inventory():
    """Inspect labeled accessories without requiring a healthy control plane."""
    ids = run(['docker', 'ps', '-aq']).decode().split()
    rows = json.loads(run(['docker', 'inspect', *ids])) if ids else []
    services = {}
    for row in rows:
        service = (row.get('Config', {}).get('Labels') or {}).get('service')
        name = (row.get('Name') or '').lstrip('/')
        if service in MEMORYD_SERVICES or name in MEMORYD_SERVICES:
            if service not in MEMORYD_SERVICES or name != service:
                raise ValueError('MemoryD accessory identity mismatch')
            if service in services:
                raise ValueError('Duplicate MemoryD accessory identity')
            state = row.get('State', {})
            services[service] = {'state': state.get('Status'),
                                 'health': state.get('Health', {}).get('Status')}
    volumes = set(run(['docker', 'volume', 'ls', '--format', '{{.Name}}']).decode().split())
    marker = STATE / 'bootstrap/memoryd-integration.json'
    if not services:
        state = 'VOLUME_ONLY' if MEMORYD_VOLUME in volumes else 'ABSENT'
    elif set(services) != MEMORYD_SERVICES:
        state = 'PARTIAL'
    elif all(item['state'] in ('exited', 'created') for item in services.values()):
        state = 'STOPPED'
    else:
        state = 'UNVERIFIED'
    return {'status': state, 'services': services,
            'volume_exists': MEMORYD_VOLUME in volumes,
            'app_registered': marker.exists() and not marker.is_symlink()}


def memoryd_status():
    result = memoryd_inventory()
    services = result['services']
    if result['status'] == 'UNVERIFIED':
        if all(item['state'] == 'running' and item['health'] == 'healthy' for item in services.values()):
            health=memoryd_health()
            result['status'] = 'HEALTHY'
            if health.get('adapter_sha256'):
                result['adapter_sha256'] = health['adapter_sha256']
        else:
            result['status'] = 'UNHEALTHY'
    return result


def memoryd_capture_preflight():
    """Prove absence or a healthy, fully registered MemoryD before capture."""
    bootstrap = STATE / 'bootstrap'
    evidence = {}
    pending = bootstrap / 'memoryd-registration-pending.json'
    if os.path.lexists(pending):
        raise ValueError('MemoryD registration is pending; capture refused')
    for pattern in ('memoryd-transfer*.json', 'memoryd-identity-*.json'):
        for path in bootstrap.glob(pattern):
            raw = private(path)
            receipt = json.loads(raw)
            if not isinstance(receipt, dict) or receipt.get('status') != 'complete':
                raise ValueError('MemoryD work is incomplete; capture refused')
            evidence['bootstrap/' + path.name] = hashlib.sha256(raw).hexdigest()
    inventory = memoryd_status()
    marker = bootstrap / 'memoryd-integration.json'
    adapter_pin = bootstrap / 'memoryd-adapter-image.json'
    if inventory.get('status') == 'ABSENT':
        if (inventory.get('services') or inventory.get('volume_exists')
                or inventory.get('app_registered') or os.path.lexists(marker)
                or os.path.lexists(adapter_pin)
                or os.path.lexists(STATE / 'memoryd-transfer') or evidence):
            raise ValueError('MemoryD absence is ambiguous; capture refused')
        identity(NAMES['kamal']['executor'], exclude_memoryd=True, require_memoryd_absent=True)
        return {'status': 'absent'}
    if (inventory.get('status') != 'HEALTHY' or not inventory.get('volume_exists')
            or not inventory.get('app_registered') or not os.path.lexists(marker)):
        raise ValueError('MemoryD is not fully healthy and registered; capture refused')
    marker_raw = private(marker)
    if not _valid_memoryd_receipt(json.loads(marker_raw)):
        raise ValueError('MemoryD registration receipt is invalid')
    evidence['bootstrap/' + marker.name] = hashlib.sha256(marker_raw).hexdigest()
    if os.path.lexists(adapter_pin):
        evidence['bootstrap/' + adapter_pin.name] = hashlib.sha256(private(adapter_pin)).hexdigest()
    transfer_root = STATE / 'memoryd-transfer'
    if os.path.lexists(transfer_root):
        info = transfer_root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('MemoryD transfer state is unsafe')
        for directory in transfer_root.iterdir():
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError('MemoryD transfer state is unsafe')
            raw = private(directory / 'transfer.json')
            manifest = json.loads(raw)
            transfer_id = manifest.get('transfer_manifest_sha256') if isinstance(manifest, dict) else None
            if (not isinstance(transfer_id, str) or not re.fullmatch(r'[a-f0-9]{64}', transfer_id)
                    or directory.name != transfer_id[:16]):
                raise ValueError('MemoryD transfer state is invalid')
            evidence['memoryd-transfer/' + directory.name] = hashlib.sha256(raw).hexdigest()
            receipt = json.loads(private(_memoryd_receipt_path(transfer_id)))
            if (not isinstance(receipt, dict) or receipt.get('status') != 'complete'
                    or receipt.get('transfer_manifest_sha256') != transfer_id):
                raise ValueError('MemoryD transfer is incomplete; capture refused')
    identity(NAMES['kamal']['executor'], exclude_memoryd=True, require_memoryd_active=True)
    health = memoryd_health()
    if (health.get('status') != 'PASS' or health.get('persistent_volume') != MEMORYD_VOLUME
            or health.get('adapter_sha256') != inventory.get('adapter_sha256')):
        raise ValueError('MemoryD health identity changed; capture refused')
    volume_users = run(['docker', 'ps', '--filter', 'volume=' + MEMORYD_VOLUME,
                        '--format', '{{.Names}}']).decode().split()
    if volume_users != ['mcp-control-plane-memoryd']:
        raise ValueError('MemoryD volume has unexpected users; capture refused')
    fingerprint = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return {'status': 'healthy', 'health': health, 'state_fingerprint': fingerprint}


def _validate_memoryd_capture(root):
    """Inspect only metadata and counts from a private, self-contained snapshot."""
    root = Path(root)
    adapter = root / 'adapter'
    for directory in (root, adapter):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('MemoryD capture directory is unsafe')
    if ({item.name for item in root.iterdir()} != {'backup.db', 'backup.db.manifest.json', 'adapter'}
            or {item.name for item in adapter.iterdir()} != {'codex_memoryd_mcp.py', 'artifact.json'}):
        raise ValueError('MemoryD capture contains unexpected files')
    database = root / 'backup.db'
    manifest_path = root / 'backup.db.manifest.json'
    adapter_path = adapter / 'codex_memoryd_mcp.py'
    for path, limit in ((database, MEMORYD_CAPTURE_MAX_BYTES), (manifest_path, 1024 * 1024),
                        (adapter_path, 1024 * 1024), (adapter / 'artifact.json', 1024 * 1024)):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= limit):
            raise ValueError('MemoryD capture file is unsafe')
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('MemoryD capture metadata has duplicate keys')
            value[key] = item
        return value
    try:
        manifest = json.loads(private(manifest_path), object_pairs_hook=no_duplicates)
        artifact = json.loads(private(adapter / 'artifact.json'), object_pairs_hook=no_duplicates)
        if not isinstance(manifest, dict) or not isinstance(artifact, dict):
            raise ValueError('MemoryD capture metadata is invalid')
        digest = file_sha256(database)
        manifest_keys = {'manifest_version', 'tool_version', 'created_at', 'database_file', 'sha256',
                         'size_bytes', 'schema_version', 'expected_schema_version', 'tables'}
        if (set(manifest) != manifest_keys or type(manifest.get('manifest_version')) is not int
                or manifest['manifest_version'] != 1 or manifest.get('tool_version') != '0.1.0'
                or manifest.get('database_file') != 'backup.db'
                or type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 13
                or type(manifest.get('expected_schema_version')) is not int or manifest['expected_schema_version'] != 13
                or type(manifest.get('size_bytes')) is not int
                or manifest.get('size_bytes') != database.stat().st_size
                or manifest.get('sha256') != 'sha256:' + digest):
            raise ValueError('MemoryD backup manifest does not match the database')
        captured = manifest.get('created_at')
        if not isinstance(captured, str) or len(captured) > 64:
            raise ValueError('MemoryD backup timestamp is invalid')
        try:
            parsed = datetime.fromisoformat(captured.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            raise ValueError('MemoryD backup timestamp is invalid') from None
        if parsed.utcoffset() is None:
            raise ValueError('MemoryD backup timestamp is invalid')
        tables = manifest.get('tables')
        if (not isinstance(tables, list) or len(tables) != len(MEMORYD_CAPTURE_TABLES)
                or any(not isinstance(item, dict) or set(item) != {'table', 'rows'}
                       or type(item['rows']) is not int or item['rows'] < 0 for item in tables)):
            raise ValueError('MemoryD backup table counts are invalid')
        counts = {item['table']: item['rows'] for item in tables}
        if set(counts) != set(MEMORYD_CAPTURE_TABLES):
            raise ValueError('MemoryD backup table set is invalid')
        adapter_digest = file_sha256(adapter_path)
        if (set(artifact) != {'adapter_sha256', 'size_bytes', 'controller_sha'}
                or artifact.get('adapter_sha256') != adapter_digest
                or type(artifact.get('size_bytes')) is not int
                or artifact.get('size_bytes') != adapter_path.stat().st_size
                or not isinstance(artifact.get('controller_sha'), str)
                or not re.fullmatch(r'[a-f0-9]{40}', artifact['controller_sha'])):
            raise ValueError('MemoryD adapter artifact does not match its receipt')
        conn = sqlite3.connect(database.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            if conn.execute('PRAGMA integrity_check(1)').fetchone() != ('ok',):
                raise ValueError('MemoryD database integrity failed')
            schema = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchall()
            instance = conn.execute('SELECT singleton_key, instance_id FROM instance_metadata').fetchall()
            if (schema != [('13',)] or len(instance) != 1 or instance[0][0] != 'default'
                    or not isinstance(instance[0][1], str)
                    or not re.fullmatch(r'cmi_[a-f0-9]{32}', instance[0][1])):
                raise ValueError('MemoryD database identity or schema is invalid')
            for table in MEMORYD_CAPTURE_TABLES:
                if conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0] != counts[table]:
                    raise ValueError('MemoryD backup table counts do not match')
            # Some release tables have only one scope column, while others carry
            # neither. Check each column that exists without printing any rows.
            tables_in_db = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            for (table,) in tables_in_db:
                quoted = '"' + table.replace('"', '""') + '"'
                columns = {column[1].lower() for column in conn.execute(f'PRAGMA table_info({quoted})')}
                checks = []
                values = []
                if 'profile_id' in columns:
                    checks.append('profile_id IS NOT ?')
                    values.append('personal')
                if 'workspace_id' in columns:
                    checks.append('workspace_id IS NOT ?')
                    values.append('dakota-codex-only')
                if table == 'profiles' and 'id' in columns:
                    checks.append('id IS NOT ?')
                    values.append('personal')
                if table == 'workspaces' and 'id' in columns:
                    checks.append('id IS NOT ?')
                    values.append('dakota-codex-only')
                if checks and conn.execute(f'SELECT 1 FROM {quoted} WHERE ' + ' OR '.join(checks)
                                           + ' LIMIT 1', values).fetchone():
                    raise ValueError('MemoryD backup contains data outside its approved scope')
            total, active, archived, invalid = conn.execute('''
                SELECT count(*), coalesce(sum(archived=0), 0), coalesce(sum(archived=1), 0),
                       coalesce(sum(profile_id IS NOT 'personal' OR workspace_id IS NOT 'dakota-codex-only'
                                    OR archived IS NULL OR archived NOT IN (0, 1)), 0)
                FROM memory_records
            ''').fetchone()
            if invalid or active + archived != total:
                raise ValueError('MemoryD backup contains records outside its approved scope')
        finally:
            conn.close()
        if file_sha256(database) != digest:
            raise ValueError('MemoryD backup changed during validation')
    except (OSError, sqlite3.Error, TypeError, AttributeError, json.JSONDecodeError):
        raise ValueError('MemoryD capture validation failed; details withheld') from None
    return {'backup_sha256': digest, 'backup_manifest_sha256': file_sha256(manifest_path),
            'backup_size_bytes': database.stat().st_size, 'adapter_sha256': adapter_digest,
            'source_instance_id': instance[0][1], 'record_count': total,
            'active_record_count': active, 'archived_record_count': archived,
            'profile': 'personal', 'workspace': 'dakota-codex-only', 'captured_at': captured}


def _memoryd_capture_cli(stage, args):
    """Run the release CLI only on an isolated snapshot, never the live DB."""
    command = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,mode=1777',
               '--user', '10001:10001', '--memory', '256m', '--memory-swap', '256m',
               '--cpus', '0.5', '--mount', 'type=volume,source=codex-memoryd-data,target=/data',
               '--env', 'CODEX_MEMORYD_HOME=' + stage, '--entrypoint', '/bin/sh', MEMORYD_IMAGE,
               '-c', 'source=$1; shift; umask 077; exec /usr/local/bin/codex-memoryd --local --db "$source" "$@"',
               'memoryd-capture', stage + '/source.db', *args]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
    if result.returncode:
        raise ValueError('MemoryD recovery backup operation failed; output withheld')
    try:
        value = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError('MemoryD recovery backup returned invalid JSON') from None
    if not isinstance(value, dict):
        raise ValueError('MemoryD recovery backup returned invalid JSON')
    return value


def _memoryd_capture_readonly_snapshot(image, spool):
    """Back up the live SQLite store with a read-only volume mount."""
    command = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
               '--user', '10001:10001', '--memory', '256m', '--memory-swap', '256m',
               '--cpus', '0.5', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777',
               '--mount', 'type=volume,source=codex-memoryd-data,target=/data,readonly',
               '--entrypoint', 'python3', image, '-c', MEMORYD_READONLY_SNAPSHOT_CODE,
               '/data/memory.db', str(MEMORYD_CAPTURE_MAX_BYTES)]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=spool,
                            stderr=subprocess.DEVNULL, timeout=180)
    if result.returncode or not 0 < spool.tell() <= MEMORYD_CAPTURE_MAX_BYTES:
        raise ValueError('Read-only MemoryD snapshot failed; output withheld')
    spool.flush()
    spool.seek(0)


def _memoryd_capture_stage_input(stage, spool):
    command = ['docker', 'exec', '-i', '--user', '10001:10001', 'mcp-control-plane-memoryd',
               'sh', '-c', 'set -C; umask 077; cat > "$1"', 'memoryd-capture', stage + '/source.db']
    result = subprocess.run(command, stdin=spool, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=180)
    if result.returncode:
        raise ValueError('MemoryD snapshot staging failed; output withheld')


def _memoryd_capture_copy(source, target, limit):
    """Stream a single container file through a private, bounded tar spool."""
    with tempfile.TemporaryFile(dir=target.parent) as spool:
        result = subprocess.run(['docker', 'cp', 'mcp-control-plane-memoryd:' + source, '-'],
                                stdin=subprocess.DEVNULL, stdout=spool, stderr=subprocess.DEVNULL,
                                timeout=600)
        if result.returncode or spool.tell() > limit + 1024 * 1024:
            raise ValueError('MemoryD recovery artifact copy failed')
        spool.seek(0)
        with tarfile.open(fileobj=spool, mode='r:') as archive:
            members = archive.getmembers()
            if (len(members) != 1 or not members[0].isfile()
                    or members[0].name != target.name or not 0 < members[0].size <= limit):
                raise ValueError('MemoryD recovery artifact archive is invalid')
            with archive.extractfile(members[0]) as data, target.open('xb') as output:
                shutil.copyfileobj(data, output, 1024 * 1024)
            target.chmod(0o600)


def _memoryd_snapshot_files(directory, health):
    """Create, separately verify, and copy one private MemoryD snapshot."""
    memory = memoryd_resource_gate(Path('/proc/meminfo').read_text())
    if memory['mem_available_kb'] < MEMORYD_CAPTURE_MIN_AVAILABLE_KB:
        raise ValueError('MemoryD capture requires at least 512 MiB available memory')
    container = 'mcp-control-plane-memoryd'
    command = ['docker', 'exec', '--user', '10001:10001', container]
    probe = ('set -eu; test -f /data/memory.db; test ! -L /data/memory.db; '
             'test ! -L /data/memory.db-wal; test ! -L /data/memory.db-shm; '
             'stat -c %s /data/memory.db; '
             'if test -e /data/memory.db-wal; then test ! -L /data/memory.db-wal; '
             'stat -c %s /data/memory.db-wal; else echo 0; fi')
    try:
        sizes = [int(value) for value in run([*command, 'sh', '-c', probe]).decode().split()]
        available = int(run([*command, 'df', '-Pk', '/data']).decode().splitlines()[-1].split()[3]) * 1024
    except (ValueError, IndexError, UnicodeDecodeError):
        raise ValueError('MemoryD backup capacity cannot be established') from None
    if (len(sizes) != 2 or sizes[0] <= 0 or sizes[1] < 0
            or sum(sizes) > MEMORYD_CAPTURE_MAX_BYTES
            or available < 3 * sum(sizes) + 16 * 1024 * 1024):
        raise ValueError('MemoryD backup exceeds the safe capacity bound')
    source_identity = run([*command, 'stat', '-c', '%d:%i', '--', '/data/memory.db']).decode().strip()
    if not re.fullmatch(r'[0-9]+:[0-9]+', source_identity):
        raise ValueError('MemoryD source identity is unavailable')
    stage = '/data/.memoryd-recovery-' + uuid.uuid4().hex
    scratch = stage + '/scratch'
    backup_path = stage + '/backup.db'
    manifest_path = backup_path + '.manifest.json'
    def checksum(path):
        value = run([*command, 'sha256sum', '--', path]).decode().split()[0]
        if not re.fullmatch(r'[a-f0-9]{64}', value):
            raise ValueError('MemoryD backup digest is invalid')
        return value
    with tempfile.TemporaryFile(dir=directory.parent) as spool:
        _memoryd_capture_readonly_snapshot(health['adapter_image'], spool)
        spool.seek(0, os.SEEK_END)
        if not 0 < spool.tell() <= MEMORYD_CAPTURE_MAX_BYTES:
            raise ValueError('Read-only MemoryD snapshot exceeds the size bound')
        spool.seek(0)
        source_hash = hashlib.file_digest(spool, 'sha256').hexdigest()
        spool.seek(0)
        if run([*command, 'stat', '-c', '%d:%i', '--', '/data/memory.db']).decode().strip() != source_identity:
            raise ValueError('MemoryD source changed during backup')
        run([*command, 'mkdir', '-m', '0700', stage])
        _memoryd_capture_stage_input(stage, spool)
    if checksum(stage + '/source.db') != source_hash:
        raise ValueError('MemoryD isolated source snapshot changed during staging')
    created = _memoryd_capture_cli(stage, ['backup', 'create', '--dest', backup_path])
    if (created.get('ok') is not True or created.get('database_path') != backup_path
            or created.get('manifest_path') != manifest_path or not isinstance(created.get('manifest'), dict)):
        raise ValueError('MemoryD backup creation returned an invalid receipt')
    if run([*command, 'stat', '-c', '%d:%i', '--', '/data/memory.db']).decode().strip() != source_identity:
        raise ValueError('MemoryD source changed during backup')
    if checksum(stage + '/source.db') != source_hash:
        raise ValueError('MemoryD release CLI changed its isolated source snapshot')
    try:
        sizes = [int(value) for value in run([*command, 'stat', '-c', '%s', '--', backup_path,
                                              manifest_path]).decode().split()]
        available = int(run([*command, 'df', '-Pk', '/data']).decode().splitlines()[-1].split()[3]) * 1024
    except (ValueError, IndexError, UnicodeDecodeError):
        raise ValueError('MemoryD backup capacity cannot be established') from None
    if (len(sizes) != 2 or not 0 < sizes[0] <= MEMORYD_CAPTURE_MAX_BYTES
            or not 0 < sizes[1] <= 1024 * 1024 or sizes[0] != created['manifest'].get('size_bytes')
            or available < sum(sizes) + 16 * 1024 * 1024):
        raise ValueError('MemoryD backup exceeds the safe capacity bound')
    run([*command, 'mkdir', '-m', '0700', scratch])
    for name in ('backup.db', 'backup.db.manifest.json'):
        run([*command, 'cp', '--', stage + '/' + name, scratch + '/' + name])
    original_hash = checksum(backup_path)
    manifest_hash = checksum(manifest_path)
    if (created['manifest'].get('sha256') != 'sha256:' + original_hash
            or checksum(scratch + '/backup.db') != original_hash
            or checksum(scratch + '/backup.db.manifest.json') != manifest_hash):
        raise ValueError('MemoryD backup copy does not match its manifest')
    verified = _memoryd_capture_cli(stage, ['backup', 'verify', '--path', scratch + '/backup.db'])
    if (verified.get('ok') is not True or verified.get('digest_matches') is not True
            or verified.get('integrity_ok') is not True or verified.get('schema_matches') is not True
            or verified.get('manifest') != created['manifest']
            or checksum(stage + '/source.db') != source_hash
            or checksum(backup_path) != original_hash or checksum(manifest_path) != manifest_hash
            or checksum(scratch + '/backup.db') != original_hash
            or checksum(scratch + '/backup.db.manifest.json') != manifest_hash):
        raise ValueError('MemoryD backup verification changed or rejected its files')
    directory.mkdir(mode=0o700)
    _memoryd_capture_copy(backup_path, directory / 'backup.db', MEMORYD_CAPTURE_MAX_BYTES)
    _memoryd_capture_copy(manifest_path, directory / 'backup.db.manifest.json', 1024 * 1024)
    if (file_sha256(directory / 'backup.db') != original_hash
            or file_sha256(directory / 'backup.db.manifest.json') != manifest_hash):
        raise ValueError('Transported MemoryD snapshot digest mismatch')
    adapter_dir = directory / 'adapter'
    adapter_dir.mkdir(mode=0o700)
    source_dir = _memoryd_adapter_dir(health['adapter_sha256'])
    for name in ('codex_memoryd_mcp.py', 'artifact.json'):
        data = private(source_dir / name)
        if len(data) > 1024 * 1024:
            raise ValueError('MemoryD adapter artifact is too large')
        with (adapter_dir / name).open('xb') as target:
            target.write(data)
        (adapter_dir / name).chmod(0o600)
    if run([*command, 'stat', '-c', '%d:%i', '--', '/data/memory.db']).decode().strip() != source_identity:
        raise ValueError('MemoryD source changed during backup')


def capture_memoryd(directory, *, expected=None):
    before = memoryd_capture_preflight()
    if expected is not None and expected != before:
        raise ValueError('MemoryD state changed before capture')
    if before['status'] == 'absent':
        if memoryd_capture_preflight() != before:
            raise ValueError('MemoryD state changed during capture')
        return {'status': 'absent'}
    health = before['health']
    image = health.get('adapter_image')
    if (health.get('memoryd_image') != MEMORYD_IMAGE or not isinstance(image, str)
            or not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}', image)):
        raise ValueError('MemoryD capture image identity is invalid')
    _memoryd_snapshot_files(directory, health)
    facts = _validate_memoryd_capture(directory)
    if facts['adapter_sha256'] != health.get('adapter_sha256') or memoryd_capture_preflight() != before:
        raise ValueError('MemoryD identity changed during capture')
    return {'status': 'captured', 'backend_image': MEMORYD_IMAGE, 'adapter_image': image, **facts}


def memoryd_transfer_preflight():
    existing = status()
    memory = memoryd_resource_gate(Path('/proc/meminfo').read_text())
    provider = memoryd_status()
    blockers = []
    if existing.get('authority') != 'kamal' or existing.get('healthy') is not True:
        blockers.append('existing_control_plane_unhealthy_or_unowned')
    if existing.get('tunnel_count') != 1:
        blockers.append('expected_exactly_one_existing_tunnel')
    if not memory.get('ready'):
        blockers.append(memory['reason'])
    if provider.get('status') != 'HEALTHY':
        blockers.append('memoryd_accessories_not_healthy')
    return {**memory, 'ready': not blockers, 'reason': blockers[0] if blockers else 'ready',
            'blockers': blockers, 'existing_services_healthy': existing.get('healthy') is True,
            'tunnel_count': existing.get('tunnel_count'), 'memoryd_status': provider.get('status'),
            'mutated': False}


def _validate_memoryd_transfer_manifest(data):
    expected = {'schema_version','transfer_manifest_sha256','source_database_sha256',
                'source_record_count','source_database_record_count','source_cutoff_at',
                'include_archived',
                'source_instance_id','source_profile','source_workspace',
                'target_profile','target_workspace','bundles'}
    if not isinstance(data,dict) or set(data)!=expected or data.get('schema_version')!=1:
        raise ValueError('MemoryD transfer manifest shape is invalid')
    digest=data.get('transfer_manifest_sha256')
    source_db=data.get('source_database_sha256')
    if (not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest)
            or not isinstance(source_db,str) or not re.fullmatch(r'[a-f0-9]{64}',source_db)):
        raise ValueError('MemoryD transfer digest is invalid')
    source_instance=data.get('source_instance_id')
    if not isinstance(source_instance,str) or not re.fullmatch(r'cmi_[a-f0-9]{32}',source_instance):
        raise ValueError('MemoryD source instance identity is invalid')
    if (data.get('source_profile')!='personal' or data.get('target_profile')!='personal'
            or data.get('source_workspace')!='dakota-codex-only'
            or data.get('target_workspace')!='dakota-codex-only'):
        raise ValueError('MemoryD transfer scope is invalid')
    record_count=data.get('source_record_count')
    bundles=data.get('bundles')
    database_count=data.get('source_database_record_count')
    if (type(record_count) is not int or record_count<1
            or type(database_count) is not int or database_count<record_count
            or data.get('include_archived') is not False
            or not isinstance(data.get('source_cutoff_at'),str) or not data['source_cutoff_at']
            or not isinstance(bundles,list) or not bundles):
        raise ValueError('MemoryD transfer bundle selection is empty')
    names=set();roots=0;total=0
    for bundle in bundles:
        if not isinstance(bundle,dict) or set(bundle)!={'path','sha256','size_bytes','bundle_id','manifest_digest','root_count'}:
            raise ValueError('MemoryD bundle descriptor shape is invalid')
        name=bundle['path']
        if (not isinstance(name,str) or Path(name).name!=name
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.bundle',name)
                or name in names):
            raise ValueError('MemoryD bundle filename is invalid')
        names.add(name)
        if (not isinstance(bundle['sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',bundle['sha256'])
                or not isinstance(bundle['manifest_digest'],str)
                or not re.fullmatch(r'sha256:[a-f0-9]{64}',bundle['manifest_digest'])):
            raise ValueError('MemoryD bundle digest is invalid')
        size=bundle['size_bytes'];root_count=bundle['root_count']
        if type(size) is not int or not 0<size<=24*1024*1024 or type(root_count) is not int or not 0<root_count<=5000:
            raise ValueError('MemoryD bundle exceeds the released size or root limit')
        if not isinstance(bundle['bundle_id'],str) or not bundle['bundle_id'].startswith('sha256:'):
            raise ValueError('MemoryD bundle identity is invalid')
        total+=size;roots+=root_count
    if total>128*1024*1024 or roots!=record_count:
        raise ValueError('MemoryD bundle set does not exactly cover the source record count')
    return data


def memoryd_transfer_prepare(data):
    manifest=_validate_memoryd_transfer_manifest(data)
    transfer_root=STATE/'memoryd-transfer'
    if not transfer_root.exists():
        transfer_root.mkdir(mode=0o700,parents=True)
    root_info=transfer_root.lstat()
    if transfer_root.is_symlink() or not transfer_root.is_dir() or root_info.st_uid!=os.getuid() or stat.S_IMODE(root_info.st_mode)!=0o700:
        raise ValueError('MemoryD transfer directory must be private')
    directory=transfer_root/manifest['transfer_manifest_sha256'][:16]
    if not directory.exists():
        directory.mkdir(mode=0o700)
    info=directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('MemoryD transfer directory identity is invalid')
    manifest_path=directory/'transfer.json'
    mutated=False
    if manifest_path.exists() or manifest_path.is_symlink():
        if json.loads(private(manifest_path))!=manifest:
            raise ValueError('MemoryD transfer directory already belongs to another source manifest')
    else:
        write(manifest_path,manifest);mutated=True
    expected_names={bundle['path'] for bundle in manifest['bundles']}|{'transfer.json'}
    actual_names={item.name for item in directory.iterdir()}
    if actual_names-expected_names:
        raise ValueError('MemoryD transfer directory contains unrecognized files')
    present=[];missing=[]
    for bundle in manifest['bundles']:
        path=directory/bundle['path']
        if not path.exists() and not path.is_symlink():
            missing.append(bundle['path']);continue
        item=path.lstat()
        if path.is_symlink() or not path.is_file() or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600:
            raise ValueError('VM bundle file must be an owner-only regular file')
        if item.st_size!=bundle['size_bytes'] or file_sha256(path)!=bundle['sha256']:
            raise ValueError('VM bundle file hash mismatch')
        present.append(bundle['path'])
    return {'directory':str(directory),'present_bundles':present,'missing_bundles':missing,'mutated':mutated}


def _memoryd_cli(args, *, timeout=300):
    command=['docker','exec','-i','mcp-control-plane-memoryd','/usr/local/bin/codex-memoryd',*args]
    result=subprocess.run(command,input=b'',capture_output=True,timeout=timeout)
    if result.returncode:
        label=' '.join(str(item) for item in args[:2])
        raise ValueError('MemoryD CLI '+label+' failed; command output withheld')
    return result.stdout


def _memoryd_cli_json(args, *, timeout=300):
    try:
        return json.loads(_memoryd_cli(args,timeout=timeout))
    except (json.JSONDecodeError,UnicodeDecodeError):
        label=' '.join(str(item) for item in args[:2])
        raise ValueError('MemoryD CLI '+label+' returned invalid JSON') from None


def _memoryd_run_step(label, args, *, timeout=180, stdin=None):
    if label not in {'target backup permissions', 'bundle copy', 'bundle permissions', 'bundle cleanup'}:
        raise ValueError('MemoryD import step label is invalid')
    try:
        result=subprocess.run(args,stdin=stdin,capture_output=True,timeout=timeout)
    except Exception:
        raise ValueError('MemoryD import step '+label+' failed (docker_unavailable)') from None
    if result.returncode:
        diagnostic=result.stderr.decode(errors='replace').lower()
        categories=(
            ('no space left on device','destination_capacity'),
            ('read-only file system','read_only_destination'),
            ('permission denied','permission_denied'),
            ('no such file or directory','path_not_found'),
            ('not a directory','invalid_destination'),
            ('no such container','container_not_found'),
            ('is not running','container_not_running'),
        )
        reason=next((category for needle,category in categories if needle in diagnostic),'docker_operation_failed')
        raise ValueError('MemoryD import step '+label+' failed ('+reason+')')
    return result.stdout


def _memoryd_stage_bundle(path, container_path, bundle):
    info=path.lstat()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (path.is_symlink() or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid!=os.getuid() or stat.S_IMODE(opened.st_mode)!=0o600
                or (info.st_dev,info.st_ino)!=(opened.st_dev,opened.st_ino)
                or opened.st_size!=bundle['size_bytes']
                or hashlib.file_digest(stream,'sha256').hexdigest()!=bundle['sha256']):
            raise ValueError('MemoryD bundle transfer file failed its host-side hash check')
        stream.seek(0)
        _memoryd_run_step('bundle copy',
            ['docker','exec','-i','--user','10001:10001','mcp-control-plane-memoryd',
             'sh','-c','umask 077; set -C; cat > "$1"','sh',container_path],
            timeout=120,stdin=stream)


def _memoryd_record_count():
    output=_memoryd_cli(['doctor','--local','--format','summary']).decode(errors='replace')
    match=re.search(r'(?m)^storage: [^\n]*\brecords=(\d+)\b',output)
    if not match:
        raise ValueError('MemoryD doctor record count is unavailable')
    return int(match.group(1))


def _memoryd_tmp_available():
    output=run(['docker','exec','mcp-control-plane-memoryd','df','-Pk','/tmp'],timeout=15).decode()
    lines=output.splitlines()
    fields=lines[-1].split() if lines else []
    if len(fields)<6 or fields[-1]!='/tmp' or not fields[-3].isdigit():
        raise ValueError('MemoryD temporary storage capacity is unavailable')
    return int(fields[-3])*1024


def _memoryd_process_start_ticks(pid):
    raw=(Path('/proc')/str(pid)/'stat').read_text()
    fields=raw.rsplit(')',1)[1].split()
    return int(fields[19])


def _memoryd_staging_owner():
    return {'pid':os.getpid(),'start_ticks':_memoryd_process_start_ticks(os.getpid()),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def _memoryd_staging_owner_alive(owner):
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=owner['boot_id']:
        return False
    try:
        return _memoryd_process_start_ticks(owner['pid'])==owner['start_ticks']
    except FileNotFoundError:
        return False
    except (OSError,ValueError,IndexError):
        raise ValueError('MemoryD staging owner cannot be verified') from None


def _memoryd_staging_in_use(path):
    target=path.encode()
    if target in run(['docker','top','mcp-control-plane-memoryd','-eo','pid,args'],timeout=15):
        return True
    for process in Path('/proc').iterdir():
        if not process.name.isdigit() or int(process.name)==os.getpid():continue
        try:
            if process.stat().st_uid==os.getuid() and target in (process/'cmdline').read_bytes():
                return True
        except FileNotFoundError:
            continue
        except OSError:
            raise ValueError('MemoryD staging use cannot be verified') from None
    return False


def _memoryd_reconcile_staging(receipt,receipt_path,transfer_id):
    owner=receipt.get('staging')
    if owner is None:return
    if (not isinstance(owner,dict) or set(owner)!={'path','pid','start_ticks','boot_id'}
            or type(owner.get('pid')) is not int or owner['pid']<1
            or type(owner.get('start_ticks')) is not int or owner['start_ticks']<1
            or not isinstance(owner.get('boot_id'),str)
            or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',owner['boot_id'])
            or not isinstance(owner.get('path'),str)
            or not re.fullmatch(r'/tmp/memoryd-transfer-'+transfer_id[:12]+r'-[a-f0-9]{32}-[0-9]{2,6}-(?:apply|replay)\.bundle',owner['path'])):
        raise ValueError('MemoryD staging receipt is invalid')
    if _memoryd_staging_owner_alive(owner) or _memoryd_staging_in_use(owner['path']):
        raise ValueError('MemoryD staging is still active; retry refused')
    _memoryd_run_step('bundle cleanup',
        ['docker','exec','--user','10001:10001','mcp-control-plane-memoryd','rm','-f',owner['path']],timeout=60)
    receipt.pop('staging');write(receipt_path,receipt)


def _validate_memoryd_bundle_report(report, manifest, bundle):
    if (not isinstance(report,dict) or report.get('integrity_status')!='verified'
            or report.get('bundle_id')!=bundle['bundle_id']
            or report.get('manifest_digest')!=bundle['manifest_digest']
            or report.get('source_instance_id')!=manifest['source_instance_id']
            or report.get('source_scope',{}).get('profile')!='personal'
            or report.get('source_scope',{}).get('workspace')!='dakota-codex-only'):
        raise ValueError('MemoryD bundle integrity, provenance, or scope check failed')


def _memoryd_receipt_path(transfer_id):
    path=STATE/'bootstrap'/f'memoryd-transfer-{transfer_id}.json'
    legacy=STATE/'bootstrap/memoryd-transfer.json'
    if not path.exists() and not path.is_symlink() and (legacy.exists() or legacy.is_symlink()):
        previous=json.loads(private(legacy))
        if previous.get('transfer_manifest_sha256')==transfer_id:
            return legacy
    return path


def memoryd_import_bundles(data):
    if not isinstance(data,dict) or set(data)!={'transfer_manifest_sha256'}:
        raise ValueError('MemoryD import request shape is invalid')
    transfer_id=data['transfer_manifest_sha256']
    if not isinstance(transfer_id,str) or not re.fullmatch(r'[a-f0-9]{64}',transfer_id):
        raise ValueError('MemoryD transfer identity is invalid')
    gate=memoryd_transfer_preflight()
    if not gate['ready']:
        raise ValueError('MemoryD transfer preflight blocked: '+gate['reason'])
    directory=STATE/'memoryd-transfer'/transfer_id[:16]
    manifest=json.loads(private(directory/'transfer.json'))
    _validate_memoryd_transfer_manifest(manifest)
    if manifest['transfer_manifest_sha256']!=transfer_id:
        raise ValueError('MemoryD transfer manifest identity mismatch')
    receipt_path=_memoryd_receipt_path(transfer_id)
    receipt=json.loads(private(receipt_path)) if receipt_path.exists() or receipt_path.is_symlink() else None
    if receipt and (receipt.get('transfer_manifest_sha256')!=transfer_id
                    or receipt.get('source_database_sha256')!=manifest['source_database_sha256']):
        raise ValueError('A different MemoryD transfer is already recorded')
    current_records=_memoryd_record_count()
    if receipt is None and current_records!=0:
        raise ValueError('MemoryD target is nonempty without a matching transfer receipt')
    legacy_path=STATE/'bootstrap/memoryd-transfer.json'
    if receipt is None and (legacy_path.exists() or legacy_path.is_symlink()):
        previous=json.loads(private(legacy_path))
        if (previous.get('status')!='in_progress' or previous.get('bundles')
                or previous.get('source_database_sha256')!=manifest['source_database_sha256']):
            raise ValueError('Previous MemoryD transfer requires reconciliation')
    backup_info=receipt.get('target_backup') if receipt else None
    if not backup_info:
        backup_path=f"/data/pre-transfer-{transfer_id[:12]}-{time.time_ns()}.db"
        created=_memoryd_cli_json(['backup','create','--local','--dest',backup_path])
        backup_manifest=created.get('manifest',{})
        _memoryd_run_step('target backup permissions',
            ['docker','exec','mcp-control-plane-memoryd','chmod','0600',
             backup_path,backup_path+'.manifest.json'])
        verified=_memoryd_cli_json(['backup','verify','--local','--path',backup_path])
        if verified.get('ok') is not True or backup_manifest.get('sha256')!=verified.get('manifest',{}).get('sha256'):
            raise ValueError('MemoryD target backup verification failed')
        backup_info={'path':backup_path,'sha256':backup_manifest['sha256'],'size_bytes':backup_manifest['size_bytes']}
    if receipt is None:
        receipt={'schema_version':1,'status':'in_progress',
                 'transfer_manifest_sha256':transfer_id,
                 'source_database_sha256':manifest['source_database_sha256'],
                 'source_instance_id':manifest['source_instance_id'],
                 'source_profile':manifest['source_profile'],'source_workspace':manifest['source_workspace'],
                 'target_profile':manifest['target_profile'],'target_workspace':manifest['target_workspace'],
                 'target_backup':backup_info,'bundles':{}}
        write(receipt_path,receipt)
    _memoryd_reconcile_staging(receipt,receipt_path,transfer_id)

    target_tmp=[];bundle_summaries=[];destination_instance_id=None
    staging_id=uuid.uuid4().hex
    def preview_apply(bundle,filename,*,idempotency=False):
        nonlocal destination_instance_id
        inspect=_memoryd_cli_json(['bundle','inspect',filename],timeout=180)
        _validate_memoryd_bundle_report(inspect,manifest,bundle)
        preview=_memoryd_cli_json(['bundle','import','--local','--preview',
            '--to-profile','personal','--to-workspace','dakota-codex-only',filename],timeout=300)
        if (preview.get('safe_to_apply') is not True
                or preview.get('integrity_status')!='verified'
                or preview.get('source_instance_id')!=manifest['source_instance_id']
                or preview.get('source_scope',{}).get('profile')!='personal'
                or preview.get('source_scope',{}).get('workspace')!='dakota-codex-only'
                or preview.get('destination_scope',{}).get('profile')!='personal'
                or preview.get('destination_scope',{}).get('workspace')!='dakota-codex-only'):
            raise ValueError('MemoryD import preview rejected bundle scope or integrity')
        counts=preview.get('counts',{})
        if counts.get('rejected',0)!=0 or counts.get('conflicts',0)!=0:
            raise ValueError('MemoryD import preview has rejected records or conflicts')
        if idempotency and counts.get('create')!=0:
            raise ValueError('MemoryD duplicate replay planned new records')
        destination=preview.get('destination_instance_id')
        if destination_instance_id and destination_instance_id!=destination:
            raise ValueError('MemoryD destination instance changed between bundles')
        destination_instance_id=destination
        applied=_memoryd_cli_json(['bundle','import','--local','--apply','--plan-id',preview['plan_id'],
            '--to-profile','personal','--to-workspace','dakota-codex-only',filename],timeout=600)
        applied_receipt=applied.get('receipt',{})
        if applied_receipt.get('status')!='applied':
            raise ValueError('MemoryD bundle apply did not produce an applied receipt')
        return {'counts':counts,'receipt_id':applied_receipt.get('receipt_id'),
                'destination_instance_id':destination}

    def stage_apply(bundle,index,*,idempotency=False):
        if _memoryd_tmp_available()<bundle['size_bytes']+4*1024*1024:
            raise ValueError('MemoryD temporary storage is insufficient for the next bundle')
        suffix='replay' if idempotency else 'apply'
        container_path=f"/tmp/memoryd-transfer-{transfer_id[:12]}-{staging_id}-{index:02d}-{suffix}.bundle"
        receipt['staging']={'path':container_path,**_memoryd_staging_owner()}
        write(receipt_path,receipt)
        target_tmp.append(container_path)
        try:
            _memoryd_stage_bundle(directory/bundle['path'],container_path,bundle)
            return preview_apply(bundle,container_path,idempotency=idempotency)
        finally:
            _memoryd_run_step('bundle cleanup',
                ['docker','exec','--user','10001:10001','mcp-control-plane-memoryd','rm','-f',container_path],timeout=60)
            target_tmp.remove(container_path)
            receipt.pop('staging');write(receipt_path,receipt)

    try:
        for index,bundle in enumerate(manifest['bundles'],1):
            name=bundle['path']
            applied=stage_apply(bundle,index)
            receipt['bundles'][name]={'sha256':bundle['sha256'],'manifest_digest':bundle['manifest_digest'],
                                      'counts':applied['counts'],'receipt_id':applied['receipt_id']}
            write(receipt_path,receipt)
            bundle_summaries.append({'path':name,'counts':applied['counts']})
        if _memoryd_record_count()!=manifest['source_record_count']:
            raise ValueError('MemoryD target record count does not match Dakota source')
        status_data=_memoryd_cli_json(['status','--local'])
        if (status_data.get('active_profiles')!=['personal']
                or status_data.get('active_workspaces')!=['dakota-codex-only']):
            raise ValueError('MemoryD target profile/workspace boundary does not match source')
        idempotency=[]
        for index,bundle in enumerate(manifest['bundles'],1):
            replay=stage_apply(bundle,index,idempotency=True)
            idempotency.append({'path':bundle['path'],'creates':replay['counts'].get('create',0),
                                'identity_reuses':replay['counts'].get('reuse_identity_exact',0),
                                'content_reuses':replay['counts'].get('reuse_content_exact',0)})
        if any(item['creates']!=0 for item in idempotency):
            raise ValueError('MemoryD duplicate-safe replay created records')
        if _memoryd_record_count()!=manifest['source_record_count']:
            raise ValueError('MemoryD record count changed during idempotency replay')
        recall=json.loads(_memoryd_cli(['recall','--local','--profile','personal','--workspace',
            'dakota-codex-only','--query','Dakota Codex durable memory']))
        recall_facts=len(recall.get('facts',[]));recall_citations=len(recall.get('citations',[]))
        if recall_facts==0 or recall_citations==0 or recall.get('policy',{}).get('authority')!='recall_not_authority':
            raise ValueError('MemoryD post-transfer recall smoke failed')
        receipt.update(status='complete',destination_instance_id=destination_instance_id,
                       imported_record_count=manifest['source_record_count'],
                       idempotency=idempotency,recall_facts=recall_facts,
                       recall_citations=recall_citations,completed_at_ns=time.time_ns())
        write(receipt_path,receipt)
        return {'status':'complete','source_instance_id':manifest['source_instance_id'],
                'destination_instance_id':destination_instance_id,
                'source_database_sha256':manifest['source_database_sha256'],
                'source_record_count':manifest['source_record_count'],
                'target_backup':backup_info,'bundles':bundle_summaries,
                'idempotency':idempotency,'recall_facts':recall_facts,
                'recall_citations':recall_citations}
    finally:
        if target_tmp:
            _memoryd_run_step('bundle cleanup',
                ['docker','exec','--user','10001:10001','mcp-control-plane-memoryd','rm','-f',*target_tmp],timeout=60)


def _require_completed_memoryd_transfer(data):
    if not isinstance(data,dict) or set(data)!={'transfer_manifest_sha256'}:
        raise ValueError('MemoryD registration request shape is invalid')
    transfer_id=data['transfer_manifest_sha256']
    if not isinstance(transfer_id,str) or not re.fullmatch(r'[a-f0-9]{64}',transfer_id):
        raise ValueError('MemoryD registration transfer identity is invalid')
    receipt_path=_memoryd_receipt_path(transfer_id)
    if not receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError('A completed MemoryD transfer is required for registration')
    receipt=json.loads(private(receipt_path))
    if (receipt.get('status')!='complete' or receipt.get('transfer_manifest_sha256')!=transfer_id
            or receipt.get('source_profile')!='personal' or receipt.get('source_workspace')!='dakota-codex-only'
            or receipt.get('target_profile')!='personal' or receipt.get('target_workspace')!='dakota-codex-only'
            or type(receipt.get('imported_record_count')) is not int
            or receipt['imported_record_count']<1
            or _memoryd_record_count()!=receipt['imported_record_count']):
        raise ValueError('A completed MemoryD transfer is required for registration')
    return receipt


def _memoryd_firewall_commands(network, bridge):
    try:
        subnet=ipaddress.ip_network(network['subnet'],strict=True)
        gateway=ipaddress.ip_address(network['gateway'])
        private_ranges=tuple(ipaddress.ip_network(value) for value in
                             ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        if (subnet.version!=4 or subnet.prefixlen<24 or gateway not in subnet
                or not any(subnet.subnet_of(value) for value in private_ranges)
                or not re.fullmatch(r'br-[a-f0-9]{12}',bridge)):
            raise ValueError
    except (KeyError,TypeError,ValueError):
        raise ValueError('MemoryD firewall requires a private bridge subnet and gateway') from None
    check=['sudo','-n','iptables','-C','ufw-user-input','-i',bridge,'-s',str(subnet),
           '-d',str(gateway),'-p','tcp','--dport','8090','-j','ACCEPT']
    allow=['sudo','-n','ufw','allow','in','on',bridge,'from',str(subnet),'to',str(gateway),
           'port','8090','proto','tcp','comment','mcp-control-plane MemoryD private bridge']
    return check,allow


def memoryd_network_allow(data):
    transfer=_require_completed_memoryd_transfer(data)
    memoryd_health()
    if not network_check(NETWORK):
        raise ValueError('MemoryD private network is not owned by Kamal')
    rows=json.loads(run(['docker','network','inspect',NETWORK['name']]))
    if len(rows)!=1:
        raise ValueError('MemoryD private bridge identity is ambiguous')
    row=rows[0]
    bridge=(row.get('Options') or {}).get('com.docker.network.bridge.name','br-'+row['Id'][:12])
    check,allow=_memoryd_firewall_commands(NETWORK,bridge)
    addresses=json.loads(run(['ip','-j','-4','address','show','dev',bridge]))
    prefix=ipaddress.ip_network(NETWORK['subnet']).prefixlen
    if not any(item.get('local')==NETWORK['gateway'] and item.get('prefixlen')==prefix
               for row in addresses for item in row.get('addr_info',[])):
        raise ValueError('MemoryD gateway is not assigned to the owned bridge')
    ufw=run(['sudo','-n','ufw','status']).decode()
    if not re.search(r'(?m)^Status: active\s*$',ufw):
        raise ValueError('MemoryD private firewall requires active UFW')
    run(['sudo','-n','iptables','-S','ufw-user-input'])
    def rule_exists():
        result=subprocess.run(check,capture_output=True,timeout=15)
        if result.returncode not in (0,1):
            raise ValueError('MemoryD firewall rule check failed')
        return result.returncode==0
    path=STATE/'bootstrap/memoryd-firewall.json'
    previous=json.loads(private(path)) if path.exists() or path.is_symlink() else None
    identity={'bridge':bridge,'subnet':NETWORK['subnet'],'gateway':NETWORK['gateway'],
              'port':8090,'transfer_manifest_sha256':transfer['transfer_manifest_sha256']}
    if previous and any(previous.get(key)!=value for key,value in identity.items()):
        raise ValueError('MemoryD firewall receipt identity changed')
    exists=rule_exists()
    created_now=False
    if not exists:
        previous={**identity,'status':'pending','created':True}
        write(path,previous)
        run(allow,timeout=60)
        created_now=True
        if not rule_exists():
            raise ValueError('MemoryD private firewall rule was not installed')
    if not previous:
        previous={**identity,'status':'active','created':False}
        write(path,previous)
    elif previous.get('status')!='active':
        previous['status']='active';write(path,previous)
    probe='import socket,sys; s=socket.create_connection((sys.argv[1],8090),timeout=5); s.close()'
    run(['docker','exec','mcp-control-plane-schema-proxy','python3','-c',probe,NETWORK['gateway']],timeout=15)
    return {**identity,'status':'PASS','rule_created':created_now,
            'rule_owned':previous['created'],'bridge_reachable':True}


def _activation_memoryd_firewall_receipt(activation_id, identity):
    """Retain the captured receipt before replacing bridge-specific state."""
    directory=STATE/'bootstrap'
    _verify_private_directory(directory)
    path=directory/'memoryd-firewall.json'
    archive=directory/f'memoryd-firewall-captured-{activation_id}.json'
    if not os.path.lexists(path):
        if os.path.lexists(archive):
            raise ValueError('MemoryD captured firewall receipt has no current receipt')
        return path,None,None
    original=private(path)
    try:
        previous=json.loads(original)
    except (ValueError,UnicodeDecodeError):
        raise ValueError('MemoryD firewall receipt is invalid') from None
    if not isinstance(previous,dict):
        raise ValueError('MemoryD firewall receipt is invalid')
    if previous.get('activation_id')==activation_id:
        keys=set(identity)|{'status','created','captured_receipt_sha256'}
        captured=previous.get('captured_receipt_sha256')
        if (set(previous)!=keys or any(previous.get(key)!=value for key,value in identity.items())
                or previous.get('status') not in ('pending','active')
                or type(previous.get('created')) is not bool
                or (captured is not None and (not isinstance(captured,str)
                    or not re.fullmatch(r'[a-f0-9]{64}',captured)))):
            raise ValueError('MemoryD activation firewall receipt identity changed')
        if captured is None:
            if os.path.lexists(archive):
                raise ValueError('Unexpected captured MemoryD firewall receipt')
        elif not os.path.lexists(archive) or hashlib.sha256(private(archive)).hexdigest()!=captured:
            raise ValueError('Captured MemoryD firewall receipt changed')
        return path,previous,captured

    if os.path.lexists(archive):
        if private(archive)!=original:
            raise ValueError('Captured MemoryD firewall receipt already exists')
    else:
        # A hard link preserves the exact private bytes and cannot replace another receipt.
        os.link(path,archive,follow_symlinks=False)
        directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        if private(archive)!=original:
            raise ValueError('Captured MemoryD firewall receipt changed')
    return path,None,hashlib.sha256(original).hexdigest()


def activation_memoryd_network(data):
    if not isinstance(data,dict) or set(data)!={'activation_id'}:
        raise ValueError('MemoryD activation network request is invalid')
    activation_id=data['activation_id']
    marker=_activation_marker(activation_id)
    if marker.get('status')!='activating' or marker.get('original_stopped_attested') is not True:
        raise ValueError('MemoryD activation network requires an active attested recovery')
    _verified_memoryd_restore(marker)
    memoryd_health(activation_id=activation_id)
    registration=json.loads(private(STATE/'bootstrap/memoryd-integration.json'))
    if (not _valid_memoryd_receipt(registration)
            or registration['url']!=f"http://{NETWORK['gateway']}:8090/mcp"):
        raise ValueError('Captured MemoryD registration does not match the private gateway')
    if not network_check(NETWORK):
        raise ValueError('MemoryD private network is not owned by Kamal')
    rows=json.loads(run(['docker','network','inspect',NETWORK['name']]))
    if len(rows)!=1 or not isinstance(rows[0],dict):
        raise ValueError('MemoryD private bridge identity is ambiguous')
    row=rows[0]
    network_id=row.get('Id')
    configs=(row.get('IPAM') or {}).get('Config') or []
    if (not isinstance(network_id,str) or not re.fullmatch(r'[a-f0-9]{64}',network_id)
            or row.get('Name')!=NETWORK['name'] or row.get('Driver')!='bridge'
            or (row.get('Labels') or {}).get('mcp-control-plane.owner')!='kamal'
            or sum(item.get('Subnet')==NETWORK['subnet'] and item.get('Gateway')==NETWORK['gateway']
                   for item in configs if isinstance(item,dict))!=1):
        raise ValueError('MemoryD private bridge identity changed')
    bridge=(row.get('Options') or {}).get('com.docker.network.bridge.name','br-'+network_id[:12])
    check,allow=_memoryd_firewall_commands(NETWORK,bridge)
    addresses=json.loads(run(['ip','-j','-4','address','show','dev',bridge]))
    subnet=ipaddress.ip_network(NETWORK['subnet'])
    if not any(item.get('local')==NETWORK['gateway'] and item.get('prefixlen')==subnet.prefixlen
               for address in addresses for item in address.get('addr_info',[])):
        raise ValueError('MemoryD gateway is not assigned to the owned bridge')
    proxy_name=NAMES['kamal']['schema-proxy']
    proxies=json.loads(run(['docker','inspect',proxy_name]))
    if len(proxies)!=1 or not isinstance(proxies[0],dict):
        raise ValueError('MemoryD schema proxy identity is ambiguous')
    proxy=proxies[0]
    attachment=(proxy.get('NetworkSettings',{}).get('Networks') or {}).get(NETWORK['name']) or {}
    try:proxy_address=ipaddress.ip_address(attachment.get('IPAddress',''))
    except ValueError:raise ValueError('MemoryD schema proxy is not on the private bridge') from None
    if (proxy.get('Name','').lstrip('/')!=proxy_name
            or (proxy.get('Config',{}).get('Labels') or {}).get('service')!=proxy_name
            or proxy.get('State',{}).get('Running') is not True
            or attachment.get('NetworkID')!=network_id or proxy_address not in subnet
            or proxy_address in (subnet.network_address,subnet.broadcast_address,
                                 ipaddress.ip_address(NETWORK['gateway']))):
        raise ValueError('MemoryD schema proxy is not on the private bridge')
    ufw=run(['sudo','-n','ufw','status']).decode()
    if not re.search(r'(?m)^Status: active\s*$',ufw):
        raise ValueError('MemoryD private firewall requires active UFW')
    run(['sudo','-n','iptables','-S','ufw-user-input'])

    def rule_exists():
        result=subprocess.run(check,capture_output=True,timeout=15)
        if result.returncode not in (0,1):
            raise ValueError('MemoryD firewall rule check failed')
        return result.returncode==0

    exists=rule_exists()
    identity={'schema_version':1,'activation_id':activation_id,'bridge':bridge,
              'subnet':NETWORK['subnet'],'gateway':NETWORK['gateway'],'port':8090}
    path,previous,captured=_activation_memoryd_firewall_receipt(activation_id,identity)
    owned=previous['created'] if previous else False
    if not exists:owned=True
    receipt={**identity,'status':'pending','created':owned,'captured_receipt_sha256':captured}
    write(path,receipt)
    if not exists:
        run(allow,timeout=60)
        if not rule_exists():
            raise ValueError('MemoryD private firewall rule was not installed')
    probe='import socket,sys; s=socket.create_connection((sys.argv[1],8090),timeout=5); s.close()'
    run(['docker','exec',proxy_name,'python3','-c',probe,NETWORK['gateway']],timeout=15)
    receipt['status']='active';write(path,receipt)
    return {**identity,'status':'PASS','rule_created':not exists,
            'rule_owned':owned,'bridge_reachable':True}


def register_memoryd_app(data):
    transfer=_require_completed_memoryd_transfer(data)
    memoryd_health()
    sys.path.insert(0, str(ROOT / 'scripts'))
    import compose_control as c
    os.environ.update(
        EXECUTOR_URL='http://127.0.0.1:4312',
        EXECUTOR_PAT_FILE=str(STATE / 'secrets/executor-pat'),
    )
    http, session = c.executor_session()
    c.verify_compact(session)
    url = f"http://{NETWORK['gateway']}:8090/mcp"
    marker = STATE / 'bootstrap/memoryd-integration.json'
    has_marker = marker.exists() or marker.is_symlink()
    receipt = json.loads(private(marker)) if has_marker else None
    if has_marker and not _valid_memoryd_receipt(receipt):
        raise ValueError('MemoryD app receipt is invalid')
    pending = STATE / 'bootstrap/memoryd-registration-pending.json'
    has_intent = pending.exists() or pending.is_symlink()
    intent = json.loads(private(pending)) if has_intent else None
    if has_intent and not isinstance(intent,dict):
        raise ValueError('MemoryD pending registration identity changed')
    if not has_intent and receipt is None:
        base=identity(NAMES['kamal']['executor'],exclude_memoryd=True)
        _memoryd_require_recorded_base(base)
        context,_=http.request('GET','/api/context')
        org=context.get('organization')
        if not isinstance(org,str) or not org:
            raise ValueError('MemoryD registration organization is unavailable')
        transfer_id=transfer['transfer_manifest_sha256']
        intent={'status':'prepared','organization':org,'url':url,
                'transfer_manifest_sha256':transfer_id,
                'transfer_receipt_sha256':hashlib.sha256(private(_memoryd_receipt_path(transfer_id))).hexdigest(),
                'source_sha256':hashlib.sha256(c.devsy_app_source(url).strip().encode()).hexdigest(),
                'base_identity':base}
        c.write_private(pending,json.dumps(intent)+'\n')
    first_attempt=False
    if intent is not None:
        if intent.get('transfer_manifest_sha256')!=transfer['transfer_manifest_sha256']:
            raise ValueError('MemoryD pending registration transfer changed')
        identity(NAMES['kamal']['executor'],exclude_memoryd=True)
        first_attempt=intent['status']=='prepared'
        if not first_attempt and receipt is None:
            from urllib.parse import quote
            org=intent['organization']
            inventory,_=http.request('GET','/api/organizations/'+quote(org,safe='')+'/inventory')
            matches=[app for app in inventory['apps'] if app.get('slug')=='memoryd' or app.get('name')=='MemoryD']
            if len(matches)!=1:
                raise ValueError('MemoryD pending registration has no unique imported app; inspect before retrying')
            receipt={'organization':org,'id':matches[0]['id'],'url':url}
    def mark_importing():
        identity(NAMES['kamal']['executor'],exclude_memoryd=True)
        if json.loads(private(pending))!=intent:
            raise ValueError('MemoryD pending registration changed before import')
        intent['status']='importing'
        c.write_private(pending,json.dumps(intent)+'\n')
    registered = c.ensure_memoryd_app(http, url, receipt,
        expected_organization=intent['organization'] if intent is not None else None,
        require_absent=first_attempt, before_import=mark_importing if first_attempt else None)
    if intent is not None:
        identity(NAMES['kamal']['executor'],exclude_memoryd=True)
    c.write_private(marker, json.dumps(registered)+'\n')
    if intent is not None:
        pending.unlink()
    c.search_memoryd(session)
    reads = c.probe_memoryd_reads(session)
    denials = c.probe_memoryd_denials(url)
    return {'registered': True, 'app_id': registered['id'], 'tool_count': 3,
            'executor_discovery': 'PASS', 'read_smoke': reads,
            'negative_checks': denials}


def memoryd_reconcile_pending_registration(data):
    """Reset only a verified, quiescent empty import under the controller lock."""
    if (not isinstance(data,dict) or set(data)!={'confirm_import_quiescent'}
            or data['confirm_import_quiescent'] is not True):
        raise ValueError('Explicit confirmation that the MemoryD import is quiescent is required')
    import compose_control as c
    pending=STATE/'bootstrap/memoryd-registration-pending.json'
    marker=STATE/'bootstrap/memoryd-integration.json'
    _verify_private_directory(pending.parent)
    original=private(pending)
    intent=json.loads(original)
    if not isinstance(intent,dict) or intent.get('status')!='importing':
        raise ValueError('MemoryD reconciliation requires an importing registration intent')
    if marker.exists() or marker.is_symlink():
        raise ValueError('MemoryD reconciliation requires no app receipt')
    identity(NAMES['kamal']['executor'],exclude_memoryd=True,require_memoryd_absent=True)
    backup=pending.with_name('memoryd-registration-intent-backup-'+uuid.uuid4().hex+'.json')
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(original);stream.flush();os.fsync(stream.fileno())
    directory_fd=os.open(backup.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    if private(pending)!=original or marker.exists() or marker.is_symlink():
        raise ValueError('MemoryD registration state changed during reconciliation')
    identity(NAMES['kamal']['executor'],exclude_memoryd=True,require_memoryd_absent=True)
    if private(pending)!=original or marker.exists() or marker.is_symlink():
        raise ValueError('MemoryD registration state changed during reconciliation')
    c.write_private(pending,json.dumps({**intent,'status':'prepared'})+'\n')
    return {'status':'prepared','backup':str(backup),'app_created':False}


def _verify_registered_memoryd_app():
    marker=json.loads(private(STATE/'bootstrap/memoryd-integration.json'))
    import compose_control as c
    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312',
                      EXECUTOR_PAT_FILE=str(STATE/'secrets/executor-pat'))
    http,session=c.executor_session()
    c.verify_compact(session)
    url=f"http://{NETWORK['gateway']}:8090/mcp"
    registered=c.ensure_memoryd_app(http,url,marker)
    if registered!=marker:
        raise ValueError('MemoryD app receipt does not match the registered app')
    c.search_memoryd(session)
    c.probe_memoryd_reads(session)
    c.probe_memoryd_denials(url)
    return registered


def memoryd_reconcile_identity(data):
    transfer=_require_completed_memoryd_transfer(data)
    memoryd_health()
    app=_verify_registered_memoryd_app()
    base=identity(NAMES['kamal']['executor'],exclude_memoryd=True)
    updated=identity(NAMES['kamal']['executor'])
    if base==updated:
        raise ValueError('MemoryD identity transition is missing its app')
    transfer_id=transfer['transfer_manifest_sha256']
    paths={name:STORE/(name+'.json') for name in ('current','previous')}
    documents={name:json.loads(private(path)) for name,path in paths.items()
               if path.exists() or path.is_symlink()}
    if 'current' not in documents or documents['current'].get('authority')!='kamal':
        raise ValueError('MemoryD identity transition requires a Kamal deployment receipt')
    transition_path=STORE/f'memoryd-identity-{transfer_id}.json'
    transition=json.loads(private(transition_path)) if transition_path.exists() or transition_path.is_symlink() else None
    expected={'transfer_manifest_sha256':transfer_id,'previous_identity':base,
              'updated_identity':updated,'memoryd_app_id':app['id'],
              'has_previous':'previous' in documents}
    if transition and (any(transition.get(key)!=value for key,value in expected.items())
                       or transition.get('status') not in ('pending','complete')):
        raise ValueError('MemoryD identity transition receipt changed')
    if any(document.get('identity') not in (base,updated) for document in documents.values()):
        raise ValueError('Executor identity drift prevents MemoryD reconciliation')
    if transition is None and any(document.get('identity')!=base for document in documents.values()):
        raise ValueError('Executor identity drift prevents MemoryD reconciliation')
    for name,document in documents.items():
        backup=STORE/f'pre-memoryd-{name}-{transfer_id}.json'
        if backup.exists() or backup.is_symlink():
            original=json.loads(private(backup))
            if original.get('identity')!=base or {**original,'identity':document['identity']}!=document:
                raise ValueError('MemoryD deployment receipt backup changed')
        else:
            if document.get('identity')!=base:
                raise ValueError('MemoryD deployment receipt backup is missing')
            write(backup,document)
    if transition is None:
        transition={**expected,'status':'pending'}
        write(transition_path,transition)
    changed=False
    for name,document in documents.items():
        if document['identity']==base:
            document['identity']=updated
            write(paths[name],document)
            changed=True
    if transition['status']!='complete':
        transition['status']='complete';write(transition_path,transition)
    return {'identity_updated':changed,'prior_identity_preserved':True,
            'current_identity_matches':True,'previous_receipt_preserved':'previous' in documents}


def lifecycle_check():
    current=json.loads(private(STORE/'current.json'))
    if current['authority']!='kamal':raise ValueError('Local lifecycle requires accepted Kamal ownership')
    _,groups,tunnels=inspect()
    if any(r and (r['State']['Running'] or r['State'].get('Paused')) for r in groups['compose'].values()):
        raise ValueError('Compose is active; Kamal start/stop refused')
    for name,r in groups['kamal'].items():
        if not r or r['Config'].get('Labels',{}).get('service')!=NAMES['kamal'][name]:
            raise ValueError('Local lifecycle requires all existing owned accessories')
    writers=run(['docker','ps','--filter','volume=codex-control-plane_executor-data','--format','{{.Names}}']).decode().split()
    if any(name!=NAMES['kamal']['executor'] for name in writers) or any(name.lstrip('/')!=NAMES['kamal']['tunnel'] for name in tunnels):
        raise ValueError('Foreign production writer/client; local lifecycle refused')
    return status()


def validate_profile():
    for path in (STATE/'cas-targets.json',Path(DEVSY['config_source']),Path(DEVSY['kubeconfig_source'])):
        private(path)
    ssh=NATIVE_SSH
    for name in ('ssh_config.native','known_hosts.native','identity'):private(ssh/name)
    for path in (STATE/'cas',STATE/'cas/runtime',STATE/'cas/receipts',Path(DEVSY['context_dir'])):
        s=path.lstat()
        if not path.is_dir() or path.is_symlink() or s.st_uid!=os.getuid():raise ValueError('Required VM bind directory missing or wrong owner')
    for path in (STATE/'devsy-bridge/scoped-jobs').glob('*.json'):
        record=json.loads(private(path))
        if not path.name.startswith('history-') and record.get('status') in ('accepted','running'):
            raise ValueError('Active scoped provisioning must finish before deployment')


def images(manifest, pull=True, pull_env=None):
    repos={'cas':'ghcr.io/joshyorko/codex-action-server','schema_proxy':'ghcr.io/joshyorko/codex-action-server','executor':'ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12','tunnel':'ghcr.io/openai/tunnel-client:v0.0.15'}
    if set(manifest['images'])!=set(repos): raise ValueError('Image set mismatch')
    for name,want in manifest['images'].items():
        if want['repository']!=repos[name] or not re.fullmatch(r'sha256:[0-9a-f]{64}',want['digest']): raise ValueError('Unapproved image reference')
    result={}
    pull_env=(pull_env or anonymous_docker_environment()) if pull else None
    for name,want in manifest['images'].items():
        ref=want['repository']+'@'+want['digest']
        if pull:run(['docker','pull','--platform','linux/amd64',ref],600,env=pull_env)
        r=json.loads(run(['docker','image','inspect',ref]))[0]
        if r['Architecture']!='amd64' or r['Os']!='linux': raise ValueError('Image architecture mismatch')
        if name in ('cas','schema_proxy') and (not re.fullmatch('[0-9a-f]{40}',want.get('revision','')) or r['Config'].get('Labels',{}).get('org.opencontainers.image.revision')!=want['revision']): raise ValueError('CAS source provenance mismatch')
        result[name]=r['Id']
    return result


def network_check(want):
    if want!=NETWORK: raise ValueError('Unapproved network')
    ids=run(['docker','network','ls','-q']).decode().split();rows=json.loads(run(['docker','network','inspect',*ids]))
    bridges=[];exists=False
    for row in rows:
        for item in row.get('IPAM',{}).get('Config') or []:
            subnet=item.get('Subnet')
            if subnet and ipaddress.ip_network(subnet).version==4 and ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(want['subnet'])):
                labels=row.get('Labels',{}) or {}
                owned=(row['Name']==want['name'] and labels.get('mcp-control-plane.owner')=='kamal')
                compose=(row['Name']=='codex-control-plane_control-plane' and labels.get('com.docker.compose.project')=='codex-control-plane' and labels.get('com.docker.compose.network')=='control-plane')
                if row['Driver']!='bridge' or not (owned or compose) or subnet!=want['subnet'] or item.get('Gateway')!=want['gateway']:raise ValueError('Private network conflicts with another owner')
                bridges.append((row.get('Options') or {}).get('com.docker.network.bridge.name','br-'+row['Id'][:12]))
                exists=exists or owned
    if len(bridges)>1:raise ValueError('Multiple private network owners')
    for route in json.loads(run(['ip','-j','-4','route','show'])):
        destination=route.get('dst','default')
        if destination!='default' and ipaddress.ip_network(destination,strict=False).overlaps(ipaddress.ip_network(want['subnet'])) and route.get('dev') not in bridges:raise ValueError('Private network conflicts with a host route')
    return exists


def network(want):
    if network_check(want):return
    run(['docker','network','create','--driver','bridge','--subnet',want['subnet'],'--gateway',want['gateway'],'--label','mcp-control-plane.owner=kamal',want['name']])


def activation_network(activation_id):
    _activation_marker(activation_id)
    if network_check(NETWORK):raise ValueError('Replacement VM network appeared after activation preflight')
    run(['docker','network','create','--driver','bridge','--subnet',NETWORK['subnet'],'--gateway',NETWORK['gateway'],
         '--label','mcp-control-plane.owner=kamal',NETWORK['name']])
    if not network_check(NETWORK):raise ValueError('Private activation network was not created')
    return {'network_created':True}


def _recovery_validator():
    module=sys.modules.get('prepare_recovery_generation')
    if module is None:
        try:module=importlib.import_module('prepare_recovery_generation')
        except ImportError:raise ValueError('Recovery-generation validator is unavailable on this source revision') from None
    return module.validate_generation


def _prepared_generation(directory):
    root=Path(directory)
    prepared=_recovery_validator()(root)
    generation=prepared['generation']
    path=root/'prepared-manifest.json'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o777!=0o600:
            raise ValueError('Prepared generation manifest ownership or mode mismatch')
        digest=hashlib.sha256()
        while block:=os.read(fd,1024*1024):digest.update(block)
    finally:os.close(fd)
    return {'root':root,'prepared':prepared,'generation':generation,
            'expected_identity':prepared['expected_identity'],'manifest_sha256':digest.hexdigest()}


def _path_is_present(path):
    return os.path.lexists(path)


def executor_volume_owner(uid, gid):
    """The pinned Executor image stores volume files as UID/GID 1000."""
    return uid==1000 and gid==1000


def current_executor_volume_owner():
    return executor_volume_owner(os.getuid(),os.getgid())


def _safe_target_parent(path):
    parent=path.parent
    try:
        info=parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
                or info.st_mode&0o022 or parent.resolve(strict=True)!=parent.absolute()):
            raise ValueError('Recovery destination parent is unsafe')
    except OSError:
        raise ValueError('Recovery destination parent is unavailable') from None


def _verify_private_directory(path):
    try:
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
                or info.st_mode&0o777!=0o700 or path.resolve(strict=True)!=path.absolute()):
            raise ValueError('Deployment state directory is unsafe')
    except OSError:
        raise ValueError('Deployment state directory is unavailable') from None


def _ensure_private_state_store():
    if not _path_is_present(STATE):
        _safe_target_parent(STATE)
        try:STATE.mkdir(mode=0o700)
        except FileExistsError:pass
    _verify_private_directory(STATE)
    if not _path_is_present(STORE):
        try:STORE.mkdir(mode=0o700)
        except FileExistsError:pass
    _verify_private_directory(STORE)


def _empty_private_directory(path, *, allow_lock=False):
    if not _path_is_present(path):
        _safe_target_parent(path)
        return False
    try:
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
                or info.st_mode&0o777!=0o700 or path.resolve(strict=True)!=path.absolute()):
            raise ValueError('Recovery destination must be an owned mode-0700 directory')
        children={child.name for child in path.iterdir()}
        if not children:return True
        if allow_lock and path==STATE and children=={'deployment'}:
            store=path/'deployment';store_info=store.lstat()
            allowed={'deploy.lock'}
            marker=store/'activation-in-progress.json'
            if os.path.lexists(marker):allowed.add(marker.name)
            lock=store/'deploy.lock';lock_info=lock.lstat()
            if (stat.S_ISDIR(store_info.st_mode) and store_info.st_uid==os.getuid()
                    and store_info.st_mode&0o777==0o700
                    and {child.name for child in store.iterdir()}==allowed
                    and stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid==os.getuid()
                    and lock_info.st_mode&0o777==0o600
                    and (not os.path.lexists(marker) or
                         (stat.S_ISREG(marker.lstat().st_mode) and marker.lstat().st_uid==os.getuid()
                          and marker.lstat().st_mode&0o777==0o600))):return True
        raise ValueError('Recovery destination directory is not empty')
    except OSError:
        raise ValueError('Recovery destination directory is unavailable') from None


def _target_preflight(*, allow_lock=False):
    if not current_executor_volume_owner():
        raise ValueError('Replacement operator UID/GID must be 1000 for the captured Executor volume')
    if not ROOT.is_dir() or ROOT.is_symlink() or ROOT.stat().st_uid!=os.getuid():
        raise ValueError('Replacement repository directory is unavailable or unsafe')
    env_path=ROOT/'.env'
    if _path_is_present(env_path):raise ValueError('Replacement repository .env already exists')
    _safe_target_parent(env_path)
    _empty_private_directory(STATE,allow_lock=allow_lock)
    _empty_private_directory(NATIVE_SSH)
    try:
        status=run(['git','-C',str(ROOT),'status','--porcelain']).decode().strip()
        source=run(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip()
    except Exception:
        raise ValueError('Replacement repository source revision is unavailable') from None
    if status:raise ValueError('Replacement repository has uncommitted changes')
    return source


def _activation_container_rows():
    ids=run(['docker','ps','-aq']).decode().split()
    return json.loads(run(['docker','inspect',*ids])) if ids else []


def _is_control_plane_container(row):
    name=row.get('Name','').lstrip('/')
    labels=row.get('Config',{}).get('Labels',{}) or {}
    image=row.get('Config',{}).get('Image','')
    mounts=row.get('Mounts',[]) or []
    known_names={item for group in NAMES.values() for item in group.values()}
    return (name in known_names or name in MEMORYD_SERVICES or name.startswith('mcp-recovery-seed-')
            or labels.get('com.docker.compose.project')=='codex-control-plane'
            or labels.get('service') in set(NAMES['kamal'].values())
            or labels.get('service') in MEMORYD_SERVICES
            or 'executor-selfhost' in image or 'tunnel-client' in image or 'codex-memoryd' in image
            or any(mount.get('Name') in ('codex-control-plane_executor-data',MEMORYD_VOLUME) for mount in mounts))


def _ensure_empty_activation_target(generation_dir, *, allow_lock=False):
    prepared=_prepared_generation(generation_dir)
    source=_target_preflight(allow_lock=allow_lock)
    generation=prepared['generation']
    if generation.get('authority')!='kamal':raise ValueError('Preserved generation does not use supported Kamal authority')
    if source!=generation['source_sha']:raise ValueError('Replacement repository does not match captured source revision')
    rows=_activation_container_rows()
    if any(_is_control_plane_container(row) for row in rows):
        raise ValueError('Replacement VM already has control-plane, Executor, or tunnel containers')
    volumes=set(run(['docker','volume','ls','-q']).decode().split())
    if 'codex-control-plane_executor-data' in volumes:
        raise ValueError('Replacement VM already has the Executor data volume')
    if MEMORYD_VOLUME in volumes:
        raise ValueError('Replacement VM already has the MemoryD data volume')
    if memoryd_listener_addresses(run(['ss','-Hln']).decode()):
        raise ValueError('Replacement VM already has a MemoryD target listener')
    if network_check(NETWORK):raise ValueError('Replacement VM already has the private control-plane network')
    unit=run(['systemctl','show','--property=LoadState','--value','codex-control-plane-devsy']).decode().strip()
    if unit!='loaded':raise ValueError('Replacement VM Devsy systemd unit is unavailable')
    return {**prepared,'repo_source_sha':source,'container_count':len(rows),'network':'absent'}


def activation_plan(generation_dir):
    info=_ensure_empty_activation_target(generation_dir,allow_lock=False)
    return {'ready':True,'generation':info['generation'],'expected_identity':info['expected_identity'],
            'prepared_manifest_sha256':info['manifest_sha256'],'inventory_count':len(info['prepared']['inventory']),
            'repo_source_sha':info['repo_source_sha'],
            'memoryd':info['prepared'].get('memoryd',{'status':'legacy'})}


def _activation_marker(activation_id, *, allow_completed=False):
    if not isinstance(activation_id,str) or not re.fullmatch('[a-f0-9]{32}',activation_id):
        raise ValueError('Activation ID is invalid')
    marker=json.loads(private(STORE/'activation-in-progress.json'))
    if (not isinstance(marker,dict) or marker.get('schema_version')!=1
            or marker.get('activation_id')!=activation_id
            or marker.get('status') not in (('installing','activating','activated') if allow_completed else ('installing','activating'))):
        raise ValueError('Activation ID does not own the current recovery operation')
    return marker


def _verified_memoryd_restore(marker):
    activation_id=marker.get('activation_id')
    descriptor=marker.get('memoryd')
    if (not isinstance(activation_id,str) or not re.fullmatch(r'[a-f0-9]{32}',activation_id)
            or not isinstance(descriptor,dict) or descriptor.get('status')!='captured'
            or not isinstance(marker.get('prepared_manifest_sha256'),str)
            or not re.fullmatch(r'[a-f0-9]{64}',marker['prepared_manifest_sha256'])
            or not isinstance(descriptor.get('backup_sha256'),str)
            or not re.fullmatch(r'[a-f0-9]{64}',descriptor['backup_sha256'])
            or not isinstance(descriptor.get('source_instance_id'),str)
            or not re.fullmatch(r'cmi_[a-f0-9]{32}',descriptor['source_instance_id'])
            or descriptor.get('profile')!='personal' or descriptor.get('workspace')!='dakota-codex-only'
            or any(type(descriptor.get(key)) is not int or descriptor[key]<0
                   for key in ('record_count','active_record_count','archived_record_count'))
            or descriptor['active_record_count']+descriptor['archived_record_count']!=descriptor['record_count']):
        raise ValueError('MemoryD restore receipt has no captured activation')
    path=STORE/f'memoryd-restore-{activation_id}.json'
    receipt=json.loads(private(path))
    expected={'schema_version':1,'status':'verified','activation_id':activation_id,
              'prepared_manifest_sha256':marker.get('prepared_manifest_sha256'),
              'backup_sha256':descriptor.get('backup_sha256'),
              'source_instance_id':descriptor.get('source_instance_id'),
              'record_count':descriptor.get('record_count'),
              'active_record_count':descriptor.get('active_record_count'),
              'archived_record_count':descriptor.get('archived_record_count'),
              'volume':MEMORYD_VOLUME}
    if (not isinstance(receipt,dict) or type(receipt.get('schema_version')) is not int
            or any(type(receipt.get(key)) is not int for key in
                   ('record_count','active_record_count','archived_record_count'))
            or not isinstance(receipt.get('owner_nonce'),str)
            or not re.fullmatch(r'[a-f0-9]{32}',receipt['owner_nonce'])
            or any(receipt.get(key)!=value for key,value in expected.items())):
        raise ValueError('MemoryD restore receipt does not match the captured generation')
    _memoryd_restore_volume(activation_id,receipt['owner_nonce'])
    return receipt


def activation_begin(generation_dir,expected_manifest_sha256,expected_identity,activation_id,original_stopped_attested):
    info=_ensure_empty_activation_target(generation_dir,allow_lock=True)
    if (info['manifest_sha256']!=expected_manifest_sha256 or info['expected_identity']!=expected_identity
            or original_stopped_attested is not True):
        raise ValueError('Activation authorization does not match the prepared generation')
    if not isinstance(activation_id,str) or not re.fullmatch('[a-f0-9]{32}',activation_id):
        raise ValueError('Activation ID is invalid')
    marker_path=STORE/'activation-in-progress.json'
    if os.path.lexists(marker_path):raise ValueError('A recovery activation is already recorded')
    marker={'schema_version':1,'activation_id':activation_id,'status':'installing',
            'source_sha':info['generation']['source_sha'],'expected_identity':expected_identity,
            'prepared_manifest_sha256':expected_manifest_sha256,'original_stopped_attested':True,
            'started_services':[],'memoryd':info['prepared'].get('memoryd',{'status':'legacy'})}
    write(marker_path,marker)
    return {'activation_started':True}


def activation_track(activation_id,service):
    marker=_activation_marker(activation_id)
    names={**NAMES['kamal'],'memoryd':'mcp-control-plane-memoryd','memoryd-mcp':'mcp-control-plane-memoryd-mcp'}
    if service not in names:raise ValueError('Activation service is unsupported')
    matching=[row for row in _activation_container_rows()
              if row.get('Name','').lstrip('/')==names[service]]
    if len(matching)!=1 or matching[0].get('Config',{}).get('Labels',{}).get('service')!=names[service]:
        raise ValueError('New Kamal accessory ownership could not be verified')
    if service not in marker['started_services']:
        marker['started_services'].append(service)
        marker['status']='activating';write(STORE/'activation-in-progress.json',marker)
    return {'accessory_recorded':service}


def _copy_verified_file(source,target,row):
    source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        source_info=os.fstat(source_fd)
        if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid!=os.getuid()
                or source_info.st_mode&0o777!=row['mode'] or source_info.st_size!=row['size']):
            raise ValueError('Prepared generation file changed after validation')
        target_fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,row['mode'])
        digest=hashlib.sha256();size=0
        try:
            while block:=os.read(source_fd,1024*1024):
                size+=len(block);digest.update(block)
                view=memoryview(block)
                while view:
                    written=os.write(target_fd,view);view=view[written:]
            os.fsync(target_fd)
        finally:os.close(target_fd)
        if size!=row['size'] or digest.hexdigest()!=row['sha256']:
            raise ValueError('Prepared generation file digest changed during installation')
        os.chmod(target,row['mode'],follow_symlinks=False)
    finally:os.close(source_fd)


def _install_tree(prepared,generation_root,source_prefix,destination,*,allow_lock=False):
    entries=[row for row in prepared['inventory'] if row['path']==source_prefix or row['path'].startswith(source_prefix+'/')]
    if not entries:raise ValueError('Prepared generation is missing a required payload directory')
    root_row=next((row for row in entries if row['path']==source_prefix),None)
    if root_row is None or root_row['type']!='directory':raise ValueError('Prepared generation payload root is invalid')
    if not _path_is_present(destination):destination.mkdir(mode=root_row['mode'])
    elif destination==STATE and allow_lock:
        _empty_private_directory(destination,allow_lock=True)
    else:
        _empty_private_directory(destination)
    created={source_prefix}
    for row in sorted((item for item in entries if item['path']!=source_prefix),key=lambda item:(item['path'].count('/'),item['path'])):
        relative=PurePosixPath(row['path']).relative_to(PurePosixPath(source_prefix))
        target=destination.joinpath(*relative.parts)
        source=Path(generation_root).joinpath(*PurePosixPath(row['path']).parts)
        if row['type']=='directory':
            if target.exists():
                if source_prefix=='state' and relative.as_posix()=='deployment' and allow_lock:
                    _empty_private_directory(STATE,allow_lock=True)
                    continue
                raise ValueError('Recovery destination contains unexpected data')
            target.mkdir(mode=row['mode']);created.add(row['path'])
        else:
            if target.parent.resolve(strict=True)!=target.parent.absolute():raise ValueError('Recovery destination traverses a symlink')
            _copy_verified_file(source,target,row)


def activation_install(generation_dir,expected_manifest_sha256,activation_id):
    _activation_marker(activation_id)
    info=_ensure_empty_activation_target(generation_dir,allow_lock=True)
    if info['manifest_sha256']!=expected_manifest_sha256:raise ValueError('Prepared generation changed after plan')
    _install_tree(info['prepared'],info['root'],'state',STATE,allow_lock=True)
    _install_tree(info['prepared'],info['root'],'native-ssh',NATIVE_SSH)
    env_row=next((row for row in info['prepared']['inventory'] if row['path']=='vm.env'),None)
    if env_row is None or env_row['type']!='file':raise ValueError('Prepared generation has no VM environment file')
    _copy_verified_file(info['root']/'vm.env',ROOT/'.env',env_row)
    return {'state_installed':True,'native_ssh_installed':True,'vm_environment_installed':True}


def activation_pull_images(manifest,activation_id):
    marker=_activation_marker(activation_id)
    with tempfile.TemporaryDirectory(prefix='mcp-activation-docker-') as root:
        config=Path(root)/'config.json'
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(b'{}\n')
        env=os.environ.copy();env.pop('DOCKER_AUTH_CONFIG',None);env['DOCKER_CONFIG']=root
        image_ids=images(manifest,pull=True,pull_env=env)
        memoryd=marker.get('memoryd',{'status':'legacy'})
        pulled=False
        if memoryd.get('status')=='captured':
            backend=memoryd.get('backend_image');adapter=memoryd.get('adapter_image')
            if (backend!=MEMORYD_IMAGE or not isinstance(adapter,str)
                    or not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}',adapter)):
                raise ValueError('Captured MemoryD image pins are invalid')
            for reference in (backend,adapter):
                run(['docker','pull','--platform','linux/amd64',reference],timeout=600,env=env)
                rows=json.loads(run(['docker','image','inspect',reference],env=env))
                if len(rows)!=1 or rows[0].get('Architecture')!='amd64' or rows[0].get('Os')!='linux':
                    raise ValueError('Captured MemoryD image architecture is invalid')
            pulled=True
        return {'image_ids':image_ids,'pulled':True,'memoryd_images_pulled':pulled}


def activation_seed(generation_dir,expected_manifest_sha256,manifest,activation_id):
    _activation_marker(activation_id)
    info=_prepared_generation(generation_dir)
    if info['manifest_sha256']!=expected_manifest_sha256:raise ValueError('Prepared generation changed before volume seed')
    if manifest!=info['generation']['manifest']:raise ValueError('Executor seed manifest differs from the captured generation')
    images(manifest,pull=False)
    if any(_is_control_plane_container(row) for row in _activation_container_rows()):
        raise ValueError('Unexpected control-plane container appeared before Executor volume seed')
    volume='codex-control-plane_executor-data'
    if volume in set(run(['docker','volume','ls','-q']).decode().split()):
        raise ValueError('Executor data volume appeared before recovery seed')
    nonce=uuid.uuid4().hex
    run(['docker','volume','create','--label','mcp-control-plane.recovery-activation='+nonce,volume])
    volume_info=json.loads(run(['docker','volume','inspect',volume]))[0]
    if volume_info.get('Name')!=volume or (volume_info.get('Labels') or {}).get('mcp-control-plane.recovery-activation')!=nonce:
        raise ValueError('Created Executor volume ownership could not be verified')
    helper='mcp-recovery-seed-'+nonce[:16]
    executor=manifest['images']['executor'];reference=executor['repository']+'@'+executor['digest']
    created=run(['docker','create','--name',helper,'--mount','type=volume,source='+volume+',target=/app/data,volume-nocopy','--entrypoint','/bin/true',reference]).decode().strip()
    try:
        state=json.loads(run(['docker','inspect',created]))[0]['State']
        if state.get('Running') is not False:raise ValueError('Executor seed helper unexpectedly started')
        run(['docker','cp','--archive',str(info['root']/'executor-data')+'/.',created+':/app/data'])
    finally:
        # The stopped helper is owned by this activation. Keep the named volume intact.
        run(['docker','rm',created])
    return {'executor_volume_seeded':True,'helper_started':False,'volume':volume}


def _memoryd_restore_descriptor(prepared):
    descriptor=prepared.get('memoryd')
    keys={'status','backend_image','adapter_image','adapter_sha256','backup_sha256',
          'backup_manifest_sha256','backup_size_bytes','source_instance_id','record_count',
          'active_record_count','archived_record_count','profile','workspace','captured_at'}
    if (prepared.get('schema_version')!=2 or not isinstance(descriptor,dict) or set(descriptor)!=keys
            or descriptor.get('status')!='captured' or descriptor.get('backend_image')!=MEMORYD_IMAGE
            or not isinstance(descriptor.get('adapter_image'),str)
            or not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}',descriptor['adapter_image'])
            or any(not isinstance(descriptor.get(key),str) or not re.fullmatch('[a-f0-9]{64}',descriptor[key])
                   for key in ('adapter_sha256','backup_sha256','backup_manifest_sha256'))
            or type(descriptor.get('backup_size_bytes')) is not int or descriptor['backup_size_bytes']<=0
            or not isinstance(descriptor.get('source_instance_id'),str)
            or not re.fullmatch(r'cmi_[a-f0-9]{32}',descriptor['source_instance_id'])
            or any(type(descriptor.get(key)) is not int or descriptor[key]<0
                   for key in ('record_count','active_record_count','archived_record_count'))
            or descriptor['record_count']!=descriptor['active_record_count']+descriptor['archived_record_count']
            or descriptor.get('profile')!='personal' or descriptor.get('workspace')!='dakota-codex-only'
            or not isinstance(descriptor.get('captured_at'),str) or not descriptor['captured_at']):
        raise ValueError('Prepared MemoryD recovery descriptor is invalid')
    return descriptor


def _memoryd_restore_private_hash(path, expected, *, size=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                or before.st_mode&0o777!=0o600 or before.st_nlink!=1
                or (size is not None and before.st_size!=size)):
            raise ValueError('Prepared MemoryD recovery file is unsafe')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
        after=os.fstat(fd)
        if (digest!=expected or before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns
                or before.st_ctime_ns!=after.st_ctime_ns):
            raise ValueError('Prepared MemoryD recovery file digest changed')
    finally:os.close(fd)


def _memoryd_restore_sources(info,descriptor):
    root=info['root']
    _verify_private_directory(root)
    _verify_private_directory(root/'memoryd')
    _memoryd_restore_private_hash(root/'prepared-manifest.json',info['manifest_sha256'])
    _memoryd_restore_private_hash(root/'memoryd/backup.db',descriptor['backup_sha256'],size=descriptor['backup_size_bytes'])
    _memoryd_restore_private_hash(root/'memoryd/backup.db.manifest.json',descriptor['backup_manifest_sha256'])


def _memoryd_restore_inventory(*, helper_id=None, owned_volume=False):
    ids=run(['docker','ps','-aq']).decode().split()
    rows=json.loads(run(['docker','inspect',*ids])) if ids else []
    if not isinstance(rows,list) or len(rows)!=len(ids):raise ValueError('MemoryD container inventory is invalid')
    for row in rows:
        if (not isinstance(row,dict) or not isinstance(row.get('Id'),str)
                or not isinstance(row.get('Name'),str) or not isinstance(row.get('Config'),dict)
                or not isinstance(row.get('Mounts'),list)
                or any(not isinstance(mount,dict) for mount in row['Mounts'])):
            raise ValueError('MemoryD container inventory is invalid')
        if row['Id']==helper_id:continue
        config=row['Config'];labels=config.get('Labels') or {};image=config.get('Image') or ''
        if not isinstance(labels,dict) or not isinstance(image,str):raise ValueError('MemoryD container inventory is invalid')
        name=row['Name'].lstrip('/')
        if ('memoryd' in name.lower() or 'codex-memoryd' in image.lower()
                or labels.get('service') in MEMORYD_SERVICES
                or (labels.get('com.docker.compose.project')=='codex-control-plane'
                    and labels.get('com.docker.compose.service') in ('memoryd','memoryd-mcp'))
                or any('memoryd' in str(m.get('Name','')).lower() for m in row['Mounts'])):
            raise ValueError('Existing MemoryD container or volume writer blocks recovery')
    volumes=set(run(['docker','volume','ls','--format','{{.Name}}']).decode().split())
    memory_volumes={name for name in volumes if 'memoryd' in name.lower()}
    if memory_volumes!=({MEMORYD_VOLUME} if owned_volume else set()):
        raise ValueError('Existing or missing MemoryD volume blocks recovery')
    if memoryd_listener_addresses(run(['ss','-Hln']).decode()):
        raise ValueError('Existing MemoryD listener blocks recovery')


def _memoryd_restore_image(descriptor):
    rows=json.loads(run(['docker','image','inspect',descriptor['backend_image']]))
    if (not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict)
            or rows[0].get('Architecture')!='amd64' or rows[0].get('Os')!='linux'
            or descriptor['backend_image'] not in (rows[0].get('RepoDigests') or [])
            or not re.fullmatch(r'sha256:[a-f0-9]{64}',rows[0].get('Id',''))):
        raise ValueError('Captured MemoryD image is not available locally by immutable digest')
    return rows[0]['Id']


def _memoryd_restore_intent(path,intent):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w',closefd=False) as stream:
            json.dump(intent,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def _memoryd_restore_volume(activation_id,nonce):
    rows=json.loads(run(['docker','volume','inspect',MEMORYD_VOLUME]))
    if (not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict)
            or rows[0].get('Name')!=MEMORYD_VOLUME or rows[0].get('Driver')!='local'
            or rows[0].get('Scope')!='local' or (rows[0].get('Options') or {})!={}
            or (rows[0].get('Labels') or {}).get('mcp-control-plane.recovery-activation')!=activation_id
            or (rows[0].get('Labels') or {}).get('mcp-control-plane.restore-nonce')!=nonce):
        raise ValueError('MemoryD recovery volume ownership could not be verified')


def _memoryd_restore_helper(helper, name, activation_id, nonce, image_id, *, running):
    rows=json.loads(run(['docker','inspect',helper]))
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):
        raise ValueError('MemoryD recovery helper inspection failed')
    row=rows[0];config=row.get('Config') or {};labels=config.get('Labels') or {};state=row.get('State') or {}
    mounts=row.get('Mounts') or []
    if (row.get('Id')!=helper or row.get('Name','').lstrip('/')!=name or row.get('Image')!=image_id
            or config.get('Image')!=MEMORYD_IMAGE or config.get('User')!='10001:10001'
            or config.get('Entrypoint')!=['/bin/sleep'] or config.get('Cmd')!=['infinity']
            or (config.get('Healthcheck') or {}).get('Test')!=['NONE']
            or labels.get('mcp-control-plane.recovery-activation')!=activation_id
            or labels.get('mcp-control-plane.restore-nonce')!=nonce
            or (row.get('HostConfig') or {}).get('NetworkMode')!='none'
            or state.get('Running') is not running or state.get('Paused') is not False
            or len(mounts)!=1 or mounts[0].get('Name')!=MEMORYD_VOLUME
            or mounts[0].get('Destination')!='/data' or mounts[0].get('RW') is not True):
        raise ValueError('MemoryD recovery helper ownership or isolation is invalid')


def _memoryd_restore_exec(helper,*args):
    return run(['docker','exec','--user','10001:10001',helper,*args],timeout=600)


def _memoryd_restore_pipe(helper,source,destination):
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        with os.fdopen(fd,'rb',closefd=False) as stream:
            result=subprocess.run(['docker','exec','-i','--user','10001:10001',helper,
                                   '/bin/sh','-c','umask 077; exec cat > "$1"','sh',destination],
                                  stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=600)
        if result.returncode:raise RuntimeError('MemoryD backup staging failed; output withheld')
    finally:os.close(fd)


def _memoryd_restore_copy_target(helper,destination):
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            result=subprocess.run(['docker','exec','--user','10001:10001',helper,'/bin/cat','/data/memory.db'],
                                  stdout=stream,stderr=subprocess.PIPE,timeout=600)
            stream.flush();os.fsync(stream.fileno())
        if result.returncode:raise RuntimeError('MemoryD restored database copy failed; output withheld')
    finally:os.close(fd)


def _memoryd_restore_scratch(helper,info,descriptor):
    _memoryd_restore_sources(info,descriptor)
    _memoryd_restore_exec(helper,'/bin/sh','-c',
                          ' # SCRATCH_FILES\n'
                          'for p in /tmp/restore/backup.db /tmp/restore/backup.db.manifest.json; do '
                          'test -f "$p" && test ! -L "$p" || exit 1; done; '
                          'for p in /tmp/restore/backup.db-wal /tmp/restore/backup.db-shm /tmp/restore/backup.db-journal; do '
                          'if [ -e "$p" ] || [ -L "$p" ]; then exit 1; fi; done')
    for path,digest in (('/tmp/restore/backup.db',descriptor['backup_sha256']),
                        ('/tmp/restore/backup.db.manifest.json',descriptor['backup_manifest_sha256'])):
        output=_memoryd_restore_exec(helper,'/usr/bin/sha256sum','--',path).decode().split()
        if len(output)!=2 or output[0]!=digest or output[1]!=path:
            raise ValueError('MemoryD scratch backup digest changed')


def _memoryd_restore_target(helper, *, present):
    # Check dangling symlinks too: restore-apply removes sidecars and overwrites a target.
    if present:
        script=(' # TARGET_PRESENT\n'
                'test -f /data/memory.db && test ! -L /data/memory.db && '
                'for p in /data/memory.db-wal /data/memory.db-shm /data/memory.db-journal; do '
                'if [ -e "$p" ] || [ -L "$p" ]; then exit 1; fi; done')
    else:
        script=(' # TARGET_ABSENT\n'
                'for p in /data/memory.db /data/memory.db-wal /data/memory.db-shm /data/memory.db-journal; do '
                'if [ -e "$p" ] || [ -L "$p" ]; then exit 1; fi; done')
    _memoryd_restore_exec(helper,'/bin/sh','-c',script)


def _memoryd_restore_verified_report(value,descriptor):
    manifest=value.get('manifest') if isinstance(value,dict) else None
    return (isinstance(manifest,dict) and all(value.get(key) is True
            for key in ('ok','digest_matches','integrity_ok','schema_matches'))
            and manifest.get('sha256')=='sha256:'+descriptor['backup_sha256']
            and manifest.get('size_bytes')==descriptor['backup_size_bytes'])


def _memoryd_restore_sqlite(path,descriptor):
    try:
        db=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
        try:
            integrity=db.execute('PRAGMA integrity_check').fetchall()
            instance=db.execute('SELECT singleton_key, instance_id FROM instance_metadata').fetchall()
            total=db.execute('SELECT count(*) FROM memory_records').fetchone()[0]
            counts=db.execute('SELECT count(*), coalesce(sum(archived=0),0), coalesce(sum(archived=1),0) '
                              'FROM memory_records WHERE profile_id=? AND workspace_id=?',
                              (descriptor['profile'],descriptor['workspace'])).fetchone()
        finally:db.close()
    except (sqlite3.Error,OSError):
        raise ValueError('Restored MemoryD database could not be checked privately') from None
    if (integrity!=[('ok',)] or instance!=[('default',descriptor['source_instance_id'])]
            or total!=descriptor['record_count'] or counts!=(descriptor['record_count'],
                descriptor['active_record_count'],descriptor['archived_record_count'])):
        raise ValueError('Restored MemoryD identity or scoped record counts do not match capture')


def _memoryd_restore_idle(helper):
    lines=run(['docker','top',helper,'-eo','pid,comm']).decode().splitlines()
    if len(lines)!=2 or lines[1].split()[-1:]!=['sleep']:
        raise ValueError('MemoryD recovery helper may still be writing')


def _memoryd_restore_guard(helper,name,activation_id,nonce,image_id):
    _memoryd_restore_helper(helper,name,activation_id,nonce,image_id,running=True)
    _memoryd_restore_volume(activation_id,nonce)
    _memoryd_restore_inventory(helper_id=helper,owned_volume=True)
    _memoryd_restore_idle(helper)


def _memoryd_restore_remove_helper(helper,name,activation_id,nonce,image_id):
    _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
    run(['docker','stop','--time','10',helper])
    _memoryd_restore_helper(helper,name,activation_id,nonce,image_id,running=False)
    run(['docker','rm',helper])


def activation_memoryd_restore(generation_dir,expected_manifest_sha256,activation_id):
    marker=_activation_marker(activation_id)
    info=_prepared_generation(generation_dir)
    descriptor=_memoryd_restore_descriptor(info['prepared'])
    if (not isinstance(expected_manifest_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_manifest_sha256)
            or info['manifest_sha256']!=expected_manifest_sha256
            or marker.get('prepared_manifest_sha256')!=expected_manifest_sha256
            or marker.get('source_sha')!=info['generation']['source_sha']
            or marker.get('expected_identity')!=info['expected_identity']
            or marker.get('original_stopped_attested') is not True or marker.get('memoryd')!=descriptor):
        raise ValueError('MemoryD recovery does not match the activation authorization')
    _memoryd_restore_sources(info,descriptor)
    _memoryd_restore_inventory()
    image_id=_memoryd_restore_image(descriptor)
    nonce=uuid.uuid4().hex
    name='mcp-recovery-memoryd-'+activation_id[:12]+'-'+nonce[:12]
    receipt_path=STORE/f'memoryd-restore-{activation_id}.json'
    receipt={'schema_version':1,'status':'intent','activation_id':activation_id,
             'prepared_manifest_sha256':expected_manifest_sha256,'backup_sha256':descriptor['backup_sha256'],
             'source_instance_id':descriptor['source_instance_id'],'record_count':descriptor['record_count'],
             'active_record_count':descriptor['active_record_count'],'archived_record_count':descriptor['archived_record_count'],
             'profile':descriptor['profile'],'workspace':descriptor['workspace'],'volume':MEMORYD_VOLUME,
             'helper_name':name,'owner_nonce':nonce,'started_at_ns':time.time_ns()}
    _memoryd_restore_intent(receipt_path,receipt)
    helper=None
    try:
        _memoryd_restore_inventory()
        run(['docker','volume','create','--driver','local','--label','mcp-control-plane.recovery-activation='+activation_id,
             '--label','mcp-control-plane.restore-nonce='+nonce,MEMORYD_VOLUME])
        _memoryd_restore_volume(activation_id,nonce)
        _memoryd_restore_inventory(owned_volume=True)
        helper=run(['docker','create','--pull','never','--name',name,'--network','none','--no-healthcheck',
                    '--user','10001:10001','--label','mcp-control-plane.recovery-activation='+activation_id,
                    '--label','mcp-control-plane.restore-nonce='+nonce,
                    '--mount','type=volume,source='+MEMORYD_VOLUME+',target=/data',
                    '--entrypoint','/bin/sleep',descriptor['backend_image'],'infinity']).decode().strip()
        _memoryd_restore_helper(helper,name,activation_id,nonce,image_id,running=False)
        _memoryd_restore_inventory(helper_id=helper,owned_volume=True)
        run(['docker','start',helper])
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_exec(helper,'/bin/mkdir','-m','0700','/tmp/restore')
        _memoryd_restore_pipe(helper,info['root']/'memoryd/backup.db','/tmp/restore/backup.db')
        _memoryd_restore_pipe(helper,info['root']/'memoryd/backup.db.manifest.json','/tmp/restore/backup.db.manifest.json')
        _memoryd_restore_scratch(helper,info,descriptor)
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_target(helper,present=False)
        base=['/usr/local/bin/codex-memoryd','backup']
        common=['--local','--db','/tmp/restore/unused.db']
        verify_raw=_memoryd_restore_exec(helper,*base,'verify',*common,'--path','/tmp/restore/backup.db')
        _memoryd_restore_scratch(helper,info,descriptor)
        verify=json.loads(verify_raw)
        if not _memoryd_restore_verified_report(verify,descriptor):raise ValueError('MemoryD backup verification failed')
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_target(helper,present=False)
        preview_raw=_memoryd_restore_exec(helper,*base,'restore-preview',*common,
                                        '--from','/tmp/restore/backup.db','--target','/data/memory.db')
        _memoryd_restore_scratch(helper,info,descriptor)
        preview=json.loads(preview_raw)
        if (not isinstance(preview,dict) or preview.get('safe_to_apply') is not True
                or preview.get('target_exists') is not False
                or not _memoryd_restore_verified_report(preview.get('verify'),descriptor)):
            raise ValueError('MemoryD restore preview is unsafe')
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_target(helper,present=False)
        _memoryd_restore_scratch(helper,info,descriptor)
        applied_raw=_memoryd_restore_exec(helper,*base,'restore-apply',*common,
                                        '--from','/tmp/restore/backup.db','--target','/data/memory.db')
        _memoryd_restore_scratch(helper,info,descriptor)
        applied=json.loads(applied_raw)
        if (not isinstance(applied,dict) or applied.get('restored') is not True
                or applied.get('target_path')!='/data/memory.db' or applied.get('prior_backup') is not None):
            raise ValueError('MemoryD restore result is invalid')
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_target(helper,present=True)
        _memoryd_restore_exec(helper,'/usr/bin/sync','-f','/data/memory.db','/data')
        with tempfile.TemporaryDirectory(prefix='memoryd-restore-check-',dir=STORE) as directory:
            copy=Path(directory)/'memory.db'
            _memoryd_restore_copy_target(helper,copy)
            _memoryd_restore_private_hash(copy,descriptor['backup_sha256'],size=descriptor['backup_size_bytes'])
            _memoryd_restore_sqlite(copy,descriptor)
            _memoryd_restore_private_hash(copy,descriptor['backup_sha256'],size=descriptor['backup_size_bytes'])
        target_hash=_memoryd_restore_exec(helper,'/usr/bin/sha256sum','--','/data/memory.db').decode().split()
        if target_hash!=[descriptor['backup_sha256'],'/data/memory.db']:
            raise ValueError('Restored MemoryD target digest does not match backup')
        _memoryd_restore_target(helper,present=True)
        _memoryd_restore_scratch(helper,info,descriptor)
        _memoryd_restore_guard(helper,name,activation_id,nonce,image_id)
        _memoryd_restore_remove_helper(helper,name,activation_id,nonce,image_id)
        helper=None
        _memoryd_restore_volume(activation_id,nonce)
        _memoryd_restore_inventory(owned_volume=True)
        _memoryd_restore_sources(info,descriptor)
        receipt.update(status='verified',verified_at_ns=time.time_ns())
        write(receipt_path,receipt)
        return {'status':'verified','memoryd_restored':True,'backup_sha256':descriptor['backup_sha256']}
    except BaseException:
        # An interrupted Docker exec can remain active. Retain its helper and volume.
        raise


def activation_identity(expected_identity,activation_id):
    marker=_activation_marker(activation_id)
    if marker['expected_identity']!=expected_identity:raise ValueError('Activation identity does not match its private operation marker')
    actual=identity(NAMES['kamal']['executor'])
    if actual!=expected_identity:raise ValueError('Recovered Executor identity did not match the captured identity')
    return {'identity_preserved':True}


def activation_record(data):
    marker=_activation_marker(data.get('activation_id'))
    if (set(data)!={'activation_id','source_sha','expected_identity','identity_preserved','original_stopped_attested'}
            or data['identity_preserved'] is not True or data['original_stopped_attested'] is not True
            or not re.fullmatch('[a-f0-9]{40}',data['source_sha'])
            or not isinstance(data['expected_identity'],str)
            or data['source_sha']!=marker['source_sha'] or data['expected_identity']!=marker['expected_identity']):
        raise ValueError('Activation receipt input is invalid')
    discovery=marker.get('memoryd_discovery')
    captured=marker.get('memoryd',{}).get('status')=='captured'
    if captured:
        _verified_memoryd_restore(marker)
    if (marker.get('status')!='activating' or marker.get('original_stopped_attested') is not True
            or discovery not in ('PASS','UNREGISTERED','UNAVAILABLE')
            or (captured and (discovery!='PASS' or marker.get('memoryd_restored') is not True))
            or (not captured and marker.get('memoryd_restored') is not False)):
        raise ValueError('Activation receipt requires a completed MemoryD recovery smoke result')
    if (STORE/'recovery-activation.json').exists():raise ValueError('Activation receipt already exists')
    marker['status']='activated';write(STORE/'activation-in-progress.json',marker)
    receipt={**data,'schema_version':1,'recorded_at_ns':time.time_ns(),
             'memoryd_discovery':discovery,'memoryd_restored':captured}
    write(STORE/'recovery-activation.json',receipt)
    return {'activation_recorded':True,'memoryd_discovery':discovery,'memoryd_restored':captured}


def activation_cleanup(activation_id,attempted_services):
    marker=_activation_marker(activation_id,allow_completed=True)
    names={**NAMES['kamal'],'memoryd':'mcp-control-plane-memoryd','memoryd-mcp':'mcp-control-plane-memoryd-mcp'}
    if (not isinstance(attempted_services,list)
            or any(service not in names for service in attempted_services)):
        raise ValueError('Activation cleanup service set is invalid')
    allowed=set(marker['started_services'])|set(attempted_services)
    rows=_activation_container_rows()
    selected=[];helper_retained=False
    restore_path=STORE/f'memoryd-restore-{activation_id}.json'
    restore=json.loads(private(restore_path)) if restore_path.exists() or restore_path.is_symlink() else None
    if restore is not None:
        nonce=restore.get('owner_nonce') if isinstance(restore,dict) else None
        if (not isinstance(nonce,str) or not re.fullmatch(r'[a-f0-9]{32}',nonce)
                or restore.get('helper_name')!='mcp-recovery-memoryd-'+activation_id[:12]+'-'+nonce[:12]):
            raise ValueError('MemoryD recovery helper receipt is invalid')
    for row in rows:
        name=row.get('Name','').lstrip('/')
        labels=row.get('Config',{}).get('Labels',{}) or {}
        if (restore and name==restore.get('helper_name')
                and labels.get('mcp-control-plane.recovery-activation')==activation_id
                and labels.get('mcp-control-plane.restore-nonce')==restore.get('owner_nonce')):
            running=row.get('State',{}).get('Running')
            if type(running) is not bool:
                raise ValueError('MemoryD recovery helper state is invalid')
            image_id=_memoryd_restore_image(marker.get('memoryd'))
            _memoryd_restore_helper(row['Id'],name,activation_id,nonce,image_id,running=running)
            _memoryd_restore_volume(activation_id,nonce)
            helper_retained=True
            continue
        service=next((key for key,value in names.items() if value==name),None)
        if service in allowed:
            if row.get('Config',{}).get('Labels',{}).get('service')!=name:
                raise ValueError('Activation cleanup refused a container with foreign ownership')
            selected.append(row)
        elif _is_control_plane_container(row):
            raise ValueError('Activation cleanup found a foreign control-plane container')
    for row in reversed(selected):
        cid=row['Id']
        if row['State'].get('Running') or row['State'].get('Paused'):run(['docker','stop',cid])
        run(['docker','rm',cid])
    marker['status']='failed-cleanup-complete';write(STORE/'activation-in-progress.json',marker)
    return {'new_accessories_removed':len(selected),'recovered_state_preserved':True,
            'executor_volume_preserved':True,'memoryd_volume_preserved':True,
            'memoryd_helper_retained':helper_retained}


def wait_service(owner,name):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        r=json.loads(run(['docker','inspect',NAMES[owner][name]]))[0]
        if r['State'].get('Health',{}).get('Status')=='healthy': return
        time.sleep(3)
    raise ValueError('Managed service health deadline failed: '+name)


def snapshot_databases(directory, archive_name):
    """Create SQLite-consistent CAS copies and a relocatable source-path map."""
    databases=directory/archive_name
    databases.mkdir(mode=0o700)
    mapping=[]
    for source in (STATE/'cas/runtime').rglob('*.db'):
        if source.name not in ('server.db','workitems.db'):continue
        relative=source.relative_to(STATE).as_posix()
        target=databases/(hashlib.sha256(relative.encode()).hexdigest()[:12]+'-'+source.name)
        with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as original,sqlite3.connect(target) as copy:
            original.backup(copy)
        target.chmod(0o600)
        mapping.append({'relative_path':relative,'snapshot':target.name})
    metadata=databases/'manifest.json'
    metadata.write_text(json.dumps({'schema_version':1,'databases':mapping},sort_keys=True)+'\n')
    metadata.chmod(0o600)
    return databases


def recorded_runtime_source_sha():
    """Require the clean VM checkout to be the source revision in its ledger."""
    current=json.loads(private(STORE/'current.json'))
    expected=current.get('source_sha') if isinstance(current,dict) else None
    if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{40}',expected):
        raise ValueError('Recorded deployment source revision is invalid')
    status=run(['git','-C',str(ROOT),'status','--porcelain']).decode().strip()
    actual=run(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip()
    if status:raise ValueError('Runtime source checkout has uncommitted changes; backup refused')
    if actual!=expected:raise ValueError('Runtime source checkout differs from the recorded deployment; backup refused')
    return expected


def create_runtime_source_bundle(directory,expected_sha):
    bundle=directory/'runtime-source.bundle'
    run(['git','-C',str(ROOT),'bundle','create',str(bundle),'HEAD'])
    bundle.chmod(0o600)
    info=bundle.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o777!=0o600:
        raise ValueError('Runtime source bundle ownership or mode mismatch')
    heads=run(['git','-C',str(ROOT),'bundle','list-heads',str(bundle)]).decode().splitlines()
    listed=[]
    for line in heads:
        fields=line.split()
        if len(fields)==2 and fields[1]=='HEAD':listed.append(fields[0])
    if listed!=[expected_sha]:raise ValueError('Runtime source bundle does not match the recorded deployment')
    return bundle


def backup(*, include_memoryd=False):
    validate_profile()
    source_sha=recorded_runtime_source_sha()
    memoryd_state=memoryd_capture_preflight() if include_memoryd else None
    owner,groups,_=inspect();cid=groups[owner]['executor']['Id']
    directory=STORE/'backups'/str(time.time_ns());directory.mkdir(mode=0o700,parents=True)
    create_runtime_source_bundle(directory,source_sha)
    guard=subprocess.Popen(['python3','-c','import subprocess,time;time.sleep(40);subprocess.run(["docker","unpause",'+repr(cid)+'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        run(['docker','pause',cid]);path=directory/'executor.tar'
        with path.open('xb') as f:
            r=subprocess.run(['docker','cp',cid+':/app/data','-'],stdout=f,stderr=subprocess.DEVNULL,timeout=35)
            if r.returncode: raise ValueError('Executor backup failed')
            f.flush();os.fsync(f.fileno())
        path.chmod(0o600)
    finally:
        run(['docker','unpause',cid]);guard.terminate();guard.wait(timeout=5)
    databases=snapshot_databases(directory,'cas-databases')
    with (directory/'essential.tar').open('xb') as output:
        with tarfile.open(fileobj=output,mode='w') as archive:
            for rel in ('secrets','bootstrap','cas-targets.json','cas/dynamic-targets.json','owner-devsy-scope','ror','devsy-bridge/scoped-jobs','devsy-bridge/creation-receipts'):
                f=STATE/rel
                if f.exists(): archive.add(f,arcname=rel)
            required_sources=(
                (STATE/'cas/receipts','cas/receipts'),
                (NATIVE_SSH,'native-ssh'),
                (Path(DEVSY['config_source']),'devsy-operator/config.yaml'),
                (Path(DEVSY['context_dir']),'devsy-operator/contexts/'+DEVSY['context']),
                (Path(DEVSY['kubeconfig_source']),'devsy-operator/operator-kubeconfig.json'),
                (STATE/'start-host-devsy.py','start-host-devsy.py'),
            )
            for source,arcname in required_sources:
                if not source.exists():raise ValueError('Required recovery input is missing: '+arcname)
                archive.add(source,arcname=arcname)
            for source,arcname in ((STORE/'current.json','deployment/current.json'),(STORE/'previous.json','deployment/previous.json')):
                if source.exists():
                    private(source)
                    archive.add(source,arcname=arcname)
            archive.add(ROOT/'.env',arcname='compose.env')
            archive.add(databases,arcname='cas-databases')
    (directory/'essential.tar').chmod(0o600)
    result = {'backup':str(directory),'executor_sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()}
    if include_memoryd:
        result['memoryd'] = capture_memoryd(directory / 'memoryd', expected=memoryd_state)
    return result


def backup_cas():
    directory=STORE/'backups'/('cas-'+str(time.time_ns()));directory.mkdir(mode=0o700,parents=True)
    databases=snapshot_databases(directory,'databases')
    archive=directory/'cas-essential.tar'
    with tarfile.open(archive,'x') as output:
        for relative in ('cas-targets.json','cas/dynamic-targets.json','owner-devsy-scope','devsy-bridge/scoped-jobs','devsy-bridge/creation-receipts'):
            path=STATE/relative
            if path.exists():output.add(path,arcname=relative)
        output.add(databases,arcname='databases')
    archive.chmod(0o600)
    return {'cas_backup':str(directory),'executor_untouched':True}


def _codex_read_payload(value):
    if not isinstance(value, dict) or set(value) != {"target", "cwd", "thread_id"}:
        return None
    target, cwd, thread_id = value["target"], value["cwd"], value["thread_id"]
    if (not isinstance(target, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", target)
            or not isinstance(cwd, str) or not isinstance(thread_id, str)):
        return None
    path = PurePosixPath(cwd)
    if (not path.is_absolute() or ".." in path.parts or str(path) != cwd
            or any(ord(char) < 32 for char in cwd)
            or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", thread_id)):
        return None
    return {"target": target, "cwd": cwd, "thread_id": thread_id}


def _codex_tool(client, session, name, arguments):
    code = "return await tools.codex." + name + "(" + json.dumps(arguments) + ");"
    try:
        envelope = client.execution(session.call("tools/call", {
            "name": "execute", "arguments": {"code": code},
        }))
    except Exception:
        return None, "EXECUTOR_UNAVAILABLE"
    if (envelope.get("status") != "completed"
            or not envelope.get("execution", {}).get("ok")):
        return None, "EXECUTOR_CALL_FAILED"
    value = envelope["execution"].get("value")
    structured = value.get("structuredContent") if isinstance(value, dict) else None
    if not isinstance(structured, dict):
        return None, "CODEX_RESPONSE_INVALID"
    error = structured.get("error")
    if error:
        if error == "Stored thread id/cwd does not match the requested workstream":
            return None, "THREAD_WORKSTREAM_MISMATCH"
        return None, "CODEX_READ_FAILED"
    result = structured.get("result")
    if not isinstance(result, dict):
        return None, "CODEX_RESPONSE_INVALID"
    return result, None


def native_thread_read(client, session, supplied):
    identity = _codex_read_payload(supplied)
    if identity is None:
        return {"status": "FAIL", "error_code": "NATIVE_TUPLE_INVALID"}
    snapshot, error = _codex_tool(client, session, "get_thread_snapshot", {
        "payload": identity,
    })
    if error:
        return {"status": "FAIL", "error_code": error}
    if not isinstance(snapshot, dict):
        return {"status": "FAIL", "error_code": "CODEX_RESPONSE_INVALID"}
    if "connection" in snapshot and "result" in snapshot:
        connection = snapshot.get("connection")
        if (not isinstance(connection, dict)
                or connection.get("target") != identity["target"]):
            return {"status": "FAIL", "error_code": "NATIVE_THREAD_IDENTITY_MISMATCH"}
        snapshot = snapshot.get("result")
    elif "error" in snapshot and "result" in snapshot:
        nested_error = snapshot.get("error")
        if nested_error:
            if nested_error == "Stored thread id/cwd does not match the requested workstream":
                return {"status": "FAIL", "error_code": "THREAD_WORKSTREAM_MISMATCH"}
            return {"status": "FAIL", "error_code": "CODEX_READ_FAILED"}
        snapshot = snapshot.get("result")
    if not isinstance(snapshot, dict):
        return {"status": "FAIL", "error_code": "CODEX_RESPONSE_INVALID"}
    if (snapshot.get("target") != identity["target"]
            or snapshot.get("cwd") != identity["cwd"]
            or snapshot.get("thread_id") != identity["thread_id"]):
        return {"status": "FAIL", "error_code": "NATIVE_THREAD_IDENTITY_MISMATCH"}
    thread_status = snapshot.get("thread_status")
    if (snapshot.get("source") != "native-app-server"
            or snapshot.get("native_state_authoritative") is not True
            or thread_status not in ("loaded", "notLoaded", "idle")):
        return {"status": "FAIL", "error_code": "NATIVE_THREAD_STATE_UNVERIFIED"}
    active_flags = snapshot.get("active_flags")
    if (not isinstance(active_flags, list) or active_flags
            or snapshot.get("unknown_active_flags") is not False):
        return {"status": "FAIL", "error_code": "NATIVE_THREAD_ACTIVITY_UNKNOWN"}
    if thread_status == "idle":
        latest_turn = snapshot.get("latest_turn")
        if (not isinstance(latest_turn, dict)
                or not isinstance(latest_turn.get("id"), str)
                or not re.fullmatch(
                    r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",
                    latest_turn["id"],
                )
                or latest_turn.get("status") != "completed"
                or latest_turn.get("error_code") is not None):
            return {"status": "FAIL", "error_code": "NATIVE_THREAD_STATE_UNVERIFIED"}
    return {"status": "PASS", "target": identity["target"]}


def _recovery_memoryd_absent():
    ids=run(['docker','ps','-aq']).decode().split()
    rows=json.loads(run(['docker','inspect',*ids])) if ids else []
    if not isinstance(rows,list) or len(rows)!=len(ids):
        raise ValueError('MemoryD container inventory is invalid')
    for row in rows:
        if (not isinstance(row,dict) or not isinstance(row.get('Name'),str)
                or not isinstance(row.get('Config'),dict)):
            raise ValueError('MemoryD container inventory is invalid')
        labels=row['Config'].get('Labels')
        if labels is None:labels={}
        if not isinstance(labels,dict):raise ValueError('MemoryD container labels are invalid')
        if (row['Name'].lstrip('/') in MEMORYD_SERVICES
                or labels.get('service') in MEMORYD_SERVICES
                or (labels.get('com.docker.compose.project')=='codex-control-plane'
                    and labels.get('com.docker.compose.service') in ('memoryd','memoryd-mcp'))):
            return False
    volumes=set(run(['docker','volume','ls','--format','{{.Name}}']).decode().split())
    return MEMORYD_VOLUME not in volumes


def smoke(request=None):
    request = request or {}
    if not isinstance(request, dict):
        raise ValueError("Smoke request is invalid")
    recovery=None
    if 'activation_id' in request:
        recovery=_activation_marker(request['activation_id'])
        if recovery.get('status')!='activating' or recovery.get('original_stopped_attested') is not True:
            raise ValueError('Recovery smoke requires an active authorized activation')
    require_native = request.get("require_native") is True
    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312',EXECUTOR_PAT_FILE=str(STATE/'secrets/executor-pat'))
    sys.path.insert(0,str(ROOT/'scripts'));import compose_control as c
    _,m=c.executor_session();c.verify_compact(m)
    profile=json.loads(private(STATE/'bootstrap/devsy-integration.json'))['profile'];c.read_devsy(m,profile)
    memoryd_discovery = 'UNREGISTERED'
    memoryd_restored=False
    captured=recovery is not None and recovery.get('memoryd',{}).get('status')=='captured'
    memoryd_marker = STATE / 'bootstrap/memoryd-integration.json'
    if captured and not (memoryd_marker.exists() or memoryd_marker.is_symlink()):
        raise ValueError('Captured MemoryD registration is missing')
    if memoryd_marker.exists() or memoryd_marker.is_symlink():
        private(memoryd_marker)
        if recovery is not None and _recovery_memoryd_absent():
            if captured:raise ValueError('Captured MemoryD provider is unavailable')
            memoryd_discovery = 'UNAVAILABLE'
        else:
            c.search_memoryd(m)
            memoryd_discovery = 'PASS'
            if captured:
                _verified_memoryd_restore(recovery)
                status_data=_memoryd_cli_json(['status','--local'])
                if (status_data.get('active_profiles')!=['personal']
                        or status_data.get('active_workspaces')!=['dakota-codex-only']
                        or _memoryd_record_count()!=recovery['memoryd']['record_count']):
                    raise ValueError('Restored MemoryD scope or record count changed')
                reads=c.probe_memoryd_reads(m)
                denials=c.probe_memoryd_denials(f"http://{NETWORK['gateway']}:8090/mcp")
                if (reads.get('status')!='PASS' or denials.get('write_blocked') is not True
                        or denials.get('scope_override_blocked') is not True):
                    raise ValueError('Restored MemoryD read-only checks failed')
                memoryd_restored=True
    supplied=request.get("native_codex")
    if supplied is None:
        native={"status":"UNCONFIGURED"}
    else:
        native=native_thread_read(c,m,supplied)
    if require_native and native["status"] != "PASS":
        if native["status"] == "UNCONFIGURED":
            raise ValueError("qualified native read is required")
        raise ValueError("qualified native read failed: " + native.get("error_code", "UNKNOWN"))
    result={'catalog':'PASS','native_read':native,'devsy_reads':'PASS',
            'memoryd_discovery':memoryd_discovery}
    if recovery is not None:
        recovery.update(memoryd_discovery=memoryd_discovery,memoryd_restored=memoryd_restored)
        write(STORE/'activation-in-progress.json',recovery)
        result['memoryd_restored']=memoryd_restored
    return result


def _devsy_bootstrap(data):
    if (not isinstance(data, dict) or not isinstance(data.get("policy"), dict)
            or not isinstance(data.get("unit_template"), str)
            or not isinstance(data.get("starter_source"), str)
            or len(data["unit_template"]) > 32768 or len(data["starter_source"]) > 8192):
        raise ValueError("Devsy bootstrap request is invalid")
    import grp
    import pwd
    from devsy_vm_bootstrap import VMDevsyBootstrap

    uid = os.getuid()
    profile = {
        "repo_dir": str(ROOT),
        "state_dir": str(STATE),
        "home": str(Path.home()),
        "devsy": DEVSY,
        "service_user": pwd.getpwuid(uid).pw_name,
        "service_group": grp.getgrgid(os.getgid()).gr_name,
        "uid": uid,
    }
    return VMDevsyBootstrap(
        profile, data["policy"], unit_template=data["unit_template"],
        starter_source=data["starter_source"],
    )


def compose_start():
    env=anonymous_docker_environment()
    env['DEVSY_MCP_ENABLED']='false'
    run(['sudo','-n','systemctl','stop','codex-control-plane-devsy'])
    run([str(ROOT/'scripts/control-plane-up')],900,env=env)
    run(['sudo','-n','systemctl','start','codex-control-plane-devsy'])
    return {'compose_started':True}


def devsy_start():
    """Restart the existing host bridge without rewriting bootstrap-managed state."""
    run(['sudo','-n','systemctl','restart','codex-control-plane-devsy'])
    return {'devsy':'PASS'}


def invocation_profile(argv=None):
    """Load a local operator profile or decode the controller's SSH payload."""
    argv=list(sys.argv if argv is None else argv)
    if argv and argv[0]=='-c':
        if len(argv)!=3:raise ValueError('Remote invocation requires an encoded instance profile')
        return argv[1],decode(argv[2])
    parser=argparse.ArgumentParser(description='Private control-plane VM operations')
    parser.add_argument('action')
    parser.add_argument('--instance-profile',help='Absolute path to an owned mode-0600 private instance profile')
    args=parser.parse_args(argv[1:])
    return args.action,load_instance_profile(args.instance_profile)


def main():
    action,instance=invocation_profile()
    configure_profile(instance)
    os.umask(0o077)
    if action=='lock':_ensure_private_state_store()
    elif action!='activation-plan' and action.startswith('activation-'):
        _verify_private_directory(STATE);_verify_private_directory(STORE)
    elif action not in ('activation-plan','memoryd-preflight','memoryd-health','memoryd-wait','memoryd-status','memoryd-inventory','memoryd-transfer-preflight','memoryd-executor-origin-check',
                        'devsy-plan','devsy-check','devsy-rollback-plan',
                        'devsy-tap-reconcile-plan','devsy-tap-reconcile',
                        'devsy-tap-rollback-plan','devsy-tap-rollback'):
        STORE.mkdir(mode=0o700,exist_ok=True)
    data=json.load(sys.stdin) if action in ('images','image-check','network','network-check','wait','commit','baseline','set-current','rollback-commit','restart-local','activation-plan','activation-preflight','activation-begin','activation-pull-images','activation-install','activation-track','activation-seed','activation-network','activation-identity','activation-cleanup','activation-record','activation-memoryd-wait','activation-memoryd-network','activation-memoryd-restore','smoke','memoryd-adapter-prepare','memoryd-adapter-finalize','memoryd-transfer-prepare','memoryd-import-bundles','memoryd-network-allow','memoryd-app-register','memoryd-registration-reconcile','memoryd-identity-reconcile','devsy-plan','devsy-check','devsy-rollback-plan','devsy-apply','devsy-rollback','devsy-scope-rebind-check','devsy-scope-rebind','devsy-bridge-path-check','devsy-bridge-path-apply','devsy-tap-reconcile-plan','devsy-tap-reconcile','devsy-tap-rollback-plan','devsy-tap-rollback') else {}
    if action == 'backup':
        raw = sys.stdin.read()
        data = json.loads(raw) if raw else {}
    if action=='activation-plan':result=activation_plan(data['generation_dir'])
    elif action=='activation-preflight':
        info=_ensure_empty_activation_target(data['generation_dir'],allow_lock=True)
        result={'ready':True,'expected_identity':info['expected_identity'],'prepared_manifest_sha256':info['manifest_sha256'],
                'memoryd':info['prepared'].get('memoryd',{'status':'legacy'})}
    elif action=='activation-begin':
        result=activation_begin(data['generation_dir'],data['prepared_manifest_sha256'],data['expected_identity'],data['activation_id'],data['original_stopped_attested'])
    elif action=='activation-pull-images':result=activation_pull_images(data['manifest'],data['activation_id'])
    elif action=='activation-install':result=activation_install(data['generation_dir'],data['prepared_manifest_sha256'],data['activation_id'])
    elif action=='activation-track':result=activation_track(data['activation_id'],data['service'])
    elif action=='activation-seed':result=activation_seed(data['generation_dir'],data['prepared_manifest_sha256'],data['manifest'],data['activation_id'])
    elif action=='activation-memoryd-restore':
        if set(data)!={'generation_dir','prepared_manifest_sha256','activation_id'}:raise ValueError('MemoryD recovery request is invalid')
        result=activation_memoryd_restore(data['generation_dir'],data['prepared_manifest_sha256'],data['activation_id'])
    elif action=='activation-network':result=activation_network(data['activation_id'])
    elif action=='activation-memoryd-network':result=activation_memoryd_network(data)
    elif action=='activation-identity':result=activation_identity(data['expected_identity'],data['activation_id'])
    elif action=='activation-memoryd-wait':result=memoryd_wait(activation_id=data['activation_id'])
    elif action=='activation-cleanup':result=activation_cleanup(data['activation_id'],data['attempted_services'])
    elif action=='activation-record':result=activation_record(data)
    elif action=='lock':
        fd=os.open(STORE/'deploy.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        s=os.fstat(fd)
        if s.st_uid!=os.getuid() or s.st_mode&0o777!=0o600:raise ValueError('Unsafe deployment lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('LOCKED',flush=True);sys.stdin.read();return
    elif action=='snapshot':result=snapshot()
    elif action=='status':result=status()
    elif action=='memoryd-preflight':result=memoryd_preflight()
    elif action=='memoryd-health':result=memoryd_health()
    elif action=='memoryd-pin-adapter-image':result=memoryd_pin_adapter_image()
    elif action=='memoryd-adapter-pin-check':result=memoryd_adapter_pin_check()
    elif action=='memoryd-executor-origin-check':result=memoryd_executor_origin_check()
    elif action=='memoryd-wait':result=memoryd_wait()
    elif action=='memoryd-status':result=memoryd_status()
    elif action=='memoryd-inventory':result=memoryd_inventory()
    elif action=='memoryd-adapter-prepare':result=memoryd_adapter_prepare(data)
    elif action=='memoryd-adapter-finalize':result=memoryd_adapter_finalize(data)
    elif action=='memoryd-transfer-preflight':result=memoryd_transfer_preflight()
    elif action=='memoryd-transfer-prepare':result=memoryd_transfer_prepare(data)
    elif action=='memoryd-import-bundles':result=memoryd_import_bundles(data)
    elif action=='memoryd-network-allow':result=memoryd_network_allow(data)
    elif action=='memoryd-app-register':result=register_memoryd_app(data)
    elif action=='memoryd-registration-check':
        _verify_registered_memoryd_app();result={'registration_verified':True}
    elif action=='memoryd-registration-reconcile':result=memoryd_reconcile_pending_registration(data)
    elif action=='memoryd-base-identity':result={'identity':identity(NAMES['kamal']['executor'],exclude_memoryd=True)}
    elif action=='memoryd-identity-reconcile':result=memoryd_reconcile_identity(data)
    elif action=='lifecycle-check':result=lifecycle_check()
    elif action=='identity-check':
        if identity(NAMES['kamal']['executor'])!=json.loads(private(STORE/'current.json'))['identity']:
            raise ValueError('Executor identity differs from recorded generation; tunnel start refused')
        result={'identity_preserved':True}
    elif action=='restart-local':
        owner,groups,_=inspect();name=data['service']
        if owner!='kamal' or name not in NAMES['kamal'] or not groups['kamal'][name]:raise ValueError('Break-glass restart requires an existing owned Kamal accessory')
        r=groups['kamal'][name]
        if r['Config'].get('Labels',{}).get('service')!=NAMES['kamal'][name]:raise ValueError('Accessory ownership mismatch')
        run(['docker','restart',r['Id']]);wait_service('kamal',name);result={'break_glass_restart':name,'health':'PASS'}
    elif action=='profile':validate_profile();result={'private_mounts':'PASS','active_provisioning':False}
    elif action=='anonymous-docker-config':result={'path':str(ensure_anonymous_docker_config())}
    elif action=='current':result=json.loads(private(STORE/'current.json')) if (STORE/'current.json').exists() else None
    elif action=='images':result={'image_provenance':'PASS','image_ids':images(data)}
    elif action=='image-check':result={'image_provenance':'PASS','image_ids':images(data,pull=False)}
    elif action=='network-check':result={'network_check':'PASS','existing_kamal_network':network_check(data)}
    elif action=='network':network(data);result={'network':'PASS'}
    elif action=='inventory':
        _,groups,_=inspect();result={'kamal_present':[key for key,r in groups['kamal'].items() if r]}
    elif action=='remove-kamal':
        _,groups,_=inspect()
        for name in ('tunnel','cas','schema-proxy','executor'):
            r=groups['kamal'][name]
            if r:
                if r['Config'].get('Labels',{}).get('service')!=NAMES['kamal'][name]:raise ValueError('Kamal container ownership mismatch')
                if r['State']['Running']:raise ValueError('Stop the owned Kamal container before removing it')
                run(['docker','rm',r['Id']])
        result={'kamal_containers_removed':True}
    elif action=='remove-network':
        ids=run(['docker','network','ls','--filter','name=^'+re.escape(NETWORK['name'])+'$','-q']).decode().split()
        if ids:
            r=json.loads(run(['docker','network','inspect',*ids]))[0]
            if r.get('Labels',{}).get('mcp-control-plane.owner')=='kamal' and not r.get('Containers'):run(['docker','network','rm',r['Id']])
        result={'network_removed':True}
    elif action=='wait':wait_service(data['owner'],data['service']);result={'health':'PASS'}
    elif action=='backup':
        if data not in ({}, {'include_memoryd': True}):
            raise ValueError('Backup request is invalid')
        result=backup(include_memoryd=data.get('include_memoryd', False))
    elif action=='backup-cas':result=backup_cas()
    elif action=='smoke':result=smoke(data)
    elif action in ('devsy-bridge-path-check','devsy-bridge-path-apply'):
        from bridge_kubectl_path import BridgeKubectlPath
        expected={'policy','unit_template','starter_source','approval','scope_document'}
        if action=='devsy-bridge-path-apply':expected|={'approved','controller_sha'}
        if set(data)!=expected:raise ValueError('Bridge PATH repair request is invalid')
        repair=BridgeKubectlPath(_devsy_bootstrap(data),data['approval'],data['scope_document'],snapshot)
        result=(repair.plan() if action=='devsy-bridge-path-check' else
                repair.apply(approved=data['approved'],controller_sha=data['controller_sha']))
    elif action in ('devsy-scope-rebind-check','devsy-scope-rebind'):
        from scope_binding_rebind import ScopeBindingRebind
        expected={'policy','unit_template','starter_source','approval','scope_document'}
        if action=='devsy-scope-rebind':expected|={'approved','controller_sha'}
        if set(data)!=expected:raise ValueError('Scope binding repair request is invalid')
        repair=ScopeBindingRebind(_devsy_bootstrap(data),data['approval'],data['scope_document'],snapshot)
        result=(repair.plan() if action=='devsy-scope-rebind-check' else
                repair.apply(approved=data['approved'],controller_sha=data['controller_sha']))
    elif action=='devsy-plan':result=_devsy_bootstrap(data).plan()
    elif action=='devsy-check':result=_devsy_bootstrap(data).assert_current()
    elif action=='devsy-rollback-plan':result=_devsy_bootstrap(data).rollback_plan()
    elif action=='devsy-tap-reconcile-plan':result=_devsy_bootstrap(data).tap_reconciliation_plan()
    elif action=='devsy-tap-rollback-plan':
        if set(data)!={"policy","unit_template","starter_source","github_run_id","github_run_attempt"}:
            raise ValueError('Tap rollback plan request is invalid')
        result=_devsy_bootstrap(data).tap_reconciliation_rollback_plan(
            github_run_id=data['github_run_id'],github_run_attempt=data['github_run_attempt'])
    elif action=='devsy-tap-reconcile':
        if set(data)!={"policy","unit_template","starter_source","approved","source_sha","github_run_id","github_run_attempt"}:
            raise ValueError('Tap reconciliation request is invalid')
        result=_devsy_bootstrap(data).reconcile_tap(
            approved=data['approved'],source_sha=data['source_sha'],
            github_run_id=data['github_run_id'],github_run_attempt=data['github_run_attempt'])
    elif action=='devsy-tap-rollback':
        if set(data)!={"policy","unit_template","starter_source","approved","github_run_id","github_run_attempt"}:
            raise ValueError('Tap rollback request is invalid')
        result=_devsy_bootstrap(data).rollback_tap_reconciliation(
            approved=data['approved'],github_run_id=data['github_run_id'],
            github_run_attempt=data['github_run_attempt'])
    elif action=='devsy-apply':
        if set(data) != {"policy", "unit_template", "starter_source", "approved", "source_sha"}:
            raise ValueError("Devsy apply request is invalid")
        result=_devsy_bootstrap(data).apply(approved=data["approved"],source_sha=data["source_sha"])
    elif action=='devsy-rollback':result=_devsy_bootstrap(data).rollback()
    elif action=='compose-stop':
        run(['sudo','-n','systemctl','stop','codex-control-plane-devsy']);run([str(ROOT/'scripts/control-plane-down')]);result={'compose_stopped':True}
    elif action=='compose-start':
        result=compose_start()
    elif action=='devsy-start':
        result=devsy_start()
    elif action=='devsy-stop':
        run(['sudo','-n','systemctl','stop','codex-control-plane-devsy']);result={'devsy_stopped':True}
    elif action=='devsy-ensure':
        run(['sudo','-n','systemctl','start','codex-control-plane-devsy']);result={'devsy_started':True}
    elif action=='devsy-restore':
        run(['sudo','-n','systemctl','stop','codex-control-plane-devsy'])
        old=STORE/'start-host-devsy.before-kamal.py'
        if old.exists():
            starter=STATE/'start-host-devsy.py';starter.write_bytes(private(old));starter.chmod(0o700)
        result={'devsy_starter_restored':True}
    elif action=='commit':
        if (STORE/'current.json').exists():write(STORE/'previous.json',json.loads(private(STORE/'current.json')))
        write(STORE/'current.json',data);result={'generation_committed':True}
    elif action=='baseline':
        if (STORE/'current.json').exists():raise ValueError('Baseline already exists')
        write(STORE/'current.json',data);result={'baseline_recorded':True}
    elif action=='set-current':write(STORE/'current.json',data);result={'generation_restored':True}
    elif action=='rollback-commit':
        write(STORE/'previous.json',data['previous']);write(STORE/'current.json',data['current']);result={'rollback_committed':True}
    elif action=='previous':result=json.loads(private(STORE/'previous.json')) if (STORE/'previous.json').exists() else None
    elif action=='rollback-target':
        path=STORE/'previous.json' if (STORE/'previous.json').exists() else STORE/'current.json'
        result=json.loads(private(path))
    else:raise ValueError('Unknown VM operation')
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except Exception as error:
        detail=str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__
        print('Deployment boundary refused: '+detail,file=sys.stderr);sys.exit(1)
