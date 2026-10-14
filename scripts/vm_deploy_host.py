#!/usr/bin/env python3
"""Private VM deployment boundary. JSON output contains no credential values."""
import fcntl
import argparse
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
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


def write(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_mode & 0o077: raise ValueError('Deployment directory is not private')
    temp = path.with_suffix('.new')
    fd = os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f: json.dump(value,f); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)


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


def identity(executor):
    from urllib.request import Request,urlopen
    pat = private(STATE/'secrets/executor-pat').decode().strip()
    def get(path):
        with urlopen(Request('http://127.0.0.1:4312'+path,headers={'Authorization':'Bearer '+pat}),timeout=15) as r: return json.load(r)
    context=get('/api/context');org=context['organization'];apps=get('/api/organizations/'+org+'/inventory')['apps']
    proof={'organization':org,'apps':sorted((x['id'],x['slug']) for x in apps),'keys':{},'secrets':{}}
    for name in ('auth-secret.key','encryption.key','install-id'):
        raw=run(['docker','cp',executor+':/app/data/'+name,'-'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive: data=archive.extractfile(archive.getmembers()[0]).read()
        proof['keys'][name]=hashlib.sha256(data).hexdigest()
    for name in ('control-plane-api-key','control-plane-tunnel-id','executor-auth-header','executor-pat'):
        proof['secrets'][name]=hashlib.sha256(private(STATE/'secrets'/name)).hexdigest()
    return hashlib.sha256(json.dumps(proof,sort_keys=True).encode()).hexdigest()


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
    return (name in known_names or name.startswith('mcp-recovery-seed-')
            or labels.get('com.docker.compose.project')=='codex-control-plane'
            or labels.get('service') in set(NAMES['kamal'].values())
            or 'executor-selfhost' in image or 'tunnel-client' in image
            or any(mount.get('Name')=='codex-control-plane_executor-data' for mount in mounts))


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
    if network_check(NETWORK):raise ValueError('Replacement VM already has the private control-plane network')
    unit=run(['systemctl','show','--property=LoadState','--value','codex-control-plane-devsy']).decode().strip()
    if unit!='loaded':raise ValueError('Replacement VM Devsy systemd unit is unavailable')
    return {**prepared,'repo_source_sha':source,'container_count':len(rows),'network':'absent'}


def activation_plan(generation_dir):
    info=_ensure_empty_activation_target(generation_dir,allow_lock=False)
    return {'ready':True,'generation':info['generation'],'expected_identity':info['expected_identity'],
            'prepared_manifest_sha256':info['manifest_sha256'],'inventory_count':len(info['prepared']['inventory']),
            'repo_source_sha':info['repo_source_sha']}


def _activation_marker(activation_id, *, allow_completed=False):
    if not isinstance(activation_id,str) or not re.fullmatch('[a-f0-9]{32}',activation_id):
        raise ValueError('Activation ID is invalid')
    marker=json.loads(private(STORE/'activation-in-progress.json'))
    if (not isinstance(marker,dict) or marker.get('schema_version')!=1
            or marker.get('activation_id')!=activation_id
            or marker.get('status') not in (('installing','activating','activated') if allow_completed else ('installing','activating'))):
        raise ValueError('Activation ID does not own the current recovery operation')
    return marker


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
            'started_services':[]}
    write(marker_path,marker)
    return {'activation_started':True}


def activation_track(activation_id,service):
    marker=_activation_marker(activation_id)
    if service not in NAMES['kamal']:raise ValueError('Activation service is unsupported')
    matching=[row for row in _activation_container_rows()
              if row.get('Name','').lstrip('/')==NAMES['kamal'][service]]
    if len(matching)!=1 or matching[0].get('Config',{}).get('Labels',{}).get('service')!=NAMES['kamal'][service]:
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


def activation_pull_images(manifest):
    with tempfile.TemporaryDirectory(prefix='mcp-activation-docker-') as root:
        config=Path(root)/'config.json'
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(b'{}\n')
        env=os.environ.copy();env.pop('DOCKER_AUTH_CONFIG',None);env['DOCKER_CONFIG']=root
        return {'image_ids':images(manifest,pull=True,pull_env=env),'pulled':True}


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


def activation_identity(expected_identity,activation_id):
    marker=_activation_marker(activation_id)
    if marker['expected_identity']!=expected_identity:raise ValueError('Activation identity does not match its private operation marker')
    actual=identity(NAMES['kamal']['executor'])
    if actual!=expected_identity:raise ValueError('Recovered Executor identity did not match the captured identity')
    return {'identity_preserved':True}


def activation_cleanup(activation_id,attempted_services):
    marker=_activation_marker(activation_id,allow_completed=True)
    if (not isinstance(attempted_services,list)
            or any(service not in NAMES['kamal'] for service in attempted_services)):
        raise ValueError('Activation cleanup service set is invalid')
    allowed=set(marker['started_services'])|set(attempted_services)
    rows=_activation_container_rows()
    selected=[]
    for row in rows:
        name=row.get('Name','').lstrip('/')
        service=next((key for key,value in NAMES['kamal'].items() if value==name),None)
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
    return {'new_accessories_removed':len(selected),'recovered_state_preserved':True,'executor_volume_preserved':True}


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


def backup():
    validate_profile()
    source_sha=recorded_runtime_source_sha()
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
    return {'backup':str(directory),'executor_sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()}


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
    if target != "local" or not isinstance(cwd, str) or not isinstance(thread_id, str):
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
    if (snapshot.get("source") != "native-app-server"
            or snapshot.get("native_state_authoritative") is not True
            or snapshot.get("thread_status") not in ("loaded", "notLoaded")):
        return {"status": "FAIL", "error_code": "NATIVE_THREAD_STATE_UNVERIFIED"}
    active_flags = snapshot.get("active_flags")
    if (not isinstance(active_flags, list) or active_flags
            or snapshot.get("unknown_active_flags") is not False):
        return {"status": "FAIL", "error_code": "NATIVE_THREAD_ACTIVITY_UNKNOWN"}
    return {"status": "PASS", "target": identity["target"]}


def smoke(request=None):
    request = request or {}
    if not isinstance(request, dict):
        raise ValueError("Smoke request is invalid")
    require_native = request.get("require_native") is True
    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312',EXECUTOR_PAT_FILE=str(STATE/'secrets/executor-pat'))
    sys.path.insert(0,str(ROOT/'scripts'));import compose_control as c
    _,m=c.executor_session();c.verify_compact(m)
    profile=json.loads(private(STATE/'bootstrap/devsy-integration.json'))['profile'];c.read_devsy(m,profile)
    supplied=request.get("native_codex")
    if supplied is None:
        native={"status":"UNCONFIGURED"}
    else:
        native=native_thread_read(c,m,supplied)
    if require_native and native["status"] != "PASS":
        if native["status"] == "UNCONFIGURED":
            raise ValueError("qualified Dakota native read is required")
        raise ValueError("qualified Dakota native read failed: " + native.get("error_code", "UNKNOWN"))
    return {'catalog':'PASS','native_read':native,'devsy_reads':'PASS'}


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
    elif action not in ('activation-plan','devsy-plan','devsy-check','devsy-rollback-plan',
                        'devsy-tap-reconcile-plan','devsy-tap-reconcile',
                        'devsy-tap-rollback-plan','devsy-tap-rollback'):
        STORE.mkdir(mode=0o700,exist_ok=True)
    data=json.load(sys.stdin) if action in ('images','image-check','network','network-check','wait','commit','baseline','set-current','rollback-commit','restart-local','activation-plan','activation-preflight','activation-begin','activation-pull-images','activation-install','activation-track','activation-seed','activation-network','activation-identity','activation-cleanup','activation-record','smoke','devsy-plan','devsy-check','devsy-rollback-plan','devsy-apply','devsy-rollback','devsy-scope-rebind-check','devsy-scope-rebind','devsy-tap-reconcile-plan','devsy-tap-reconcile','devsy-tap-rollback-plan','devsy-tap-rollback') else {}
    if action=='activation-plan':result=activation_plan(data['generation_dir'])
    elif action=='activation-preflight':
        info=_ensure_empty_activation_target(data['generation_dir'],allow_lock=True)
        result={'ready':True,'expected_identity':info['expected_identity'],'prepared_manifest_sha256':info['manifest_sha256']}
    elif action=='activation-begin':
        result=activation_begin(data['generation_dir'],data['prepared_manifest_sha256'],data['expected_identity'],data['activation_id'],data['original_stopped_attested'])
    elif action=='activation-pull-images':
        _activation_marker(data['activation_id']);result=activation_pull_images(data['manifest'])
    elif action=='activation-install':result=activation_install(data['generation_dir'],data['prepared_manifest_sha256'],data['activation_id'])
    elif action=='activation-track':result=activation_track(data['activation_id'],data['service'])
    elif action=='activation-seed':result=activation_seed(data['generation_dir'],data['prepared_manifest_sha256'],data['manifest'],data['activation_id'])
    elif action=='activation-network':result=activation_network(data['activation_id'])
    elif action=='activation-identity':result=activation_identity(data['expected_identity'],data['activation_id'])
    elif action=='activation-cleanup':result=activation_cleanup(data['activation_id'],data['attempted_services'])
    elif action=='activation-record':
        marker=_activation_marker(data.get('activation_id'))
        if (set(data)!={'activation_id','source_sha','expected_identity','identity_preserved','original_stopped_attested'}
                or data['identity_preserved'] is not True or data['original_stopped_attested'] is not True
                or not re.fullmatch('[a-f0-9]{40}',data['source_sha'])
                or not isinstance(data['expected_identity'],str)
                or data['source_sha']!=marker['source_sha'] or data['expected_identity']!=marker['expected_identity']):
            raise ValueError('Activation receipt input is invalid')
        marker['status']='activated';write(STORE/'activation-in-progress.json',marker)
        receipt={**data,'schema_version':1,'recorded_at_ns':time.time_ns()}
        if (STORE/'recovery-activation.json').exists():raise ValueError('Activation receipt already exists')
        write(STORE/'recovery-activation.json',receipt)
        result={'activation_recorded':True}
    elif action=='lock':
        fd=os.open(STORE/'deploy.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        s=os.fstat(fd)
        if s.st_uid!=os.getuid() or s.st_mode&0o777!=0o600:raise ValueError('Unsafe deployment lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('LOCKED',flush=True);sys.stdin.read();return
    elif action=='snapshot':result=snapshot()
    elif action=='status':result=status()
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
    elif action=='backup':result=backup()
    elif action=='backup-cas':result=backup_cas()
    elif action=='smoke':result=smoke(data)
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
