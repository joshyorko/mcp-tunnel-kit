#!/usr/bin/env python3
"""Private VM deployment boundary. JSON output contains no credential values."""
import fcntl
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path('/home/kdlocpanda/Projects/mcp-tunnel-kit')
STATE = Path('/home/kdlocpanda/.local/share/codex-control-plane')
STORE = STATE / 'deployment'
PUBLIC_DOCKER_CONFIG = STORE / 'anonymous-docker-config'
NAMES = {'compose': {'executor':'codex-control-plane-executor-1','schema-proxy':'codex-control-plane-executor-schema-proxy-1','cas':'codex-control-plane-codex-action-server-1','tunnel':'codex-control-plane-tunnel-client-1'},
         'kamal': {name:'mcp-control-plane-'+name for name in ('executor','schema-proxy','cas','tunnel')}}


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


def validate_profile():
    for relative in ('cas-targets.json','devsy-operator/config.yaml','ror/operator-kubeconfig.json'):
        private(STATE/relative)
    ssh=Path('/home/kdlocpanda/.local/share/issue16-dakota-ssh')
    for name in ('ssh_config.native','known_hosts.native','identity'):private(ssh/name)
    for relative in ('cas','cas/runtime','cas/receipts','devsy-operator/contexts/default'):
        path=STATE/relative;s=path.lstat()
        if not path.is_dir() or path.is_symlink() or s.st_uid!=os.getuid():raise ValueError('Required VM bind directory missing or wrong owner')
    for path in (STATE/'devsy-bridge/scoped-jobs').glob('*.json'):
        record=json.loads(private(path))
        if not path.name.startswith('history-') and record.get('status') in ('accepted','running'):
            raise ValueError('Active scoped provisioning must finish before deployment')


def images(manifest, pull=True):
    repos={'cas':'ghcr.io/joshyorko/codex-action-server','schema_proxy':'ghcr.io/joshyorko/codex-action-server','executor':'ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12','tunnel':'ghcr.io/openai/tunnel-client:v0.0.15'}
    if set(manifest['images'])!=set(repos): raise ValueError('Image set mismatch')
    for name,want in manifest['images'].items():
        if want['repository']!=repos[name] or not re.fullmatch(r'sha256:[0-9a-f]{64}',want['digest']): raise ValueError('Unapproved image reference')
    result={}
    pull_env=anonymous_docker_environment() if pull else None
    for name,want in manifest['images'].items():
        ref=want['repository']+'@'+want['digest']
        if pull:run(['docker','pull','--platform','linux/amd64',ref],600,env=pull_env)
        r=json.loads(run(['docker','image','inspect',ref]))[0]
        if r['Architecture']!='amd64' or r['Os']!='linux': raise ValueError('Image architecture mismatch')
        if name in ('cas','schema_proxy') and (not re.fullmatch('[0-9a-f]{40}',want.get('revision','')) or r['Config'].get('Labels',{}).get('org.opencontainers.image.revision')!=want['revision']): raise ValueError('CAS source provenance mismatch')
        result[name]=r['Id']
    return result


def network_check(want):
    if want!={'name':'mcp-control-plane','subnet':'172.30.86.0/24','gateway':'172.30.86.1'}: raise ValueError('Unapproved network')
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


def wait_service(owner,name):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        r=json.loads(run(['docker','inspect',NAMES[owner][name]]))[0]
        if r['State'].get('Health',{}).get('Status')=='healthy': return
        time.sleep(3)
    raise ValueError('Managed service health deadline failed: '+name)


def backup():
    owner,groups,_=inspect();cid=groups[owner]['executor']['Id']
    directory=STORE/'backups'/str(time.time_ns());directory.mkdir(mode=0o700,parents=True)
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
    databases=directory/'cas-databases';databases.mkdir(mode=0o700)
    for source in (STATE/'cas/runtime').rglob('*.db'):
        if source.name not in ('server.db','workitems.db'):continue
        target=databases/(hashlib.sha256(str(source).encode()).hexdigest()[:12]+'-'+source.name)
        with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as original,sqlite3.connect(target) as copy:
            original.backup(copy)
        target.chmod(0o600)
    with (directory/'essential.tar').open('xb') as output:
        with tarfile.open(fileobj=output,mode='w') as archive:
            for rel in ('secrets','bootstrap','cas-targets.json','cas/dynamic-targets.json','owner-devsy-scope','ror','devsy-bridge/scoped-jobs','devsy-bridge/creation-receipts'):
                f=STATE/rel
                if f.exists(): archive.add(f,arcname=rel)
            archive.add(ROOT/'.env',arcname='compose.env')
            archive.add(databases,arcname='cas-databases')
    (directory/'essential.tar').chmod(0o600)
    return {'backup':str(directory),'executor_sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()}


def backup_cas():
    directory=STORE/'backups'/('cas-'+str(time.time_ns()));directory.mkdir(mode=0o700,parents=True)
    databases=directory/'databases';databases.mkdir(mode=0o700)
    for source in (STATE/'cas/runtime').rglob('*.db'):
        if source.name not in ('server.db','workitems.db'):continue
        target=databases/(hashlib.sha256(str(source).encode()).hexdigest()[:12]+'-'+source.name)
        with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as original,sqlite3.connect(target) as copy:original.backup(copy)
        target.chmod(0o600)
    archive=directory/'cas-essential.tar'
    with tarfile.open(archive,'x') as output:
        for relative in ('cas-targets.json','cas/dynamic-targets.json','owner-devsy-scope','devsy-bridge/scoped-jobs','devsy-bridge/creation-receipts'):
            path=STATE/relative
            if path.exists():output.add(path,arcname=relative)
        output.add(databases,arcname='databases')
    archive.chmod(0o600)
    return {'cas_backup':str(directory),'executor_untouched':True}


def smoke():
    os.environ.update(EXECUTOR_URL='http://127.0.0.1:4312',EXECUTOR_PAT_FILE=str(STATE/'secrets/executor-pat'))
    sys.path.insert(0,str(ROOT/'scripts'));import compose_control as c
    _,m=c.executor_session();c.verify_compact(m)
    payload={'target':'local','cwd':'/home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit','thread_id':'01a12bba-9641-79c1-9b29-93136f976fa6','include_turns':False}
    r=c.execution(m.call('tools/call',{'name':'execute','arguments':{'code':'return await tools.codex.read_thread('+json.dumps({'payload':payload})+');'}}))
    v=r['execution']['value']['structuredContent']
    if not r['execution']['ok'] or v.get('error') is not None: raise ValueError('Native exact-thread read failed')
    profile=json.loads(private(STATE/'bootstrap/devsy-integration.json'))['profile'];c.read_devsy(m,profile)
    return {'catalog':'PASS','native_read':'PASS','devsy_reads':'PASS'}


def compose_start():
    env=anonymous_docker_environment()
    env['DEVSY_MCP_ENABLED']='false'
    run(['sudo','-n','systemctl','stop','codex-control-plane-devsy'])
    run([str(ROOT/'scripts/control-plane-up')],900,env=env)
    run(['sudo','-n','systemctl','start','codex-control-plane-devsy'])
    return {'compose_started':True}


def main():
    os.umask(0o077);STORE.mkdir(mode=0o700,exist_ok=True)
    action=sys.argv[1];data=json.load(sys.stdin) if action in ('images','image-check','network','network-check','wait','commit','baseline','set-current','rollback-commit','restart-local') else {}
    if action=='lock':
        fd=os.open(STORE/'deploy.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        s=os.fstat(fd)
        if s.st_uid!=os.getuid() or s.st_mode&0o777!=0o600:raise ValueError('Unsafe deployment lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('LOCKED',flush=True);sys.stdin.read();return
    if action=='snapshot':result=snapshot()
    elif action=='status':result=status()
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
        ids=run(['docker','network','ls','--filter','name=^mcp-control-plane$','-q']).decode().split()
        if ids:
            r=json.loads(run(['docker','network','inspect',*ids]))[0]
            if r.get('Labels',{}).get('mcp-control-plane.owner')=='kamal' and not r.get('Containers'):run(['docker','network','rm',r['Id']])
        result={'network_removed':True}
    elif action=='wait':wait_service(data['owner'],data['service']);result={'health':'PASS'}
    elif action=='backup':result=backup()
    elif action=='backup-cas':result=backup_cas()
    elif action=='smoke':result=smoke()
    elif action=='compose-stop':
        run(['sudo','-n','systemctl','stop','codex-control-plane-devsy']);run([str(ROOT/'scripts/control-plane-down')]);result={'compose_stopped':True}
    elif action=='compose-start':
        result=compose_start()
    elif action=='devsy-start':
        helper=ROOT/'scripts/host_devsy_service.py'
        starter=STATE/'start-host-devsy.py';old=STATE/'deployment/start-host-devsy.before-kamal.py'
        if not old.exists():old.write_bytes(starter.read_bytes());old.chmod(0o600)
        starter.write_text('import runpy\nrunpy.run_path('+repr(str(helper))+', run_name="__main__")\n');starter.chmod(0o700)
        run(['sudo','-n','systemctl','restart','codex-control-plane-devsy']);result={'devsy':'PASS'}
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
    elif action=='previous':result=json.loads(private(STORE/'previous.json'))
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
