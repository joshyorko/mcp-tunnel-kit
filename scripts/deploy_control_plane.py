#!/usr/bin/env python3
"""Trusted runner -> Kamal accessories -> private VM operations."""
import argparse
import base64
import contextlib
import copy
import json
import hashlib
import os
from pathlib import Path
import re
import select
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zlib

from kamal_model import render,validate_manifest
from image_provenance import verify as verify_provenance
from instance_profile import DEFAULT_PATH as DEFAULT_INSTANCE_PROFILE, encode as encode_instance_profile, load as load_instance_profile
ROOT=Path(__file__).resolve().parents[1]
DEFAULT_SSH=Path.home()/'.local/share/mcp-control-plane-deploy/ssh_config'
DEFAULT_KEY=DEFAULT_SSH.parent/'identity'
DEFAULT_KNOWN=DEFAULT_SSH.parent/'known_hosts'
SSH=DEFAULT_SSH
KEY=DEFAULT_KEY
KNOWN=DEFAULT_KNOWN
LOCAL_CONFIGURED=False
HOST=None
ORDER=('executor','schema-proxy','cas','tunnel')
VMROOT=None
VM_HOST_PIN=None
INSTANCE=None


def configure_instance(value):
    """Apply an already validated private profile before any VM transport."""
    global HOST,VMROOT,VM_HOST_PIN,INSTANCE
    candidate=load_instance_profile(value) if isinstance(value,(str,Path)) or value is None else value
    from instance_profile import validate
    INSTANCE=validate(candidate)
    HOST=INSTANCE['deploy_host']['alias']
    VMROOT=INSTANCE['vm']['repo_dir']
    VM_HOST_PIN=INSTANCE['deploy_host']['host_key_fingerprint']
    return INSTANCE


def trusted_context(env, local=False):
    if INSTANCE is None:raise ValueError('Private instance profile must be loaded before deployment')
    if not (local and LOCAL_CONFIGURED):
        if socket.gethostname()!='pi5-01' or os.uname().machine!='aarch64':raise ValueError('Deployment must run on the approved ARM64 Pi')
        if not local and (LOCAL_CONFIGURED or env.get('GITHUB_REPOSITORY')!='joshyorko/mcp-tunnel-kit' or env.get('GITHUB_REF')!='refs/heads/main' or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch' or env.get('RUNNER_NAME')!='pi5-01-mcp-control-plane'):
            raise ValueError('Untrusted workflow/runner context')
    for p in (SSH,KEY,KNOWN):
        s=p.lstat()
        if p.is_symlink() or not p.is_file() or s.st_uid!=os.getuid() or s.st_mode&0o777!=0o600:raise ValueError('Runner SSH file ownership/mode mismatch')
    validate_ssh_config(SSH,KEY,KNOWN)


def _read_private_file(path, limit=16384):
    try:
        metadata=path.lstat()
        if (path.is_symlink() or not path.is_file() or metadata.st_uid!=os.getuid()
                or metadata.st_mode&0o777!=0o600):raise ValueError('Local deployment file ownership/mode mismatch')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.getuid() or opened.st_mode&0o777!=0o600:
            os.close(fd);raise ValueError('Local deployment file ownership/mode mismatch')
        with os.fdopen(fd,'rb') as stream: data=stream.read(limit+1)
        if len(data)>limit:raise ValueError('Local deployment file is too large')
        return data.decode('utf-8')
    except (OSError,UnicodeError):
        raise ValueError('Local deployment file is unavailable or invalid') from None


def configure_local(path, profile_path=None):
    """Explicitly load a private local SSH path file for the Dakota CLI."""
    global SSH,KEY,KNOWN,LOCAL_CONFIGURED,INSTANCE,HOST,VMROOT,VM_HOST_PIN
    LOCAL_CONFIGURED=False
    INSTANCE=None;HOST=None;VMROOT=None;VM_HOST_PIN=None
    SSH,KEY,KNOWN=DEFAULT_SSH,DEFAULT_KEY,DEFAULT_KNOWN
    config_path=Path(path)
    if not config_path.is_absolute():raise ValueError('Local config path must be absolute')
    values={}
    for raw in _read_private_file(config_path).splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):continue
        name,separator,value=line.partition('=')
        if not separator or name not in {'KAMAL_SSH_CONFIG','KAMAL_SSH_KEY','KAMAL_KNOWN_HOSTS','KAMAL_INSTANCE_PROFILE'} or name in values:
            raise ValueError('Local deployment config has an invalid key set')
        try:parts=shlex.split(value,comments=True,posix=True)
        except ValueError:raise ValueError('Local deployment config has invalid quoting') from None
        if len(parts)!=1 or not parts[0]:raise ValueError('Local deployment config value is invalid')
        values[name]=Path(parts[0])
    if not {'KAMAL_SSH_CONFIG','KAMAL_SSH_KEY','KAMAL_KNOWN_HOSTS'} <= set(values):
        raise ValueError('Local deployment config is incomplete')
    config,key,known=(values['KAMAL_SSH_CONFIG'],values['KAMAL_SSH_KEY'],values['KAMAL_KNOWN_HOSTS'])
    if any(not value.is_absolute() for value in (config,key,known)):
        raise ValueError('Local SSH references must be absolute paths')
    for reference in (config,key,known):_read_private_file(reference)
    profile_reference=Path(profile_path or values.get('KAMAL_INSTANCE_PROFILE',DEFAULT_INSTANCE_PROFILE))
    if not profile_reference.is_absolute():raise ValueError('Instance profile path must be absolute')
    configure_instance(profile_reference)
    validate_ssh_config(config,key,known)
    SSH,KEY,KNOWN=config,key,known
    LOCAL_CONFIGURED=True
    return {'ssh_config':str(SSH),'ssh_key':str(KEY),'known_hosts':str(KNOWN)}


def validate_ssh_config(config,key,known,instance=None):
    instance=instance or INSTANCE
    if instance is None:raise ValueError('Private instance profile must be loaded before SSH validation')
    deploy_host=instance['deploy_host']
    expected={'host':deploy_host['alias'],'hostname':deploy_host['address'],'user':deploy_host['user'],'identityfile':str(key),'identitiesonly':'yes','batchmode':'yes','forwardagent':'no','stricthostkeychecking':'yes','userknownhostsfile':str(known),'globalknownhostsfile':'/dev/null','preferredauthentications':'publickey'}
    actual={}
    for line in config.read_text().splitlines():
        fields=shlex.split(line,comments=True)
        if not fields:continue
        if len(fields)!=2 or fields[0].lower() in actual:raise ValueError('Ambiguous runner SSH configuration')
        actual[fields[0].lower()]=fields[1]
    if actual!=expected:raise ValueError('Runner SSH configuration changed or is not strictly pinned')
    fields=known.read_text().split()
    if len(fields)!=3 or fields[0]!=deploy_host['alias']+','+deploy_host['address'] or fields[1]!='ssh-ed25519':raise ValueError('Unexpected VM host-key record')
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(fields[2],validate=True)).digest()).decode().rstrip('=')
    if fingerprint!=deploy_host['host_key_fingerprint']:raise ValueError('VM SSH fingerprint mismatch')


def ssh_args(command):
    if INSTANCE is None:raise ValueError('Private instance profile must be loaded before SSH transport')
    return ['ssh','-F',str(SSH),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no',HOST,command]


def remote(action,data=None):
    source=remote_source()
    argv=ssh_args(shlex.join(['python3','-c',source,action,encode_instance_profile(INSTANCE)]))
    r=subprocess.run(argv,input='' if data is None else json.dumps(data),text=True,capture_output=True,timeout=900)
    if r.returncode:raise RuntimeError('VM '+action+' refused; '+r.stderr.strip()[:300])
    return json.loads(r.stdout)


@contextlib.contextmanager
def lock():
    source=remote_source()
    p=subprocess.Popen(ssh_args(shlex.join(['python3','-c',source,'lock',encode_instance_profile(INSTANCE)])),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        if not select.select([p.stdout],[],[],15)[0] or p.stdout.readline().strip()!='LOCKED':raise RuntimeError('VM deployment lock unavailable')
        yield
        if p.poll() is not None:raise RuntimeError('VM deployment lock connection was lost')
    finally:
        p.stdin.close()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=5)


def remote_source():
    bootstrap='import sys,types\n'
    for name in ('instance_profile','prepare_recovery_generation'):
        source=(ROOT/'scripts'/(name+'.py')).read_text()
        bootstrap+=('_module=types.ModuleType('+repr(name)+')\n'
                    +'_module.__file__='+repr(str(ROOT/'scripts'/(name+'.py')))+'\n'
                    +'sys.modules['+repr(name)+']=_module\n'
                    +'exec('+repr(source)+',_module.__dict__)\n')
    source=bootstrap+(ROOT/'scripts/vm_deploy_host.py').read_text()
    payload=base64.b64encode(zlib.compress(source.encode(),9)).decode()
    return f"import base64,zlib;exec(compile(zlib.decompress(base64.b64decode({payload!r})), '<mcp-private-vm>', 'exec'))"


def profile():
    if INSTANCE is None:raise ValueError('Private instance profile must be loaded before rendering deployment configuration')
    vm=INSTANCE['vm'];native=Path(vm['native_ssh_dir']);devsy=vm['devsy']
    return {'host':HOST,'network':vm['network'],'ssh_user':INSTANCE['deploy_host']['user'],'ssh_key':str(KEY),'ssh_known_hosts':str(KNOWN),'ssh_config':str(SSH),'state_dir':vm['state_dir'],'repo_dir':VMROOT,
            'cas_ssh_config_source':str(native/'ssh_config.native'),'cas_ssh_known_hosts_source':str(native/'known_hosts.native'),'cas_identity_source':str(native/'identity'),
            'devsy':devsy}


def kamal(config,operation,name):
    # Public images only. Never run the unrelated top-level app/proxy/registry commands.
    if operation not in ('boot','reboot','start','stop','details') or name not in ORDER:raise ValueError('Unsupported Kamal operation')
    docker_config=remote('anonymous-docker-config')['path']
    env={**os.environ,'BUNDLE_GEMFILE':str(ROOT/'Gemfile.deploy'),'KAMAL_PUBLIC_DOCKER_CONFIG':docker_config}
    r=subprocess.run(['bundle','exec','ruby',str(ROOT/'scripts/kamal_anonymous.rb'),'accessory',operation,name,'--config-file',str(config)],env=env,capture_output=True,text=True,timeout=300)
    if r.returncode:raise RuntimeError('Kamal accessory '+operation+' '+name+' failed; raw output withheld')


def configuration(directory,manifest):
    p=Path(directory)/'deploy.yml';p.write_text(render(profile(),manifest));p.chmod(0o600);return p


def choose_manifest(current, digest, revision):
    result=copy.deepcopy(current)
    if bool(digest)!=bool(revision):raise ValueError('CAS digest and source revision must be selected together')
    if digest:
        result['images']['cas']['digest']=digest
        result['images']['cas']['revision']=revision
    validate_manifest(result)
    return result


def prove_images(manifest,current=None):
    recorded=(current or {}).get('publication_proof',{})
    result={};checked={}
    for name in ('cas','schema_proxy'):
        image=manifest['images'][name];old=recorded.get(name,{})
        matching=all(old.get(key)==image[key] for key in ('repository','revision','digest'))
        if matching and old.get('publisher_tag')=='sha-'+image['revision'] and re.fullmatch('[a-f0-9]{40}',old.get('current_main','')):
            result[name]=old;continue
        key=(image['repository'],image['revision'],image['digest'])
        if key not in checked:
            projected=copy.deepcopy(manifest)
            projected['images']['cas']=image;projected['images']['schema_proxy']=image
            checked[key]=verify_provenance(projected)['cas']
        result[name]=checked[key]
    return result


def sync_source(sha):
    if not re.fullmatch('[a-f0-9]{40}',sha):raise ValueError('Invalid immutable source SHA')
    command='cd '+shlex.quote(VMROOT)+' && test -z "$(git status --porcelain)" && git fetch origin main && git merge-base --is-ancestor '+sha+' origin/main && git checkout --detach '+sha
    r=subprocess.run(ssh_args(command),capture_output=True,text=True,timeout=60)
    if r.returncode:raise RuntimeError('Trusted VM source update refused')


def stop_owned(config):
    present=remote('inventory')['kamal_present']
    for name in reversed(ORDER):
        if name in present:kamal(config,'stop',name)
    remote('remove-kamal')


def restore(previous,directory):
    config=configuration(directory,previous['manifest'])
    current=remote('inventory')
    if current['kamal_present']:stop_owned(config)
    sync_source(previous['source_sha'])
    if previous['authority']=='compose':
        remote('devsy-restore')
        remote('remove-network')
        remote('set-current',previous)
        remote('compose-start')
    else:
        remote('network',profile()['network'])
        for name in ORDER:
            kamal(config,'reboot',name);remote('wait',{'owner':'kamal','service':name})
        remote('devsy-start')
    remote('smoke')
    after=remote('snapshot')
    if after['identity']!=previous['identity']:raise RuntimeError('Rollback identity mismatch')
    remote('set-current',previous)
    return after


def restore_cas(previous,directory):
    config=configuration(directory,previous['manifest'])
    kamal(config,'reboot','cas');remote('wait',{'owner':'kamal','service':'cas'})
    remote('smoke');after=remote('snapshot')
    if after['identity']!=previous['identity']:raise RuntimeError('CAS rollback identity mismatch')
    if after['source_sha']!=previous['source_sha']:raise RuntimeError('CAS rollback found source drift; full deployment reconciliation required')
    remote('set-current',previous)
    return after


def execute(args):
    if INSTANCE is None:
        configure_instance(getattr(args,'instance_profile',None) or os.environ.get('KAMAL_INSTANCE_PROFILE',DEFAULT_INSTANCE_PROFILE))
    trusted_context(os.environ,args.local)
    if args.operation in ('adopt','deploy','rollback') and not args.approve_full_stack:raise ValueError('Explicit full-stack approval input required')
    sha=os.environ.get('GITHUB_SHA') or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    with lock(), tempfile.TemporaryDirectory(prefix='mcp-kamal-') as directory:
        if args.operation=='status':
            result=remote('status')
            result['smoke']=remote('smoke') if result['healthy'] else {'status':'BLOCKED: managed service unhealthy'}
            return result
        if args.operation=='rollback':
            current=remote('current');previous=remote('rollback-target')
            if current is None:raise ValueError('No recorded deployment generation exists')
            remote('profile')
            previous['publication_proof']=prove_images(previous['manifest'],previous)
            remote('images',previous['manifest'])
            state=remote('status')
            if state['inventory'].get('executor',{}).get('state')=='running':remote('backup')
            after=restore(previous,directory)
            remote('rollback-commit',{'current':previous,'previous':current})
            return {'operation':'rollback','authority':after['authority'],'inventory':after['inventory'],'identity_preserved':True}
        before=remote('snapshot')
        remote('profile')
        remote('network-check',profile()['network'])
        current=remote('current');needs_baseline=current is None
        defaults=json.loads((ROOT/'config/deploy-images.json').read_text())
        if current is None:
            current={'authority':before['authority'],'source_sha':before['source_sha'],'manifest':defaults,'identity':before['identity']}
        if before['identity']!=current['identity']:raise ValueError('Executor identity drift')
        current['publication_proof']=prove_images(current['manifest'],current)
        manifest=choose_manifest(current['manifest'],args.cas_digest,args.cas_revision)
        publication=prove_images(manifest,current)
        config=configuration(directory,manifest)
        provenance=remote('image-check',current['manifest'])
        for key,image_id in provenance['image_ids'].items():
            service='schema-proxy' if key=='schema_proxy' else key
            if before['inventory'][service]['image']!=image_id:raise ValueError('Current managed image differs from recorded generation')
        if args.operation in ('preflight','status'):
            smoke=remote('smoke')
            return {'operation':args.operation,'authority':before['authority'],'inventory':before['inventory'],'smoke':smoke,'pinned_images':manifest['images']}
        if args.operation=='cas' and before['authority']!='kamal':raise ValueError('Kamal adoption must precede accessory redeploy')
        if args.operation=='adopt' and before['authority']!='compose':raise ValueError('Adoption requires the sole Compose owner')
        if args.operation=='deploy' and before['authority']!='kamal':raise ValueError('Use explicit adoption first')
        remote('images',manifest)
        if needs_baseline:remote('baseline',current)
        backup=remote('backup-cas' if args.operation=='cas' else 'backup')
        phase='source-sync'
        try:
            if args.operation!='cas':sync_source(sha)
            if args.operation=='adopt':
                phase='compose-stop';remote('compose-stop')
                phase='network';remote('network',profile()['network'])
                phase='devsy-start';remote('devsy-start')
                for name in ORDER:
                    phase='boot-'+name
                    kamal(config,'boot',name);remote('wait',{'owner':'kamal','service':name})
            elif args.operation=='cas':
                phase='reboot-cas'
                kamal(config,'reboot','cas');remote('wait',{'owner':'kamal','service':'cas'})
            else:
                for name in reversed(ORDER):
                    phase='stop-'+name;kamal(config,'stop',name)
                for name in ORDER:
                    phase='reboot-'+name
                    kamal(config,'reboot',name);remote('wait',{'owner':'kamal','service':name})
                phase='devsy-start'
                remote('devsy-start')
            phase='acceptance'
            after=remote('snapshot');smoke=remote('smoke')
            if after['identity']!=before['identity']:raise RuntimeError('Post-deploy Executor identity changed')
            deployed_source=current['source_sha'] if args.operation=='cas' else sha
            remote('commit',{'authority':'kamal','source_sha':deployed_source,'manifest':manifest,'identity':after['identity'],'publication_proof':publication})
            return {'operation':args.operation,'authority':'kamal','inventory':after['inventory'],'smoke':smoke,'identity_preserved':True,'backup':backup,'source_sha':deployed_source,'controller_sha':sha}
        except Exception:
            # Report only our fixed phase names, never subprocess output or secrets.
            try:
                if args.operation=='cas':restore_cas(current,directory)
                else:restore(current,directory)
            except Exception:
                raise RuntimeError('Deployment failed at '+phase+'; automatic rollback FAILED; operator recovery required') from None
            raise RuntimeError('Deployment failed at '+phase+'; previous generation restored') from None


def main():
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('preflight','status','adopt','cas','deploy','rollback'));p.add_argument('--cas-digest',default='');p.add_argument('--cas-revision',default='');p.add_argument('--approve-full-stack',action='store_true');p.add_argument('--instance-profile',help='Absolute path to an owned mode-0600 private instance profile');p.add_argument('--local',action='store_true',help='Approved Pi break-glass, or bin/kamal with explicit private local config')
    args=p.parse_args()
    try:print(json.dumps(execute(args),indent=2))
    except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)

if __name__=='__main__':main()
