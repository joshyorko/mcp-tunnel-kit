#!/usr/bin/env python3
"""Transfer only a validated VM generation into new private VM staging."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile

import deploy_control_plane as deploy
from prepare_recovery_generation import GenerationError, validate_generation


REMOTE = '''
import io,json,os,pathlib,shutil,stat,sys,tarfile,tempfile,types
os.umask(0o077)
destination=pathlib.Path(sys.argv[1])
base=pathlib.Path.home()/'.local/state/mcp-control-plane-recovery-staging'
if not destination.is_absolute() or destination.parent!=base or destination.name in ('','.','..'):
 raise ValueError('Destination must be one new directory under the private recovery staging base')
base.mkdir(mode=0o700,parents=True,exist_ok=True)
s=base.lstat()
if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:
 raise ValueError('Private staging base is unsafe')
if destination.exists() or destination.is_symlink():raise ValueError('Staging destination already exists')
module=types.ModuleType('prepare_recovery_generation')
module.__file__=str(base/'validator.py')
sys.modules[module.__name__]=module
exec(sys.argv[2],module.__dict__)
with tempfile.TemporaryDirectory(prefix='.transfer-',dir=base) as temporary:
 temporary=pathlib.Path(temporary)
 archive=temporary/'incoming.tar'
 with archive.open('xb') as output:
  total=0
  while True:
   block=sys.stdin.buffer.read(1024*1024)
   if not block:break
   total+=len(block)
   if total>105*1024**3:raise ValueError('Transfer exceeds recovery limits')
   output.write(block)
 with tarfile.open(archive,'r:') as stream:
  members=stream.getmembers()
  if len(members)>200000:raise ValueError('Transfer inventory exceeds recovery limits')
  names=set()
  for member in members:
   p=pathlib.PurePosixPath(member.name)
   if (p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='generation'
       or str(p)!=member.name or member.name in names or not(member.isfile() or member.isdir())
       or member.mode not in (0o600,0o700)):
    raise ValueError('Unsafe transfer archive member')
   names.add(member.name)
  for member in members:
   p=temporary.joinpath(*pathlib.PurePosixPath(member.name).parts)
   if member.isdir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
   else:
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with stream.extractfile(member) as source,p.open('xb') as output:shutil.copyfileobj(source,output)
    p.chmod(member.mode)
 source=temporary/'generation'
 metadata=module.validate_generation(source)
 # mkdir is exclusive, so another transfer cannot replace this destination.
 destination.mkdir(mode=0o700)
 try:
  for child in source.iterdir():os.rename(child,destination/child.name)
  module.validate_generation(destination)
 except BaseException:
  shutil.rmtree(destination)
  raise
 print(json.dumps({'transferred':True,'generation_dir':str(destination),'expected_identity':metadata['expected_identity']}))
'''


def transfer(local_config, instance_profile, generation_dir, destination):
    generation_dir = Path(generation_dir)
    metadata = validate_generation(generation_dir)
    deploy.configure_local(local_config, instance_profile)
    deploy.trusted_context(os.environ, local=True)
    destination = Path(destination)
    if not destination.is_absolute():
        raise ValueError('VM staging destination must be absolute')
    validator = (deploy.ROOT / 'scripts/prepare_recovery_generation.py').read_text()
    command = deploy.ssh_args(shlex.join(['python3', '-c', REMOTE, str(destination), validator]))
    with tempfile.TemporaryFile(mode='w+b') as transport:
        with tarfile.open(fileobj=transport, mode='w') as archive:
            archive.add(generation_dir, arcname='generation')
        transport.seek(0)
        result = subprocess.run(command, stdin=transport, capture_output=True, timeout=900)
    if result.returncode:
        raise ValueError('Pinned recovery transfer refused; remote diagnostic withheld')
    receipt = json.loads(result.stdout)
    if receipt.get('expected_identity') != metadata['expected_identity']:
        raise ValueError('Transferred generation identity mismatch')
    return {'transferred': True, 'generation_dir': receipt['generation_dir'], 'services_changed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-config', required=True)
    parser.add_argument('--instance-profile', required=True)
    parser.add_argument('--generation-dir', required=True, help='Validated local prepared-generation directory')
    parser.add_argument('--destination', required=True, help='New absolute VM path under ~/.local/state/mcp-control-plane-recovery-staging')
    args = parser.parse_args()
    try:
        result = transfer(args.local_config, args.instance_profile, args.generation_dir, args.destination)
    except (OSError, ValueError, RuntimeError, GenerationError, subprocess.SubprocessError):
        parser.exit(1, 'Recovery transfer refused; no services were activated.\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
