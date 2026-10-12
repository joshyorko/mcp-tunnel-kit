#!/usr/bin/env python3
"""Start the existing host Devsy bridge independently of Compose ownership."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import devsy_bridge as bridge
from compose_control import read_private,write_private
state=Path('/home/kdlocpanda/.local/share/codex-control-plane/devsy-bridge')
value=json.loads(read_private(state/'config.json'))
bridge.start(value)
r=json.loads(read_private(state/'process.json'))
if not bridge.owned_process(r):raise RuntimeError('Devsy process ownership mismatch')
write_private(state/'systemd.pid',str(r['pid'])+'\n')
