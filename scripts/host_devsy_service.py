#!/usr/bin/env python3
"""Start the managed host Devsy MCP bridge under systemd."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from devsy_vm_service import main

raise SystemExit(main())
