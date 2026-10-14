#!/usr/bin/env python3
"""Start the managed host Devsy MCP bridge under systemd."""

from devsy_vm_service import main

raise SystemExit(main())
