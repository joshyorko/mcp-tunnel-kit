"""Shared, fixed bounds for the Friday bridge; never derived from MCP arguments."""

import re


SESSION_ID = "friday-chatgpt-tunnel"
MAX_MESSAGE_LENGTH = 8000
REQUEST_ID_MAX_LENGTH = 255
RUN_ID_PATTERN = r"^run_[0-9a-f]{32}$"
RUN_ID_RE = re.compile(RUN_ID_PATTERN)
