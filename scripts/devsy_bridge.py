#!/usr/bin/env python3
"""Host-owned Devsy stdio bridge. No credentials are copied or logged."""

from __future__ import annotations

import ipaddress

UPSTREAM_READS = frozenset({"provider_list", "workspace_list", "workspace_status"})
READ_ONLY = UPSTREAM_READS | {"workspace_diagnostics"}
KNOWN_TOOLS = UPSTREAM_READS | {"workspace_create", "workspace_start", "workspace_stop",
                         "workspace_delete", "workspace_exec", "provider_add",
                         "provider_delete", "provider_use"}


class BridgeError(Exception):
    """Fixed diagnostics only; upstream stderr and payloads stay private."""


def validate_bind(subnet, gateway):
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
        address = ipaddress.IPv4Address(gateway)
        private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if (network.prefixlen != 24 or address != network.network_address + 1
                or not any(network.subnet_of(ipaddress.ip_network(item)) for item in private)):
            raise ValueError()
        return network
    except ValueError:
        raise BridgeError("Devsy must bind to the managed private /24 bridge gateway.") from None


def normalize_tool(tool):
    """Names, never upstream hints, decide which tools bypass browser approval."""
    return {**tool, "annotations": {"readOnlyHint": tool["name"] in READ_ONLY,
                                  "destructiveHint": tool["name"] not in READ_ONLY,
                                  "openWorldHint": True}}


import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import threading
import time

PROTOCOLS = {"2025-11-25", "2025-06-18", "2025-03-26"}
MAX_BYTES = 2 * 1024 * 1024
_CHILDREN = set()
_CHILD_LOCK = threading.Lock()


def terminate(process):
    """Kill the owned process group, including descendants, then reap its leader."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def stop_children():
    with _CHILD_LOCK:
        children = list(_CHILDREN)
    for process in children:
        terminate(process)


class Stdio:
    """One newline-delimited MCP session with a total deadline and byte limits."""
    def __init__(self, process, timeout):
        self.process = process
        self.deadline = time.monotonic() + timeout
        self.buffer = b""
        self.identifier = 0
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stdin.fileno(), False)

    def wait(self, file, event):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeError("Devsy operation timed out; it was not retried.")
        with selectors.DefaultSelector() as selector:
            selector.register(file, event)
            if not selector.select(remaining):
                raise BridgeError("Devsy operation timed out; it was not retried.")

    def send(self, message):
        data = json.dumps(message, allow_nan=False).encode() + b"\n"
        if len(data) > MAX_BYTES:
            raise BridgeError("Devsy request exceeded its size limit.")
        while data:
            self.wait(self.process.stdin, selectors.EVENT_WRITE)
            data = data[os.write(self.process.stdin.fileno(), data):]

    def call(self, method, params):
        self.identifier += 1
        self.send({"jsonrpc": "2.0", "id": self.identifier, "method": method, "params": params})
        while True:
            if time.monotonic() >= self.deadline:
                raise BridgeError("Devsy operation timed out; it was not retried.")
            if b"\n" not in self.buffer:
                self.wait(self.process.stdout, selectors.EVENT_READ)
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise BridgeError("Devsy closed its stdio transport.")
                self.buffer += chunk
                if len(self.buffer) > MAX_BYTES:
                    raise BridgeError("Devsy response exceeded its size limit.")
                continue
            line, self.buffer = self.buffer.split(b"\n", 1)
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise BridgeError("Devsy returned an invalid MCP response.")
            if "method" in message:
                # Sampling, elicitation and other server requests are not advertised.
                if "id" in message:
                    self.send({"jsonrpc": "2.0", "id": message["id"], "error": {
                        "code": -32601, "message": "Host bridge does not support server requests"}})
                continue
            if message.get("id") != self.identifier or "error" in message or "result" not in message:
                raise BridgeError("Devsy MCP request failed; details omitted.")
            return message["result"]


class Devsy:
    def __init__(self, binary, cwd, env=None, timeout=120, targets_source=None):
        executable = Path(binary)
        directory = Path(cwd)
        if (not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK)
                or not directory.is_absolute() or not directory.is_dir() or not 0 < timeout <= 120):
            raise BridgeError("Set an absolute existing Devsy executable and working directory.")
        self.stopping = threading.Event()
        # Follow the configured launcher on each call after package-manager upgrades.
        self.binary, self.cwd, self.env, self.timeout = str(executable), str(directory.resolve()), env, timeout
        self.targets_source = targets_source

    @staticmethod
    def diagnostic_module():
        import importlib.util
        path = Path(__file__).with_name('worker_diagnostics.py')
        spec = importlib.util.spec_from_file_location('worker_diagnostics', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @contextlib.contextmanager
    def session(self, timeout=None):
        budget = self.timeout if timeout is None else min(self.timeout, timeout)
        with _CHILD_LOCK:
            if self.stopping.is_set():
                raise BridgeError("Host Devsy bridge is stopping.")
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child",
                                        self.binary, str(os.getpid()), str(budget)],
                                       cwd=self.cwd, env=self.env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
            _CHILDREN.add(process)
        try:
            session = Stdio(process, budget)
            result = session.call("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                  "clientInfo": {"name": "tunnel-kit-host-devsy", "version": "1"}})
            if result.get("protocolVersion") not in PROTOCOLS or "tools" not in result.get("capabilities", {}):
                raise BridgeError("Devsy did not negotiate the required MCP tools capability.")
            session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            yield session
        except (OSError, ValueError, TypeError, KeyError):
            raise BridgeError("Devsy stdio exchange failed; details omitted.") from None
        finally:
            terminate(process)
            process.stdin.close()
            process.stdout.close()
            with _CHILD_LOCK:
                _CHILDREN.discard(process)

    @staticmethod
    def discover(session):
        tools, names, cursor, seen = [], set(), None, set()
        for _ in range(20):
            page = session.call("tools/list", {} if cursor is None else {"cursor": cursor})
            if not isinstance(page, dict) or not isinstance(page.get("tools"), list):
                raise BridgeError("Devsy returned an invalid tool catalog.")
            for tool in page["tools"]:
                name = tool.get("name") if isinstance(tool, dict) else None
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name)
                        or name in names or not isinstance(tool.get("inputSchema"), dict)
                        or len(tools) >= 128):
                    raise BridgeError("Devsy tool catalog is invalid or exceeds its limit.")
                names.add(name)
                tools.append(normalize_tool(tool))
            cursor = page.get("nextCursor")
            if not cursor:
                if not KNOWN_TOOLS.issubset(names):
                    raise BridgeError("Devsy catalog lacks the expected workspace/provider tools.")
                return tools
            if not isinstance(cursor, str) or cursor in seen or len(cursor) > 1024:
                raise BridgeError("Devsy catalog pagination is invalid.")
            seen.add(cursor)
        raise BridgeError("Devsy catalog exceeded its pagination limit.")

    def catalog(self):
        with self.session(timeout=10) as session:
            tools = self.discover(session)
        if self.targets_source:
            tools.append(normalize_tool(self.diagnostic_module().TOOL))
        return tools

    def call(self, name, arguments):
        if name == 'workspace_diagnostics' and self.targets_source:
            module = self.diagnostic_module()
            try:
                result = module.diagnose(self.targets_source, arguments, self.call, self.env)
            except module.DiagnosticError as error:
                result = {'error': {'code': 'worker_diagnostics_refused', 'message': str(error)}}
                return {'content': [{'type': 'text', 'text': json.dumps(result)}],
                        'structuredContent': result, 'isError': True}
            return {'content': [{'type': 'text', 'text': json.dumps(result)}],
                    'structuredContent': result, 'isError': False}
        if name not in KNOWN_TOOLS or not isinstance(arguments, dict):
            raise BridgeError("Unknown Devsy tool or invalid arguments; call refused.")
        with self.session() as session:
            self.discover(session)
            result = session.call("tools/call", {"name": name, "arguments": arguments})
            if not isinstance(result, dict) or not isinstance(result.get("content"), list):
                raise BridgeError("Devsy returned an invalid tool result; call was not retried.")
            return result


class BridgeServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = False
    request_queue_size = 16

    def __init__(self, address, devsy, subnet, instance):
        self.devsy, self.subnet, self.instance = devsy, subnet, instance
        self.slots = threading.BoundedSemaphore(8)
        self.connections = set()
        self.connection_lock = threading.Lock()
        super().__init__(address, BridgeHandler)
        self.authority = f"{self.server_address[0]}:{self.server_port}"

    def shutdown(self):
        self.devsy.stopping.set()
        with self.connection_lock:
            for connection in self.connections:
                try:
                    connection.shutdown(2)
                except OSError:
                    pass
                connection.close()
        stop_children()
        super().shutdown()

    def process_request(self, request, client_address):
        if self.devsy.stopping.is_set():
            request.close()
            return
        # A client can send its next request before the previous handler's
        # finally releases a slot. Bound admission instead of resetting it.
        if not self.slots.acquire(timeout=0.25):
            try:
                request.settimeout(0.25)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Retry-After: 1\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            request.close()
            return
        with self.connection_lock:
            if self.devsy.stopping.is_set():
                request.close()
                self.slots.release()
                return
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.connection_lock:
                self.connections.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # HTTP errors can contain arguments; never emit raw tracebacks.


class BridgeHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass

    def reply(self, status, body=None):
        data = b"" if body is None else json.dumps(body, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        peer = ipaddress.ip_address(self.client_address[0])
        if ((peer not in self.server.subnet and not peer.is_loopback)
                or self.headers.get("Host") != self.server.authority
                or self.headers.get("Origin") not in (None, "http://" + self.server.authority)):
            self.reply(403, {"error": "Private bridge request refused"})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        if self.path != "/health":
            self.reply(405 if self.path == "/mcp" else 404)
            return
        try:
            self.server.devsy.catalog()
            self.reply(200, {"ready": True, "instance": self.server.instance})
        except Exception:
            self.reply(503, {"ready": False})

    def do_DELETE(self):
        if self.allowed():
            self.reply(405)  # Stateless transport has no session to terminate.

    def do_POST(self):
        if not self.allowed():
            return
        if self.path != "/mcp":
            self.reply(404)
            return
        identifier = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if (not 0 < length <= MAX_BYTES or self.headers.get("Transfer-Encoding")
                    or self.headers.get_content_type() != "application/json"):
                self.reply(400, {"error": "Invalid MCP request framing"})
                return
            request = json.loads(self.rfile.read(length))
            if self.server.devsy.stopping.is_set():
                raise BridgeError("Host Devsy bridge is stopping.")
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise BridgeError("Invalid MCP request.")
            identifier, method, params = request.get("id"), request.get("method"), request.get("params", {})
            if not isinstance(params, dict):
                raise BridgeError("Invalid MCP parameters.")
            if "id" not in request:
                if method in {"notifications/initialized", "notifications/cancelled"}:
                    self.reply(202)
                    return
                raise BridgeError("Unsupported MCP notification.")
            if method == "initialize":
                self.server.devsy.catalog()
                version = params.get("protocolVersion")
                result = {"protocolVersion": version if version in PROTOCOLS else "2025-03-26",
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "tunnel-kit-host-devsy", "version": "1"}}
            elif self.headers.get("MCP-Protocol-Version", "2025-03-26") not in PROTOCOLS:
                raise BridgeError("Unsupported MCP protocol version.")
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                if params.get("cursor"):
                    raise BridgeError("Unknown catalog cursor.")
                result = {"tools": self.server.devsy.catalog()}
            elif method == "tools/call":
                result = self.server.devsy.call(params.get("name"), params.get("arguments", {}))
            else:
                raise BridgeError("Unsupported MCP method.")
            self.reply(200, {"jsonrpc": "2.0", "id": identifier, "result": result})
        except Exception:
            self.reply(200, {"jsonrpc": "2.0", "id": identifier, "error": {
                "code": -32603, "message": "Devsy request failed or was refused; details omitted. Do not retry a mutation automatically."}})


import argparse
import fcntl
import hashlib
import secrets
import sys
import urllib.request
import urllib.error


def settings(configuration):
    operator = configuration.get('x-operator', {})
    enabled = str(operator.get('devsy_enabled', 'false')).lower()
    if enabled not in {'true', 'false'}:
        raise BridgeError('DEVSY_MCP_ENABLED must be true or false.')
    if enabled == 'false':
        return None
    network = configuration['networks']['control-plane']['ipam']['config'][0]
    result = {'subnet': network['subnet'], 'gateway': network['gateway'],
              'binary': operator.get('devsy_binary', ''), 'cwd': operator.get('devsy_cwd', ''),
              'state': str(Path(operator.get('devsy_state', './.state/devsy-bridge')).resolve()), 'home': operator.get('devsy_home', ''),
              'targets_source': operator.get('targets_source')}
    validate_settings(result)
    return result


def validate_settings(value):
    validate_bind(value['subnet'], value['gateway'])
    Devsy(value['binary'], value['cwd'])
    state = Path(value.get('state', ''))
    if not state.is_absolute():
        raise BridgeError('Devsy bridge state must be an absolute private path.')
    home = value.get('home')
    if home and (not Path(home).is_absolute() or not Path(home).is_dir()):
        raise BridgeError('DEVSY_MCP_HOME must be an existing absolute host configuration directory.')


def process_identity(pid):
    try:
        # comm may contain spaces or parentheses; starttime is field 22.
        fields = Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()
        return fields[19] if fields[0] != 'Z' else None
    except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
        return None


def owned_process(receipt):
    pid = receipt.get('pid')
    if not isinstance(pid, int) or pid <= 1 or receipt.get('started') != process_identity(pid):
        return False
    try:
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        return os.fsencode(str(Path(__file__).resolve())) in command and b'--serve' in command
    except (FileNotFoundError, ProcessLookupError):
        return False


def fingerprint(value):
    # No credentials: configuration contains only selected paths and bridge addresses.
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode() + Path(__file__).read_bytes()).hexdigest()


def host_opener():
    # Docker may masquerade a gateway-to-itself connection to a different host
    # interface address. Select numeric loopback as its source, not a LAN allowlist.
    class HostHTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(HTTPConnection, request, source_address=("127.0.0.1", 0))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args):
            return None
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), HostHTTP(), NoRedirect())


def health(value, instance):
    opener = host_opener()
    with opener.open(f"http://{value['gateway']}:8089/health", timeout=15) as response:
        data = json.loads(response.read(4096))
    if data != {'ready': True, 'instance': instance}:
        raise BridgeError('Host Devsy bridge readiness identity did not match.')


@contextlib.contextmanager
def state_lock(state, name, nonblocking=False):
    from compose_control import private_directory
    private_directory(state)
    descriptor = os.open(state / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
            raise BridgeError('Bridge lock must be private and owned by this user.')
        fcntl.flock(descriptor, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        yield
    finally:
        os.close(descriptor)


def start(value):
    """Retain a matching owned process; never replace a live mismatched listener."""
    from compose_control import read_private, write_private
    validate_settings(value)
    state = Path(value['state'])
    with state_lock(state, 'control.lock'):
        marker = state / 'process.json'
        old = json.loads(read_private(marker)) if marker.exists() or marker.is_symlink() else None
        if old and owned_process(old):
            if old.get('configuration') != fingerprint(value):
                raise BridgeError('Devsy bridge settings changed while running. Down then up to apply them.')
            health(value, old['instance'])
            return
        config = state / 'config.json'
        write_private(config, json.dumps(value) + '\n')
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--serve', str(config)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 30
        phase = "waiting for private process receipt"
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise BridgeError('Host Devsy bridge failed to start. Check the binary, paths and private gateway.')
            if marker.exists():
                record = json.loads(read_private(marker))
                phase = "checking process identity"
                if record.get('pid') == child.pid and owned_process(record):
                    phase = "checking MCP health"
                    try:
                        health(value, record['instance'])
                        return
                    except urllib.error.HTTPError as error:
                        phase = "MCP health HTTP " + str(error.code)
                    except (OSError, ValueError) as error:
                        phase = "MCP health " + type(error).__name__
            time.sleep(0.1)
        terminate(child)
        raise BridgeError('Host Devsy bridge readiness timed out while ' + phase + '; no tunnel was started.')


def stop(state):
    """Stop only the recorded daemon, verified against Linux process birth time."""
    from compose_control import read_private
    state = Path(state)
    if not state.exists():
        return
    with state_lock(state, 'control.lock'):
        marker = state / 'process.json'
        if not marker.exists() and not marker.is_symlink():
            return
        record = json.loads(read_private(marker))
        if owned_process(record):
            # pidfd keeps a PID reused between checking and signalling safe.
            descriptor = None
            try:
                descriptor = os.pidfd_open(record['pid'])
                if owned_process(record):
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                    deadline = time.monotonic() + 8
                    while owned_process(record) and time.monotonic() < deadline:
                        time.sleep(0.05)
                    if owned_process(record):
                        raise BridgeError('Host bridge has not stopped; its state was retained. Do not remove the bridge network.')
            except ProcessLookupError:
                if owned_process(record):
                    raise BridgeError('Could not confirm that the host bridge stopped.') from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        marker.unlink(missing_ok=True)


def serve(config):
    from compose_control import read_private, write_private, network_preflight, config as compose_config
    server = None
    stopping = threading.Event()
    def shutdown(_signal, _frame):
        if not stopping.is_set():
            stopping.set()
            if server is not None:
                threading.Thread(target=server.shutdown, daemon=True).start()
            if server is None:
                # Unwind startup; never acquire child locks in a signal handler.
                # Child guards also clean up if startup is interrupted inside Popen.
                raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    value = json.loads(read_private(Path(config)))
    validate_settings(value)
    # Direct invocation still must prove the managed Compose network and gateway.
    configuration = compose_config()
    network_preflight(configuration)
    if settings(configuration) != value:
        raise BridgeError('Host bridge settings do not match the managed Compose configuration.')
    state = Path(value['state'])
    with state_lock(state, 'daemon.lock', nonblocking=True):
        environment = dict(os.environ)
        if value.get('home'):
            environment['DEVSY_HOME'] = value['home']
        devsy = Devsy(value['binary'], value['cwd'], environment,
                      targets_source=value.get('targets_source'))
        devsy.catalog()
        instance = secrets.token_hex(16)
        server = BridgeServer((value['gateway'], 8089), devsy,
                              validate_bind(value['subnet'], value['gateway']), instance)
        marker = state / 'process.json'
        write_private(marker, json.dumps({'pid': os.getpid(), 'started': process_identity(os.getpid()),
                                         'configuration': fingerprint(value), 'instance': instance}) + '\n')
        try:
            server.serve_forever(poll_interval=0.1)
        finally:
            stop_children()
            server.server_close()
            marker.unlink(missing_ok=True)


def child_guard(binary, parent, budget):
    """Linux parent-death cleanup without preexec_fn in threaded HTTP workers.

    The guard and Devsy share a private process group. Its own deadline and
    parent-death handler kill that group even if the bridge is SIGKILLed.
    """
    import ctypes
    def die(_signal=None, _frame=None):
        os.killpg(os.getpgrp(), signal.SIGKILL)
    signal.signal(signal.SIGTERM, die)
    signal.signal(signal.SIGINT, die)
    if not 0 < budget <= 120 or not Path(binary).is_absolute():
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent:
        return 2
    try:
        result = subprocess.run([binary, "mcp", "serve"], timeout=budget,
                                stderr=subprocess.DEVNULL, check=False)
        return result.returncode
    except subprocess.TimeoutExpired:
        die()
    finally:
        # Reap no unexpected descendants into the host: the whole group ends.
        die()


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--child':
        return child_guard(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', required=True, metavar='PRIVATE_CONFIG')
    args = parser.parse_args()
    try:
        serve(args.serve)
    except Exception:
        print('Host Devsy bridge stopped; raw errors and private values omitted.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
