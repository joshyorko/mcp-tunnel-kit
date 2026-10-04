#!/usr/bin/env python3
"""Bounded Compose setup and probes. No daemon, credential output, or native lifecycle."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "codex-control-plane"
NETWORK = PROJECT + "_control-plane"
COMPACT = {"execute", "resume", "skills"}
PROTOCOL_VERSIONS = {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
SECRET_VARIABLES = {
    "control-plane-api-key": "CONTROL_PLANE_API_KEY",
    "control-plane-tunnel-id": "CONTROL_PLANE_TUNNEL_ID",
    "executor-pat": "EXECUTOR_PAT",
}


class ControlError(Exception):
    """Only fixed, credential-free diagnostics cross the command boundary."""


def read_private(path: Path, *, strip=True) -> str:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ControlError("Secret/state files must be regular, owned by you, mode 0600; symlinks are refused.")
    with path.open(newline="") as handle:
        value = handle.read()
    return value.strip() if strip else value


def private_directory(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        missing = [path]
        parent = path.parent
        while not parent.exists() and not parent.is_symlink():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ControlError("State directories must be owned by you, mode 0700; symlinks are refused.")


def write_private(path: Path, value: str) -> None:
    private_directory(path.parent)
    if path.exists() or path.is_symlink():
        if read_private(path, strip=False) == value:
            return
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def compose_rows():
    raw = compose("ps", "--all", "--format", "json")
    return json.loads(raw) if raw.lstrip().startswith("[") else [json.loads(line) for line in raw.splitlines() if line.strip()]


def write_bind_file(path: Path, value: str) -> None:
    if path.exists() or path.is_symlink():
        if read_private(path) == value.strip():
            return
    if any(row.get("Service") in {"codex-action-server", "app-ready", "tunnel-client"}
           and row.get("State") in {"running", "paused", "restarting"} for row in compose_rows()):
        raise ControlError("Targets or token header changed while containers are active. Run control-plane-down, update files, then control-plane-up to refresh file mounts.")
    write_private(path, value)


def command(arguments: list[str], timeout: int = 30):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise ControlError("Command failed; raw output omitted. Inspect configuration and service health separately.")
    return result.stdout


def compose(*arguments, timeout: int = 30):
    return command(["docker", "compose", *arguments], timeout)


def config():
    return json.loads(compose("config", "--format", "json"))


def validate_network(subnet, gateway, routes, networks) -> None:
    try:
        chosen = ipaddress.IPv4Network(subnet, strict=True)
        address = ipaddress.IPv4Address(gateway)
        if (not any(chosen.subnet_of(private) for private in PRIVATE_NETWORKS)
                or chosen.prefixlen != 24 or address != chosen.network_address + 1):
            raise ValueError()
    except ValueError:
        raise ControlError("Use a private /24 subnet and its first usable address as the managed bridge gateway.") from None
    managed_interfaces = set()
    for network in networks:
        own = network.get("Name") == NETWORK
        labels = network.get("Labels") or {}
        entries = (network.get("IPAM") or {}).get("Config") or []
        if own:
            if (network.get("Driver") != "bridge"
                    or labels.get("com.docker.compose.project") != PROJECT
                    or labels.get("com.docker.compose.network") != "control-plane"
                    or len(entries) != 1 or entries[0].get("Subnet") != subnet
                    or entries[0].get("Gateway") != gateway):
                raise ControlError("The existing managed bridge does not match this project, subnet, and gateway.")
            interface = (network.get("Options") or {}).get("com.docker.network.bridge.name")
            managed_interfaces.add(interface or "br-" + network.get("Id", "")[:12])
            continue
        for entry in entries:
            other = entry.get("Subnet")
            if other and ipaddress.ip_network(other, strict=False).version == 4:
                if chosen.overlaps(ipaddress.ip_network(other, strict=False)):
                    raise ControlError("The chosen subnet overlaps an unrelated Docker network. Choose another private /24.")
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        route_network = ipaddress.IPv4Network(destination, strict=False)
        if route.get("dev") in managed_interfaces and route_network.subnet_of(chosen):
            continue
        if chosen.overlaps(route_network):
            raise ControlError("The chosen subnet overlaps a host route. Choose another private /24.")


def validate_engine(options) -> None:
    if sys.platform != "linux" or any("rootless" in value or "userns" in value for value in options):
        raise ControlError("This host-network/native-socket deployment requires rootful Linux Docker without user namespace remapping.")


def network_preflight(configuration) -> None:
    validate_engine(json.loads(command(["docker", "info", "--format", "{{json .SecurityOptions}}"])))
    ipam = configuration["networks"]["control-plane"]["ipam"]["config"]
    if len(ipam) != 1 or configuration.get("name") != PROJECT:
        raise ControlError("Keep the documented project and one managed bridge.")
    ids = command(["docker", "network", "ls", "--quiet"]).split()
    networks = json.loads(command(["docker", "network", "inspect", *ids])) if ids else []
    routes = json.loads(command(["ip", "-json", "-4", "route", "show", "table", "all"]))
    validate_network(ipam[0]["subnet"], ipam[0]["gateway"], routes, networks)


def prepare_targets(source: Path, socket_directory: Path, uid: int):
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ControlError("The operator target file must be a regular file owned by you; symlinks are refused.")
    data = json.loads(source.read_text())
    local = data.get("targets", {}).get("local", {})
    if local.get("transport") != "local" or not local.get("socket_path"):
        raise ControlError("Configure local.socket_path explicitly in the operator target file before deployment.")
    socket_path = Path(local["socket_path"]).resolve(strict=True)
    info = socket_path.stat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid
            or socket_path.parent != socket_directory.resolve(strict=True)):
        raise ControlError("The resolved native socket must match the narrow mount directory and CAS UID.")
    local["socket_path"] = "/run/native-codex/" + socket_path.name
    return data


def mount(service, target):
    return Path(next(volume["source"] for volume in service["volumes"] if volume["target"] == target))


def prepare(configuration) -> None:
    service = configuration["services"]["codex-action-server"]
    uid = int(service["user"].split(":")[0])
    if uid != os.getuid():
        raise ControlError("Run setup as the socket owner and set CAS_UID to that same UID.")
    source = configuration.get("x-operator", {}).get("targets_source")
    if not source:
        raise ControlError("Set CAS_TARGETS_SOURCE to the existing operator-owned target file.")
    target_file = mount(service, "/run/codex-action-server/targets.json")
    state = mount(service, "/var/lib/codex-action-server")
    generated = prepare_targets(Path(source), mount(service, "/run/native-codex"), uid)
    private_directory(target_file.parent)
    private_directory(state)
    private_directory(state / "actions")
    private_directory(mount(service, "/var/lib/codex-action-server/runtime"))
    private_directory(mount(service, "/var/lib/codex-action-server/receipts"))
    private_directory(mount(configuration["services"]["app-ready"], "/var/lib/tunnel-kit"))
    write_bind_file(target_file, json.dumps(generated, indent=2) + "\n")


def validate_secrets(configuration) -> None:
    pat = read_private(Path(configuration["secrets"]["executor-pat"]["file"]))
    if not re.fullmatch(r"[!-~]+", pat):
        raise ControlError("The Executor PAT file must contain a nonempty token without whitespace.")
    write_bind_file(Path(configuration["secrets"]["executor-auth-header"]["file"]), "Bearer " + pat + "\n")
    for name, entry in configuration["secrets"].items():
        value = read_private(Path(entry["file"]))
        if not value or any(char in value for char in "\r\n"):
            raise ControlError("Secret files must contain one nonempty line.")
        if name == "control-plane-tunnel-id" and not re.fullmatch(r"tunnel_[0-9a-f]{32}", value):
            raise ControlError("The tunnel ID file does not contain a supported existing tunnel ID.")
        if name == "executor-auth-header" and not re.fullmatch(r"Bearer [!-~]+", value):
            raise ControlError("The Executor auth file must contain the complete Bearer PAT header.")


def save_secrets(configuration, dotenv=None) -> None:
    materialize_secrets(configuration, interactive=True, dotenv=dotenv)
    print("Private secret files ready; supplied values updated, absent values retained.")


def validate_credential(name: str, value: str) -> str:
    variable = SECRET_VARIABLES[name]
    if not re.fullmatch(r"[!-~]+", value):
        raise ControlError(f"Set {variable} to a nonempty single-line token without whitespace; values are never printed.")
    if name == "control-plane-tunnel-id" and not re.fullmatch(r"tunnel_[0-9a-f]{32}", value):
        raise ControlError("Set CONTROL_PLANE_TUNNEL_ID to a supported existing tunnel ID.")
    return value


def credential_dotenv() -> dict[str, str]:
    """Read only literal credential assignments; Compose still owns other settings."""
    path = ROOT / ".env"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    except OSError:
        raise ControlError("Cannot read repo-local .env; use a regular file owned by you, without symlinks.") from None
    names = {variable: name for name, variable in SECRET_VARIABLES.items()}
    values = {}
    with os.fdopen(descriptor, encoding="utf-8-sig", newline="") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ControlError("The repo-local .env must be a regular file owned by you; symlinks are refused.")
        # Protect even malformed credentials, without following a swapped path.
        os.fchmod(handle.fileno(), 0o600)
        for line in handle:
            # Other Compose settings are not evaluated, exported, or rewritten here.
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"(?:export\s+)?([A-Za-z_][A-Za-z_0-9]*)", stripped)
            if not match or match[1] not in names:
                continue
            key = match[1]
            if "\r" in line.removesuffix("\r\n"):
                raise ControlError(f"Use one single-line literal value for {key} in .env.")
            assignment = re.fullmatch(r"([A-Z_]+)\s*=\s*(.*?)", stripped)
            if not assignment or key in values:
                raise ControlError(f"Use one literal {key}=value assignment in .env; values are never printed.")
            value = assignment[2]
            if value.startswith(("'", '"')):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ControlError(f"Use one single-line literal value for {key} in .env.")
                value = value[1:-1]
            if any(char in value for char in "\\\"'"):
                raise ControlError(f"Quotes inside values and backslash escapes are unsupported for {key} in .env.")
            values[key] = validate_credential(names[key], value)
    return values


def materialize_secrets(configuration, *, interactive=False, dotenv=None) -> None:
    """Validate the entire set before replacing any private, file-backed secret."""
    if dotenv is None:
        dotenv = credential_dotenv()
    desired, current = {}, {}
    for entry in configuration["secrets"].values():
        parent = Path(entry["file"]).parent
        if parent.exists() or parent.is_symlink():
            private_directory(parent)
    for name, variable in SECRET_VARIABLES.items():
        path = Path(configuration["secrets"][name]["file"])
        if path.exists() or path.is_symlink():
            current[name] = read_private(path, strip=False)
        if variable in os.environ:
            value = os.environ[variable]
        elif variable in dotenv:
            value = dotenv[variable]
        elif name in current:
            value = current[name].removesuffix("\n")
        elif interactive:
            value = getpass.getpass(f"{variable} (input hidden): ")
        else:
            raise ControlError(f"Set {variable} in repo-local .env or the process environment, or use --secrets for hidden input.")
        desired[name] = validate_credential(name, value) + "\n"
    desired["executor-auth-header"] = "Bearer " + desired["executor-pat"]
    header = Path(configuration["secrets"]["executor-auth-header"]["file"])
    if header.exists() or header.is_symlink():
        current["executor-auth-header"] = read_private(header, strip=False)
    changed = {name: value for name, value in desired.items()
               if current.get(name, "").removesuffix("\n") != value.removesuffix("\n")}
    if not changed:
        return
    if any(row.get("Service") in {"codex-action-server", "app-ready", "tunnel-client"}
           and row.get("State") in {"running", "paused", "restarting"} for row in compose_rows()):
        raise ControlError("Secret files changed while containers are active. Run control-plane-down, then control-plane-up to refresh file mounts.")
    for name in changed:
        private_directory(Path(configuration["secrets"][name]["file"]).parent)
    for name, value in changed.items():
        write_private(Path(configuration["secrets"][name]["file"]), value)


def refuse_external_tunnel() -> None:
    own_ids = compose("ps", "--quiet", "tunnel-client").split()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")[:2]
            if not any(Path(os.fsdecode(arg)).name == "tunnel-client" for arg in arguments):
                continue
            group = (process / "cgroup").read_text()
            if not any(identity in group for identity in own_ids):
                raise ControlError("Another tunnel-client is running. Stop its own foreground pane before deploying this tunnel.")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class Http:
    def __init__(self, origin, authorization=None):
        self.origin = origin.rstrip("/")
        self.authorization = authorization
        self.deadline = time.monotonic() + 150
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, headers=None, empty=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ControlError("The bounded bootstrap/probe deadline expired.")
        request_headers = {"Accept": "application/json, text/event-stream"}
        if self.authorization:
            request_headers["Authorization"] = self.authorization
        if headers:
            request_headers.update(headers)
        encoded = None if body is None else json.dumps(body).encode()
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + path, data=encoded,
                                         headers=request_headers, method=method)
        with self.opener.open(request, timeout=min(remaining, 60)) as response:
            sse = "text/event-stream" in response.headers.get("Content-Type", "")
            raw, event, total = b"", [], 0
            while True:
                if time.monotonic() >= self.deadline:
                    raise ControlError("The bounded bootstrap/probe deadline expired.")
                chunk = response.read1(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    raise ControlError("HTTP/MCP response exceeded the bounded probe size.")
                raw += chunk
                if sse:
                    while b"\n" in raw:
                        line, raw = raw.split(b"\n", 1)
                        line = line.rstrip(b"\r").decode()
                        if not line and event:
                            data = json.loads("\n".join(event))
                            if "result" in data or "error" in data:
                                return data, response.headers
                            event = []
                        elif line.startswith("data:"):
                            event.append(line[5:].lstrip())
            if sse:
                raise ControlError("MCP stream ended without a response.")
            return ({} if empty and not raw else json.loads(raw)), response.headers


class Mcp:
    def __init__(self, http, path, state=None):
        self.http, self.path, self.headers, self.identifier = http, path, {}, 0
        if state is not None:
            if (not isinstance(state, dict) or set(state) != {"sessionId", "protocolVersion"}
                    or state["protocolVersion"] not in PROTOCOL_VERSIONS
                    or (state["sessionId"] is not None and (not isinstance(state["sessionId"], str)
                        or not re.fullmatch(r"[!-~]{1,512}", state["sessionId"])) )):
                raise ControlError("Saved MCP session metadata is invalid; the pending request was retained.")
            self.headers["MCP-Protocol-Version"] = state["protocolVersion"]
            if state["sessionId"] is not None:
                self.headers["Mcp-Session-Id"] = state["sessionId"]
            return
        initialized = self.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "compose-readiness", "version": "1"}})
        negotiated = initialized.get("protocolVersion")
        if negotiated not in PROTOCOL_VERSIONS:
            raise ControlError("MCP negotiated an unsupported protocol version.")
        self.headers["MCP-Protocol-Version"] = negotiated
        self.http.request("POST", self.path, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                          self.headers, empty=True)

    def session_state(self):
        return {"sessionId": self.headers.get("Mcp-Session-Id"),
                "protocolVersion": self.headers["MCP-Protocol-Version"]}

    def call(self, method, params):
        self.identifier += 1
        data, headers = self.http.request("POST", self.path,
                                          {"jsonrpc": "2.0", "id": self.identifier,
                                           "method": method, "params": params}, self.headers)
        if headers.get("Mcp-Session-Id"):
            self.headers["Mcp-Session-Id"] = headers["Mcp-Session-Id"]
        if data.get("id") != self.identifier or "error" in data or "result" not in data:
            raise ControlError("Authenticated MCP request failed; response omitted.")
        return data["result"]

    def tools(self):
        tools, cursor = [], None
        for _ in range(20):
            page = self.call("tools/list", {} if cursor is None else {"cursor": cursor})
            tools.extend(page["tools"])
            cursor = page.get("nextCursor")
            if not cursor:
                return tools
        raise ControlError("MCP discovery exceeded the bounded pagination limit.")


def executor_session(state=None):
    origin = os.environ.get("EXECUTOR_URL", "http://executor:4312")
    if origin not in {"http://executor:4312", "http://127.0.0.1:4312"}:
        raise ControlError("Executor probes use only the documented service DNS or host loopback origin.")
    pat = read_private(Path(os.environ.get("EXECUTOR_PAT_FILE", "/run/secrets/executor-pat")))
    if not re.fullmatch(r"[!-~]+", pat):
        raise ControlError("The Executor PAT file must contain a nonempty token without whitespace.")
    header = "Bearer " + pat
    http = Http(origin, header)
    return http, Mcp(http, "/mcp?elicitation_mode=browser", state=state)


def verify_compact(session):
    tools = session.tools()
    if {tool["name"] for tool in tools} != COMPACT or len(tools) != 3:
        raise ControlError("Executor must advertise exactly execute, resume, and skills.")
    resume = next(tool for tool in tools if tool["name"] == "resume")
    schema = resume["inputSchema"]
    identifier = schema.get("properties", {}).get("requestId", {})
    variants = identifier.get("anyOf", [identifier])
    if (schema.get("type") != "object" or set(schema.get("properties", {})) != {"requestId"}
            or set(schema.get("required", [])) != {"requestId"}
            or not variants or any(variant.get("type") != "string" for variant in variants)):
        raise ControlError("Browser resume must declare only the string requestId, with no decision response field.")


def verify_app_source(source, url):
    files = source.get("files", [])
    index = next((file["content"] for file in files if file.get("path") == "index.ts"), "")
    expected = '''import { defineApp, toolAnnotations, withApprovals } from "apps"
import { mcpRouter } from "apps/mcp"
import { always } from "apps/operations/approval"

export default defineApp({ accounts: {} }, async ({ signal, cache }) => ({
  tools: withApprovals(await mcpRouter({
    url: URL_PLACEHOLDER,
    cache,
    signal,
  }),
    // Ask before running tools the server marks destructive. Edit this rule to change which tools need approval.
    (tool) => (toolAnnotations(tool)?.destructiveHint === true ? always() : undefined),
  ),
}))
'''.replace("URL_PLACEHOLDER", json.dumps(url))
    if index.strip() != expected.strip():
        digest = hashlib.sha256(index.encode()).hexdigest()
        raise ControlError("Retained Codex source differs from the pinned generator; source SHA-256=" + digest + ". Inspect it in the dashboard; no source was changed.")


def execution(result):
    if result.get("isError"):
        raise ControlError("Executor tool failed; contents omitted.")
    data = result.get("structuredContent")
    if data is None:
        text = [block["text"] for block in result.get("content", []) if block.get("type") == "text"]
        if len(text) != 1:
            raise ControlError("Unexpected Executor result shape.")
        data = json.loads(text[0])
    return data


def search_codex(session):
    paths = set()
    for query in ("target", "thread"):
        data = execution(session.call("tools/call", {"name": "execute", "arguments": {"code":
            "return await tools.search(" + json.dumps({"namespace": "codex", "query": query, "limit": 100}) + ");"}}))
        if (data.get("status") != "completed" or not data.get("execution", {}).get("ok")
                or data.get("unavailableApps")):
            raise ControlError("Codex discovery through Executor is unavailable; inspect app access and CAS health.")
        paths.update(item["path"] for item in data["execution"]["value"].get("items", []))
    if not {"tools.codex.list_targets", "tools.codex.discover_threads"}.issubset(paths):
        raise ControlError("Executor Codex discovery lacks the expected target and thread tools.")


def ensure_codex_app(http, url, receipt=None):
    context, _ = http.request("GET", "/api/context")
    organization = context.get("organization")
    if not isinstance(organization, str) or not organization:
        raise ControlError("Use a PAT scoped to the browser-created organization.")
    prefix = "/api/organizations/" + urllib.parse.quote(organization, safe="")
    inventory, _ = http.request("GET", prefix + "/inventory")
    existing = [app for app in inventory["apps"] if app.get("slug") == "codex" or app.get("name") == "Codex"]
    if receipt:
        identity = [app for app in inventory["apps"] if app.get("id") == receipt.get("id")]
        if (receipt.get("organization") != organization or receipt.get("url") != url
                or len(identity) != 1 or identity[0].get("slug") != "codex"
                or identity[0].get("name") != "Codex" or existing != identity):
            raise ControlError("The saved Codex app identity, organization, or URL changed. Inspect the dashboard; no app was imported.")
    if len(existing) > 1:
        raise ControlError("Multiple Codex apps exist. Inspect the dashboard before retrying.")
    if existing:
        app = existing[0]
    else:
        app, _ = http.request("POST", prefix + "/apps/import", {"source": {"kind": "mcp", "name": "Codex", "url": url}})
    if app.get("slug") != "codex" or not app.get("id") or not app.get("activeDeployment"):
        raise ControlError("Codex import returned an unexpected or undeployed app; inspect the dashboard.")
    source, _ = http.request("GET", prefix + "/apps/" + urllib.parse.quote(app["id"], safe="") + "/source")
    verify_app_source(source, url)
    return {"organization": organization, "id": app["id"], "url": url}


def bootstrap():
    http, session = executor_session()
    verify_compact(session)
    url = os.environ["CAS_MCP_URL"]
    parsed = urllib.parse.urlsplit(url)
    address = ipaddress.IPv4Address(parsed.hostname)
    if (parsed.scheme != "http" or parsed.port != 8088 or parsed.path != "/mcp"
            or parsed.query or parsed.fragment or parsed.username or parsed.password
            or not any(address in network for network in PRIVATE_NETWORKS)):
        raise ControlError("CAS import must use the private managed bridge gateway at port 8088 and /mcp.")
    cas = Mcp(Http(url.removesuffix("/mcp")), "/mcp")
    if not {"list_targets", "discover_threads"}.issubset({tool["name"] for tool in cas.tools()}):
        raise ControlError("CAS readiness discovery lacks required native Codex tools.")
    state = Path(os.environ["CONTROL_PLANE_BOOTSTRAP_DIR"])
    marker = state / "codex-integration.json"
    receipt = json.loads(read_private(marker)) if marker.exists() or marker.is_symlink() else None
    receipt = ensure_codex_app(http, url, receipt)
    write_private(marker, json.dumps(receipt) + "\n")
    search_codex(session)
    print("Codex import retained; authenticated browser MCP and Codex discovery ready.")


def probe(resume=False):
    state = Path(os.environ["CONTROL_PLANE_BOOTSTRAP_DIR"])
    pending = state / "browser-approval.json"
    if resume:
        record = json.loads(read_private(pending))
        if not isinstance(record, dict) or not isinstance(record.get("mcpSession"), dict):
            raise ControlError("The pending receipt lacks its original MCP session metadata. Recover that metadata before resuming; no new execution was started.")
        _, session = executor_session(record["mcpSession"])
        verify_compact(session)
        result = session.call("tools/call", {"name": "resume", "arguments": {"requestId": record["requestId"]}})
    else:
        if pending.exists() or pending.is_symlink():
            raise ControlError("A browser approval is already pending. Use resume after answering it; do not rerun execute.")
        _, session = executor_session()
        verify_compact(session)
        search_codex(session)
        result = session.call("tools/call", {"name": "execute", "arguments": {"code": "return await tools.codex.list_targets({});"}})
    data = execution(result)
    if data.get("status") == "completed" and pending.exists():
        read_private(pending)
        pending.replace(state / f"browser-approval-terminal-{time.time_ns()}.json")
    if data.get("status") == "unavailable":
        raise ControlError("Continuation unavailable; its pending receipt is retained. Verify the original MCP session and browser request before retrying resume. Do not rerun execute.")
    if data.get("status") == "busy":
        print("Continuation still busy; its pending receipt is retained. Retry resume without rerunning execute.")
        return 3
    if data.get("status") in {"approval-required", "input-required"}:
        approval_url = urllib.parse.urlsplit(data["approvalUrl"])
        if (approval_url.scheme != "http" or approval_url.hostname != "127.0.0.1"
                or approval_url.port != 4312 or approval_url.username or approval_url.password):
            raise ControlError("Approval URL does not match the configured browser origin.")
        write_private(pending, json.dumps({"requestId": data["requestId"], "approvalUrl": data["approvalUrl"],
                      "mcpSession": session.session_state()}) + "\n")
        print("Browser approval pending. Answer it in the signed-in Executor browser, then run the resume probe.")
        return 3
    if data.get("status") != "completed" or not data.get("execution", {}).get("ok"):
        raise ControlError("The harmless Codex read did not complete; details omitted.")
    native = data["execution"]["value"]
    if native.get("isError"):
        raise ControlError("The native Codex read returned an MCP error; details omitted.")
    payload = native.get("structuredContent")
    if payload is None:
        payload = json.loads(next(block["text"] for block in native["content"] if block.get("type") == "text"))
    if payload.get("error") or not isinstance(payload.get("result", {}).get("targets"), list):
        raise ControlError("Unexpected native target-list response; contents omitted.")
    pending.unlink(missing_ok=True)
    write_private(state / "read-acceptance.json", json.dumps({"completed": True, "target_count": len(payload["result"]["targets"])}) + "\n")
    print("Harmless native Codex read completed through Executor; target contents omitted.")
    return 0


def status():
    for row in compose_rows():
        print(f"{row['Service']}: {row['State']} {row.get('Health', '')}".rstrip())
    print("Browser and ChatGPT acceptance require their separate live gates.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("first-run", "secrets", "check", "up", "down", "status", "bootstrap", "probe", "resume"))
    args = parser.parse_args()
    try:
        if args.mode in {"bootstrap", "probe", "resume"}:
            def expire(_signal, _frame):
                raise ControlError("The bounded bootstrap/probe deadline expired.")
            signal.signal(signal.SIGALRM, expire)
            signal.alarm(180)
        if args.mode == "bootstrap":
            bootstrap()
        elif args.mode in {"probe", "resume"}:
            return probe(args.mode == "resume")
        elif args.mode == "status":
            status()
        elif args.mode == "down":
            compose("down", "--timeout", "30", timeout=90)
            print("Control-plane containers stopped; persistent data and secret files retained.")
        else:
            dotenv = credential_dotenv() if args.mode != "first-run" else {}
            configuration = config()
            if args.mode == "secrets":
                save_secrets(configuration, dotenv)
                return 0
            network_preflight(configuration)
            if args.mode == "first-run":
                compose("up", "-d", "--wait", "--wait-timeout", "120", "executor", timeout=150)
                print("Executor ready at http://127.0.0.1:4312/. Complete browser owner, organization, and PAT setup.")
                return 0
            image = configuration["services"]["codex-action-server"]["image"]
            local_build = "build" in configuration["services"]["codex-action-server"]
            if not local_build and not re.fullmatch(r"ghcr\.io/joshyorko/codex-action-server(?:@sha256:[0-9a-f]{64}|:sha-[0-9a-f]{40})", image):
                raise ControlError("Production CAS_IMAGE must be the published immutable digest or full SHA tag.")
            materialize_secrets(configuration, dotenv=dotenv)
            prepare(configuration)
            validate_secrets(configuration)
            refuse_external_tunnel()
            if args.mode == "check":
                print("Compose paths, socket ownership, private files, immutable image and bridge collision checks passed; no service started.")
            else:
                compose("up", "-d", "--wait", "--wait-timeout", "300", timeout=330)
                status()
    except ControlError as error:
        print(str(error), file=sys.stderr)
        return 2
    except Exception:
        print("Control-plane setup/probe failed; raw errors and private values omitted.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
