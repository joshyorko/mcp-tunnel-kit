"""Fixed, bounded Kubernetes diagnostics for the operator-pinned Devsy worker."""
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess


class DiagnosticError(Exception):
    pass


TOOL = {
    'name': 'workspace_diagnostics',
    'description': 'Read CPU, RAM, disk capacity, startup/process and native Codex daemon metadata for the exact '
                   'operator-pinned or verified scope-owned Kubernetes workspace. No caller-supplied commands, '
                   'credentials, lifecycle operations, or daemon restart.',
    'inputSchema': {'type': 'object', 'additionalProperties': False,
                    'properties': {'name': {'type': 'string'},
                                   'workspace_uid': {'type': 'string'}},
                    'required': ['name', 'workspace_uid']},
}

COMMAND = r'''set -eu
export LC_ALL=C
for item in /proc/[0-9]*; do
  test "${item##*/}" != "$$" || continue
  if test -r "$item/comm"; then
    read -r name < "$item/comm" || continue
    case "$name" in
      bash|sh|git|curl|brew|ruby|codex|python3|devsy|node|npm|uv|rtk|headroom)
        printf 'process=%s:%s\n' "${item##*/}" "$name" ;;
    esac
    worker_command_line=$(tr '\000' ' ' < "$item/cmdline" 2>/dev/null || :)
    case "$worker_command_line" in *scripts/remote/setup.sh*) printf 'stage=worker_setup\n';; esac
    case "$worker_command_line" in *scripts/remote/verify.sh*) printf 'stage=worker_verify\n';; esac
    case "$worker_command_line" in *devcontainer-post-create.sh*) printf 'stage=image_post_create\n';; esac
  fi
done
if test -x /home/vscode/.local/bin/codex; then
  printf 'codex_binary=present\n'
  printf 'codex_version=%s\n' "$(timeout 5s su -s /bin/sh -c 'CODEX_HOME=/home/vscode/.codex /home/vscode/.local/bin/codex --version' vscode 2>/dev/null || :)"
else printf 'codex_binary=absent\n'; fi
if test -S /home/vscode/.codex/app-server-control/app-server-control.sock; then printf 'daemon_socket=present\n';
else printf 'daemon_socket=absent\n'; fi
if test -f /home/vscode/.codex/auth.json; then printf 'auth_file=present\n';
else printf 'auth_file=absent\n'; fi
if test -x /home/vscode/.local/bin/codex; then
  if timeout 8s su -s /bin/sh -c 'CODEX_HOME=/home/vscode/.codex /home/vscode/.local/bin/codex login status' vscode >/dev/null 2>&1; then
    printf 'auth_status=authenticated\n'
  else
    worker_login_status=$?
    if test "$worker_login_status" = 1; then printf 'auth_status=not_authenticated\n';
    else printf 'auth_status=unverified\n'; fi
  fi
fi
printf 'daemon_begin\n'
if test -x /home/vscode/.local/bin/codex; then
  timeout 8s su -s /bin/sh -c 'CODEX_HOME=/home/vscode/.codex /home/vscode/.local/bin/codex app-server daemon version' vscode 2>/dev/null || :
fi
printf '\ndaemon_end\n'
timeout 3s python3 - <<'PY' || printf 'capacity_status=unavailable\n'
import json, os, shutil
from pathlib import Path
memory = {}
for line in Path('/proc/meminfo').read_text().splitlines():
    key, value = line.split(':', 1)
    if key in {'MemTotal', 'MemAvailable'}:
        memory[key] = int(value.strip().split()[0]) * 1024
cores = float(len(os.sched_getaffinity(0)))
quota = None
try:
    amount, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
    if amount != 'max':
        quota = int(amount) / int(period)
        cores = min(cores, quota)
except (OSError, ValueError):
    pass
limit = current = None
available = memory.get('MemAvailable', 0)
try:
    raw = Path('/sys/fs/cgroup/memory.max').read_text().strip()
    current = int(Path('/sys/fs/cgroup/memory.current').read_text())
    if raw != 'max':
        limit = int(raw)
        available = min(available, max(0, limit - current))
except (OSError, ValueError):
    pass
workspace = Path('/workspaces') / os.environ.get('DEVSY_WORKSPACE_ID', '')
if not workspace.is_dir():
    workspace = Path('/workspaces')
disk = shutil.disk_usage(workspace)
print('capacity=' + json.dumps({'cpu_effective_cores': cores, 'cpu_quota_cores': quota,
    'memory_available_bytes': available, 'memory_limit_bytes': limit, 'memory_current_bytes': current,
    'workspace_total_bytes': disk.total, 'workspace_used_bytes': disk.used, 'workspace_free_bytes': disk.free}))
PY
'''


def _identity(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}', value):
        raise DiagnosticError('Invalid diagnostic identity; no command ran.')
    return value


def _private_json(source):
    source = Path(source)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise DiagnosticError('Diagnostic scope must be a private operator-owned target file.')
    return json.loads(source.read_text())


def _run(arguments, environment):
    try:
        result = subprocess.run(arguments, env=environment, capture_output=True,
                                text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DiagnosticError('Worker diagnostic transport failed or timed out; no lifecycle action ran.') from None
    if result.returncode or len(result.stdout) > 64 * 1024:
        raise DiagnosticError('Worker diagnostic transport failed; raw output omitted.')
    return result.stdout


def diagnose(source, arguments, call, environment, *, selection=None):
    if not isinstance(arguments, dict) or set(arguments) != {'name', 'workspace_uid'}:
        raise DiagnosticError('Diagnostics accept only name and workspace_uid, never a command.')
    selected = selection if selection is not None else _private_json(source)['targets']['devsy']
    expected = {key: _identity(selected[key])
                for key in ['context', 'provider', 'workspace', 'workspace_uid']}
    if (expected['provider'] != 'kubernetes' or arguments['name'] != expected['workspace']
            or arguments['workspace_uid'] != expected['workspace_uid']):
        raise DiagnosticError('Workspace does not match the authorized diagnostic scope.')
    response = call('workspace_status', {'name': expected['workspace']})
    if response.get('isError'):
        raise DiagnosticError('Workspace metadata is unavailable; no remote command ran.')
    row = response.get('structuredContent')
    if row is None:
        row = json.loads(next(item['text'] for item in response['content'] if item['type'] == 'text'))
    if (row.get('id') != expected['workspace'] or row.get('uid') != expected['workspace_uid']
            or row.get('context') != expected['context']
            or row.get('provider', {}).get('name') != expected['provider']):
        raise DiagnosticError('Live workspace identity changed; no remote command ran.')
    options = row['provider']['options']
    context = _identity(options['KUBERNETES_CONTEXT']['value'])
    namespace = _identity(options['KUBERNETES_NAMESPACE']['value'])
    kubeconfig = options['KUBERNETES_CONFIG']['value']
    if not isinstance(kubeconfig, str) or not Path(kubeconfig).is_absolute():
        raise DiagnosticError('Workspace kubeconfig must be an absolute operator path.')
    if selection is not None and (context != selection['kubernetes_context']
            or namespace != selection['namespace'] or kubeconfig != selection['kubeconfig']):
        raise DiagnosticError('Workspace cluster identity changed; no remote command ran.')
    prefix = ['kubectl', '--kubeconfig', kubeconfig, '--context', context, '-n', namespace]
    pods = json.loads(_run(prefix + ['get', 'pods', '-l',
        'devsy.sh/workspace-uid=' + expected['workspace_uid'], '-o', 'json'], environment))['items']
    if len(pods) != 1:
        raise DiagnosticError('Diagnostic scope requires exactly one matching pod.')
    pod = pods[0]
    name = _identity(pod['metadata']['name'])
    if (pod['metadata'].get('namespace') != namespace
            or pod['metadata'].get('labels', {}).get('devsy.sh/workspace-uid') != expected['workspace_uid']
            or not any(container['name'] == 'devsy' for container in pod['spec']['containers'])):
        raise DiagnosticError('Pod does not match the selected workspace.')
    report = {'workspace': expected, 'pod': name, 'pod_uid': pod['metadata']['uid'],
              'pod_phase': pod.get('status', {}).get('phase'), 'native_daemon': {'status': 'unverified'}}
    if report['pod_phase'] != 'Running':
        return report
    output = _run(prefix + ['exec', name, '-c', 'devsy', '--', '/bin/bash', '-c', COMMAND], environment)
    report['processes'] = []
    report['active_setup_stages'] = []
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        if separator and key in {'codex_binary', 'daemon_socket', 'auth_file'} and value in {'present', 'absent'}:
            report[key] = value
        elif key == 'process' and re.fullmatch(r'[0-9]+:[a-z0-9]+', value):
            pid, name = value.split(':')
            report['processes'].append({'pid': int(pid), 'name': name})
        elif key == 'stage' and value in {'worker_setup', 'worker_verify', 'image_post_create'}:
            if value not in report['active_setup_stages']:
                report['active_setup_stages'].append(value)
        elif key == 'codex_version' and re.fullmatch(r'codex(?:-cli)? [0-9][A-Za-z0-9_.+-]{0,80}', value):
            report[key] = value
        elif key == 'auth_status' and value in {'authenticated', 'not_authenticated', 'unverified'}:
            report[key] = value
        elif key == 'capacity':
            try:
                capacity = json.loads(value)
                fields = {'cpu_effective_cores', 'cpu_quota_cores', 'memory_available_bytes',
                          'memory_limit_bytes', 'memory_current_bytes', 'workspace_total_bytes',
                          'workspace_used_bytes', 'workspace_free_bytes'}
                report['capacity'] = {field: number for field, number in capacity.items() if field in fields
                                      and (number is None or type(number) in {int, float}
                                           and math.isfinite(number) and number >= 0)}
            except (ValueError, TypeError, AttributeError):
                report['capacity'] = {'status': 'unavailable'}
    if 'daemon_begin\n' in output and '\ndaemon_end' in output:
        native = output.split('daemon_begin\n', 1)[1].split('\ndaemon_end', 1)[0].strip()
        try:
            version = json.loads(native)
        except ValueError:
            version = {}
        report['native_daemon'] = {key: version[key] for key in ['status', 'version', 'socketPath', 'appServerVersion', 'serverVersion']
                                   if key in version and isinstance(version[key], str)} or {'status': 'unverified'}
    again = json.loads(_run(prefix + ['get', 'pod', report['pod'], '-o', 'json'], environment))
    if again['metadata']['uid'] != report['pod_uid']:
        raise DiagnosticError('Pod identity changed during diagnostics; discard the result.')
    return report
