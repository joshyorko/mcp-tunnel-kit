#!/usr/bin/env python3
"""Trusted runner -> Kamal accessories -> private VM operations."""
import argparse
import base64
import contextlib
import copy
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
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
from devsy_vm_bootstrap import MISSING_KUBECTL_REASON
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
MEMORYD_ORDER=('memoryd','memoryd-mcp')
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
    for name in ('instance_profile','prepare_recovery_generation','devsy_vm_bootstrap','scope_binding_rebind','bridge_kubectl_path'):
        source=(ROOT/'scripts'/(name+'.py')).read_text()
        bootstrap+=('_module=types.ModuleType('+repr(name)+')\n'
                    +'_module.__file__='+repr(str(ROOT/'scripts'/(name+'.py')))+'\n'
                    +'sys.modules['+repr(name)+']=_module\n'
                    +'exec('+repr(source)+',_module.__dict__)\n')
    source=bootstrap+(ROOT/'scripts/vm_deploy_host.py').read_text()
    payload=base64.b64encode(zlib.compress(source.encode(),9)).decode()
    return f"import base64,zlib;exec(compile(zlib.decompress(base64.b64decode({payload!r})), '<mcp-private-vm>', 'exec'))"


def devsy_payload():
    """Ship only reviewed nonsecret Devsy policy and source inputs to the VM boundary."""
    scripts = str(Path(VMROOT) / "scripts")
    starter = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.path.insert(0, " + repr(scripts) + ")\n"
        "from host_devsy_service import main\n"
        "raise SystemExit(main())\n"
    )
    return {
        "policy": json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text()),
        "unit_template": (ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        "starter_source": starter,
    }


def profile():
    if INSTANCE is None:raise ValueError('Private instance profile must be loaded before rendering deployment configuration')
    vm=INSTANCE['vm'];native=Path(vm['native_ssh_dir']);devsy=vm['devsy']
    return {'host':HOST,'network':vm['network'],'ssh_user':INSTANCE['deploy_host']['user'],'ssh_key':str(KEY),'ssh_known_hosts':str(KNOWN),'ssh_config':str(SSH),'state_dir':vm['state_dir'],'repo_dir':VMROOT,
            'cas_ssh_config_source':str(native/'ssh_config.native'),'cas_ssh_known_hosts_source':str(native/'known_hosts.native'),'cas_identity_source':str(native/'identity'),
            'devsy':devsy}


def kamal(config,operation,name):
    # Public images only. Never run the unrelated top-level app/proxy/registry commands.
    if operation not in ('boot','reboot','start','stop','details') or name not in (*ORDER,*MEMORYD_ORDER):raise ValueError('Unsupported Kamal operation')
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


def native_codex_tuple(args, *, require_valid=True):
    """Return an explicit operator-supplied target/thread/worktree tuple."""
    values = [getattr(args, name, None) for name in (
        "native_target", "native_cwd", "native_thread_id")]
    values = [value or None for value in values]
    if not any(values):
        return None
    target, cwd, thread_id = values
    valid = (all(isinstance(value, str) and value for value in values)
             and bool(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", target)))
    if valid:
        path = PurePosixPath(cwd)
        valid = (path.is_absolute() and ".." not in path.parts and str(path) == cwd
                 and not any(ord(char) < 32 for char in cwd)
                 and bool(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", thread_id)))
    if not valid and require_valid:
        raise ValueError("native Codex tuple must explicitly bind a safe target name, cwd, and thread id")
    return {"target": target, "cwd": cwd, "thread_id": thread_id}


def smoke_request(native_tuple, *, require_native=False):
    return {"native_codex": native_tuple, "require_native": bool(require_native)}


def smoke(native_tuple, *, require_native=False):
    result = remote("smoke", smoke_request(native_tuple, require_native=require_native))
    if require_native and result.get("native_read", {}).get("status") != "PASS":
        raise RuntimeError("Qualified native read failed; production changes were not started")
    return result


def scope_binding_operation(native_tuple, source_sha, *, apply=False, bridge_path=False):
    """Keep the deployed source and all Kamal accessories untouched."""
    approval_file = 'config/issue27-bridge-kubectl-path.json' if bridge_path else 'config/issue27-scope-binding-rebind.json'
    approval = json.loads((ROOT / approval_file).read_text())
    before = remote('snapshot')
    current = remote('current')
    if (before.get('authority') != 'kamal' or before.get('tunnel_count') != 1
            or not current or current.get('identity') != before.get('identity')
            or before.get('source_sha') != approval['host_apply_source_sha']
            or current.get('source_sha') != before.get('source_sha')):
        raise ValueError('Scope repair requires the recorded healthy Kamal identity')
    remote('lifecycle-check')
    remote('profile')
    smoke(native_tuple, require_native=True)
    payload = {**devsy_payload(),
               'approval': approval,
               'scope_document': json.loads((ROOT / 'docs/devsy-worker-scope.proposed.json').read_text())}
    action = ('devsy-bridge-path-apply' if apply else 'devsy-bridge-path-check') if bridge_path else (
        'devsy-scope-rebind' if apply else 'devsy-scope-rebind-check')
    if apply:
        payload.update(approved=True, controller_sha=source_sha)
    result = remote(action, payload)
    after = remote('snapshot')
    if after != before:
        raise RuntimeError('Control-plane snapshot changed during scope repair; stop and inspect receipt')
    remote('lifecycle-check')
    smoke(native_tuple, require_native=True)
    return {**result, 'native_read': 'PASS', 'accessories_unchanged': True,
            'identity_preserved': True, 'source_unchanged': True}


def _devsy_plan_fingerprint(plan):
    return {key: plan.get(key) for key in (
        "tap_revision", "devsy_current_version", "provider", "systemd_unit",
        "bridge_starter", "service_active", "service_enabled")}


def _devsy_plan_fingerprint_differences(before, after):
    before_fingerprint = _devsy_plan_fingerprint(before)
    after_fingerprint = _devsy_plan_fingerprint(after)
    return [key for key in before_fingerprint
            if before_fingerprint[key] != after_fingerprint[key]]


def _host_devsy_apply_failure_code(error):
    """Expose only the VM bootstrap's allowlisted phase and safe error category."""
    detail = str(error)
    boundary = "Deployment boundary refused: "
    if boundary in detail:
        detail = detail.split(boundary, 1)[1]
    if detail == (
            "Devsy apply stopped before provider or Devsy changes; "
            "staged kubectl rollback failed"):
        return "kubectl-staging:rollback-failed"

    preflight_prefixes = (
        "Devsy apply stopped before provider or Devsy changes: ",
        "ROR admission preflight is blocked: ",
    )
    preflight_reason = None
    for prefix in preflight_prefixes:
        if detail.startswith(prefix):
            preflight_reason = detail[len(prefix):]
            break
    if preflight_reason is not None:
        if preflight_reason.startswith("ROR admission preflight remains blocked: "):
            preflight_reason = preflight_reason[
                len("ROR admission preflight remains blocked: "):]
        rollback_suffix = "; staged kubectl was rolled back"
        if preflight_reason.endswith(rollback_suffix):
            preflight_reason = preflight_reason[:-len(rollback_suffix)]
        preflight_codes = {
            "pinned Kubernetes kubectl source is unavailable": "kubectl-download:source-unavailable",
            "pinned Kubernetes kubectl download timed out": "kubectl-download:timeout",
            "pinned kubectl source URL is invalid": "kubectl-download:source-policy-invalid",
            "pinned kubectl does not support this Linux architecture": "kubectl-download:architecture-unsupported",
            "pinned Kubernetes kubectl exceeds its size limit": "kubectl-artifact:size-limit",
            "pinned Kubernetes kubectl checksum mismatch": "kubectl-artifact:checksum-mismatch",
            "kubectl candidate failed pinned source/hash validation": "kubectl-path:untrusted-existing",
            "installed pinned kubectl failed source/hash verification": "kubectl-path:verification-failed",
            "pinned kubectl is missing; ROR admission preflight was not run": "kubectl-path:missing-after-staging",
            "ROR Kubernetes authentication failed": "ror-kubectl:authentication",
            "ROR Kubernetes authorization failed": "ror-kubectl:authorization",
            "ROR Kubernetes connection failed": "ror-kubectl:connection",
            "ROR Kubernetes connection timed out": "ror-kubectl:connection-timeout",
            "ROR Kubernetes admission request rejected": "ror-admission:rejected",
            "ROR Kubernetes command failed; raw output withheld": "ror-kubectl:unclassified",
            "authorized ROR namespace devsy is unavailable": "ror-admission:namespace-unavailable",
            "ROR devsy quota or LimitRange changed; resource admission needs review": "ror-admission:constraints-changed",
            "ROR has no ready worker node matching the Devsy selector": "ror-admission:no-ready-worker",
            "ROR worker allocatable capacity cannot admit the bounded Devsy request": "ror-admission:capacity-insufficient",
            "ROR default storage class drift; PVC admission needs review": "ror-admission:storage-class-drift",
            "ROR returned invalid Kubernetes inventory": "ror-admission:invalid-inventory",
        }
        return preflight_codes.get(preflight_reason, "preflight:unclassified")

    marker = "Devsy apply failed at "
    if not detail.startswith(marker):
        return "unclassified"
    rest = detail[len(marker):]
    phase = rest.split(":", 1)[0].split(";", 1)[0]
    allowed_phases = {
        "stop-service", "homebrew", "tap", "devsy-install", "provider-config",
        "provider-readback", "bridge-starter", "systemd-unit", "service-start",
        "live-verification", "receipt",
    }
    if phase not in allowed_phases:
        return "unclassified"

    reason = rest.split(": ", 1)[1].split("; ", 1)[0] if ": " in rest else ""
    reason_codes = {
        "ROR provider readback did not match the approved resource policy": "provider-policy-mismatch",
        "running host kubectl failed pinned version/checksum verification": "kubectl-checksum-mismatch",
        "systemd unit readback did not match the managed unit": "systemd-unit-mismatch",
        "systemd Devsy unit identity or health readback failed": "systemd-unit-health",
        "running bridge does not use the tap-managed Devsy binary": "bridge-binary-binding",
        "running bridge Devsy binary failed version/checksum verification": "bridge-binary-checksum",
        "running bridge process identity did not match its receipt": "bridge-process-identity",
        "Host Devsy bridge health identity check failed": "bridge-health-identity",
        "VM Devsy bootstrap command failed; raw output withheld": "host-command-failed",
    }
    return f"{phase}:{reason_codes[reason]}" if reason in reason_codes else phase


def _host_tap_control_plane_guard(native_tuple):
    before = remote("snapshot")
    if before.get("authority") != "kamal" or before.get("tunnel_count") != 1:
        raise ValueError("Homebrew tap operation requires the healthy Kamal owner and one tunnel client")
    remote("lifecycle-check")
    current = remote("current")
    if (not isinstance(current, dict) or current.get("authority") != "kamal"
            or current.get("identity") != before.get("identity")):
        raise ValueError("Homebrew tap operation requires the recorded healthy Kamal generation")
    smoke(native_tuple, require_native=True)
    return before


def _verify_host_tap_control_plane(before, native_tuple):
    remote("lifecycle-check")
    after = remote("snapshot")
    if (after.get("authority") != "kamal"
            or after.get("identity") != before.get("identity")
            or after.get("inventory") != before.get("inventory")
            or after.get("source_sha") != before.get("source_sha")
            or after.get("tunnel_count") != 1):
        raise RuntimeError("Homebrew tap operation changed control-plane identity, source or accessories")
    smoke(native_tuple, require_native=True)
    return after


def _check_host_tap_reconciliation(native_tuple):
    before = _host_tap_control_plane_guard(native_tuple)
    plan = remote("devsy-tap-reconcile-plan", devsy_payload())
    after = _verify_host_tap_control_plane(before, native_tuple)
    return {"operation": "devsy-tap-reconcile-check", "ready": plan.get("ready") is True,
            "plan": plan, "identity_preserved": True,
            "accessories_unchanged": True, "source_unchanged": True,
            "tunnel_count": after["tunnel_count"], "mutated": False}


def _reconcile_host_tap(native_tuple, source_sha, github_run_id, github_run_attempt):
    payload = devsy_payload()
    before = _host_tap_control_plane_guard(native_tuple)
    plan = remote("devsy-tap-reconcile-plan", payload)
    if plan.get("ready") is not True:
        raise ValueError("Homebrew tap reconciliation plan is blocked: "
                         + str(plan.get("reason", "no ready plan returned")))
    run_identity = {"github_run_id": github_run_id,
                    "github_run_attempt": github_run_attempt}
    phase = "host-tap-reconciliation"
    changed = False
    try:
        result = remote("devsy-tap-reconcile", {
            **payload, "approved": True, "source_sha": source_sha, **run_identity,
        })
        if (result.get("operation") != "devsy-tap-reconcile"
                or result.get("status") not in ("completed", "already-reconciled")
                or type(result.get("changed")) is not bool):
            raise RuntimeError("Host tap reconciliation receipt was invalid")
        changed = result["changed"]
        phase = "tap-receipt-check"
        verified = remote("devsy-tap-reconcile-plan", payload)
        if (verified.get("ready") is not True
                or verified.get("status") != "already-reconciled"):
            raise RuntimeError("Host tap reconciliation receipt did not match the live tap")
        phase = "control-plane-check"
        after = _verify_host_tap_control_plane(before, native_tuple)
        return {"operation": "devsy-tap-reconcile", "host_tap": result,
                "verified_plan": verified, "identity_preserved": True,
                "accessories_unchanged": True, "source_unchanged": True,
                "tunnel_count": after["tunnel_count"], "native_read": "PASS"}
    except Exception as error:
        if changed:
            try:
                rollback = remote("devsy-tap-rollback", {
                    **payload, "approved": True, **run_identity,
                })
                if rollback.get("restored") is not True:
                    raise RuntimeError("protected rollback receipt was invalid")
            except Exception:
                raise RuntimeError("Homebrew tap reconciliation failed at " + phase
                                   + "; protected tap rollback FAILED; operator recovery required") from None
            raise RuntimeError("Homebrew tap reconciliation failed at " + phase
                               + "; protected tap rollback restored the observed tap") from None
        failure = str(error) if isinstance(error, (RuntimeError, ValueError)) else type(error).__name__
        raise RuntimeError("Homebrew tap reconciliation failed at " + phase + ": " + failure) from None


def _check_host_tap_rollback(native_tuple, github_run_id, github_run_attempt):
    before = _host_tap_control_plane_guard(native_tuple)
    plan = remote("devsy-tap-rollback-plan", {
        **devsy_payload(), "github_run_id": github_run_id,
        "github_run_attempt": github_run_attempt,
    })
    after = _verify_host_tap_control_plane(before, native_tuple)
    return {"operation": "devsy-tap-rollback-check", "ready": plan.get("ready") is True,
            "plan": plan, "identity_preserved": True,
            "accessories_unchanged": True, "source_unchanged": True,
            "tunnel_count": after["tunnel_count"], "mutated": False}


def _rollback_host_tap(native_tuple, github_run_id, github_run_attempt):
    payload = devsy_payload()
    before = _host_tap_control_plane_guard(native_tuple)
    run_identity = {"github_run_id": github_run_id,
                    "github_run_attempt": github_run_attempt}
    plan = remote("devsy-tap-rollback-plan", {**payload, **run_identity})
    if plan.get("ready") is not True:
        raise ValueError("Homebrew tap rollback plan is blocked: "
                         + str(plan.get("reason", "no ready rollback plan returned")))
    restored = remote("devsy-tap-rollback", {
        **payload, "approved": True, **run_identity,
    })
    if restored.get("restored") is not True:
        raise RuntimeError("Host tap rollback receipt was invalid")
    after = _verify_host_tap_control_plane(before, native_tuple)
    return {"operation": "devsy-tap-rollback", "host_tap": restored,
            "identity_preserved": True, "accessories_unchanged": True,
            "source_unchanged": True, "tunnel_count": after["tunnel_count"],
            "native_read": "PASS"}


def _attested_missing_kubectl_plan(plan, policy):
    """Allow only the exact pinned-tool absence that apply can safely stage."""
    if not isinstance(plan, dict) or not isinstance(policy, dict):
        return False
    configured = policy.get("kubectl")
    observation = plan.get("observed")
    changes = plan.get("changes")
    if (not isinstance(configured, dict) or not isinstance(observation, dict)
            or not isinstance(changes, list)):
        return False
    observed = observation.get("kubectl")
    if not isinstance(observed, dict):
        return False
    architecture = observed.get("platform")
    if architecture != "x86_64":
        return False
    expected_hash = configured.get("artifact_sha256", {}).get(architecture)
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
        return False
    return (
        plan.get("ready") is False
        and plan.get("status") == "blocked"
        and plan.get("cluster") == {
            "ready": False, "status": "blocked",
            "reason": MISSING_KUBECTL_REASON,
        }
        and "install-pinned-kubectl" in changes
        and observed == {
            "status": "missing", "platform": architecture,
            "version": configured.get("version"), "sha256": None,
            "target_sha256": expected_hash,
            "install_location": configured.get("install_location"),
            "managed_path_present": False,
        }
    )


def _apply_host_devsy(native_tuple, source_sha):
    payload = devsy_payload()
    before = remote("snapshot")
    if before.get("authority") != "kamal" or before.get("tunnel_count") != 1:
        raise ValueError("Host Devsy apply requires the healthy Kamal owner and one tunnel client")
    remote("lifecycle-check")
    current = remote("current")
    if (not isinstance(current, dict) or current.get("authority") != "kamal"
            or current.get("identity") != before.get("identity")):
        raise ValueError("Host Devsy apply requires the recorded healthy Kamal generation")
    previous = remote("previous")
    plan_before = remote("devsy-plan", payload)
    if (plan_before.get("ready") is not True or plan_before.get("status") == "blocked") and not (
            _attested_missing_kubectl_plan(plan_before, payload["policy"])):
        raise ValueError("Host Devsy plan is blocked; no source or host changes were started")
    smoke(native_tuple, require_native=True)
    old_source_sha = before["source_sha"]
    changed = False
    phase = "source-sync"
    try:
        sync_source(source_sha)
        phase = "host-apply"
        applied = remote("devsy-apply", {
            **payload, "approved": True, "source_sha": source_sha,
        })
        if applied.get("operation") != "apply" or type(applied.get("changed")) is not bool:
            raise RuntimeError("Host Devsy apply receipt was invalid")
        changed = applied["changed"]
        phase = "drift-check"
        verified = remote("devsy-check", payload)
        if verified.get("status") != "current":
            raise RuntimeError("Host Devsy drift check failed")
        phase = "control-plane-check"
        after = remote("snapshot")
        if (after.get("identity") != before.get("identity")
                or after.get("inventory") != before.get("inventory")
                or after.get("tunnel_count") != 1
                or after.get("authority") != "kamal"):
            raise RuntimeError("control-plane identity or accessory state changed")
        phase = "native-acceptance"
        smoke(native_tuple, require_native=True)
        generation = dict(current)
        generation.update(authority="kamal", source_sha=source_sha,
                          identity=after["identity"])
        if not generation.get("publication_proof"):
            generation["publication_proof"] = prove_images(generation["manifest"], generation)
        phase = "generation-commit"
        remote("commit", generation)
        return {"operation": "devsy-apply", "source_sha": source_sha,
                "host_devsy": applied, "drift_check": "PASS",
                "native_read": "PASS", "identity_preserved": True,
                "accessories_unchanged": True,
                "rollback_ready": bool(applied.get("rollback_ready", not changed))}
    except Exception as error:
        host_apply_failure = (
            _host_devsy_apply_failure_code(error) if phase == "host-apply" else None
        )
        rollback_stage = "source-restore"
        rollback_failures = []
        try:
            try:
                sync_source(old_source_sha)
            except Exception:
                rollback_failures.append("source-restore")
            if changed:
                rollback_stage = "host-devsy-restore"
                remote("devsy-rollback", payload)
            rollback_stage = "control-plane-snapshot"
            restored = remote("snapshot")
            if (not isinstance(restored, dict)
                    or restored.get("source_sha") != old_source_sha
                    or restored.get("identity") != before.get("identity")
                    or restored.get("inventory") != before.get("inventory")
                    or restored.get("tunnel_count") != 1):
                rollback_failures.append("control-plane-snapshot")
            rollback_stage = "devsy-plan"
            plan_restored = remote("devsy-plan", payload)
            if not isinstance(plan_restored, dict):
                rollback_failures.append("devsy-plan:unavailable")
            else:
                plan_differences = _devsy_plan_fingerprint_differences(
                    plan_before, plan_restored,
                )
                if plan_differences:
                    rollback_failures.append("devsy-plan:" + ",".join(plan_differences))
            if rollback_failures:
                rollback_stage = rollback_failures[-1]
                raise RuntimeError("rollback verification differed from the prior state")
            rollback_stage = "generation-commit"
            remote("rollback-commit", {"current": current, "previous": previous})
        except Exception:
            failed_stages = rollback_failures.copy()
            if rollback_stage not in failed_stages:
                failed_stages.append(rollback_stage)
            failure_label = ("; host-apply-phase=" + host_apply_failure
                             if host_apply_failure else "")
            raise RuntimeError("Host Devsy apply failed at " + phase + failure_label
                               + "; automatic rollback FAILED at " + ",".join(failed_stages)
                               + "; operator recovery required") from None
        failure_label = ("; host-apply-phase=" + host_apply_failure
                         if host_apply_failure else "")
        raise RuntimeError("Host Devsy apply failed at " + phase + failure_label
                           + "; previous host state restored") from None


def _rollback_host_devsy(native_tuple):
    payload = devsy_payload()
    before = remote("snapshot")
    if before.get("authority") != "kamal" or before.get("tunnel_count") != 1:
        raise ValueError("Host Devsy rollback requires the healthy Kamal owner and one tunnel client")
    remote("lifecycle-check")
    current = remote("current")
    if (not isinstance(current, dict) or current.get("authority") != "kamal"
            or current.get("identity") != before.get("identity")):
        raise ValueError("Host Devsy rollback requires the recorded healthy Kamal generation")
    target = remote("devsy-rollback-plan", payload)
    target_sha = target.get("source_sha") if isinstance(target, dict) else None
    if not isinstance(target_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", target_sha):
        raise ValueError("Host Devsy rollback plan is invalid")
    if not target.get("ready"):
        raise ValueError("Host Devsy rollback is not ready")

    sync_source(target_sha)
    restored = remote("devsy-rollback", payload)
    if restored.get("restored") is not True or restored.get("source_sha") != target_sha:
        raise RuntimeError("Host Devsy rollback receipt was invalid")
    after = remote("snapshot")
    if (after.get("source_sha") != target_sha
            or after.get("identity") != before.get("identity")
            or after.get("inventory") != before.get("inventory")
            or after.get("tunnel_count") != 1
            or after.get("authority") != "kamal"):
        raise RuntimeError("Host Devsy rollback changed control-plane identity or accessory state")
    plan_after = remote("devsy-plan", payload)
    native = smoke(native_tuple)
    generation = dict(current)
    generation.update(authority="kamal", source_sha=target_sha,
                      identity=after["identity"])
    if not generation.get("publication_proof"):
        generation["publication_proof"] = prove_images(generation["manifest"], generation)
    remote("commit", generation)
    return {"operation": "devsy-rollback", "host_devsy": restored,
            "plan_after": plan_after, "native_read": native,
            "identity_preserved": True, "accessories_unchanged": True,
            "source_sha": target_sha}


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


def restore(previous,directory,native_tuple=None):
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
    smoke(native_tuple)
    after=remote('snapshot')
    if after['identity']!=previous['identity']:raise RuntimeError('Rollback identity mismatch')
    remote('set-current',previous)
    return after


def restore_cas(previous,directory,native_tuple=None):
    config=configuration(directory,previous['manifest'])
    kamal(config,'reboot','cas');remote('wait',{'owner':'kamal','service':'cas'})
    smoke(native_tuple);after=remote('snapshot')
    if after['identity']!=previous['identity']:raise RuntimeError('CAS rollback identity mismatch')
    if after['source_sha']!=previous['source_sha']:raise RuntimeError('CAS rollback found source drift; full deployment reconciliation required')
    remote('set-current',previous)
    return after


def deploy_memoryd(source_sha, directory):
    """Add only the private MemoryD accessories after a read-only capacity gate."""
    before_status = remote('status')
    if (before_status.get('authority') != 'kamal' or before_status.get('healthy') is not True
            or before_status.get('tunnel_count') != 1):
        return {'operation':'memoryd','status':'BLOCKED','reason':'existing_control_plane_unhealthy_or_unowned',
                'mutated':False,'existing_status':before_status}
    before = remote('snapshot')
    if (before.get('authority') != 'kamal' or not before.get('identity')
            or before.get('tunnel_count') != 1):
        return {'operation':'memoryd','status':'BLOCKED','reason':'existing_control_plane_identity_unverified',
                'mutated':False}
    preflight = remote('memoryd-preflight')
    if preflight.get('ready') is not True:
        return {'operation':'memoryd','status':'BLOCKED','reason':preflight.get('reason','memoryd_preflight_failed'),
                'preflight':preflight,'mutated':False}
    current = remote('current')
    if (not current or current.get('authority') != 'kamal'
            or current.get('identity') != before['identity']
            or current.get('manifest') is None):
        return {'operation':'memoryd','status':'BLOCKED','reason':'deployment_receipt_changed',
                'preflight':preflight,'mutated':False}
    profile_value = profile()
    remote('profile')
    remote('network-check',profile_value['network'])
    config = configuration(directory,current['manifest'])
    phase = 'source-sync'
    try:
        sync_source(source_sha)
        phase = 'memoryd-boot'
        kamal(config,'boot','memoryd')
        phase = 'memoryd-mcp-boot'
        kamal(config,'boot','memoryd-mcp')
        phase = 'health'
        remote('memoryd-wait')
        phase = 'executor-registration'
        registration = remote('memoryd-app-register')
        phase = 'executor-discovery'
        smoke_result = smoke(None)
        after_status = remote('status')
        after = remote('snapshot')
        health = remote('memoryd-health')
        if (after_status.get('authority') != 'kamal' or after_status.get('healthy') is not True
                or after_status.get('tunnel_count') != 1
                or after.get('identity') != before['identity']
                or after.get('inventory') != before.get('inventory')
                or smoke_result.get('memoryd_discovery') != 'PASS'
                or health.get('status') != 'PASS'):
            raise RuntimeError('post-deploy acceptance mismatch')
        return {'operation':'memoryd','status':'PASS','services':health,
                'registration':registration,'existing_identity_preserved':True,
                'existing_inventory_preserved':True,'tunnel_count':after_status['tunnel_count'],
                'source_sha':source_sha,'preflight':preflight}
    except Exception:
        raise RuntimeError('MemoryD deployment failed during '+phase+'; existing control plane was not restarted. Inspect the additive accessories before retrying.') from None


def execute(args):
    host_tap_operations = (
        'devsy-tap-reconcile-check', 'devsy-tap-reconcile',
        'devsy-tap-rollback-check', 'devsy-tap-rollback',
    )
    native_tuple = native_codex_tuple(
        args, require_valid=args.operation in ('adopt','cas','deploy','devsy-apply')
        or args.operation in host_tap_operations)
    if args.operation in host_tap_operations and native_tuple is None:
        raise ValueError('qualified native Codex tuple is required for protected Homebrew tap operations')
    if INSTANCE is None:
        configure_instance(getattr(args,'instance_profile',None) or os.environ.get('KAMAL_INSTANCE_PROFILE',DEFAULT_INSTANCE_PROFILE))
    trusted_context(os.environ,args.local)
    if args.operation in ('adopt','deploy','rollback') and not args.approve_full_stack:raise ValueError('Explicit full-stack approval input required')
    sha=os.environ.get('GITHUB_SHA') or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    with lock(), tempfile.TemporaryDirectory(prefix='mcp-kamal-') as directory:
        if args.operation in ('devsy-bridge-path-check', 'devsy-bridge-path-apply'):
            if native_tuple is None or args.local or LOCAL_CONFIGURED:
                raise ValueError('Bridge PATH repair requires the protected Pi and exact native tuple')
            apply = args.operation == 'devsy-bridge-path-apply'
            if apply and not getattr(args, 'approve_bridge_kubectl_path', False):
                raise ValueError('Explicit one-time bridge PATH approval is required')
            return scope_binding_operation(native_tuple, sha, apply=apply, bridge_path=True)
        if args.operation in ('devsy-scope-rebind-check', 'devsy-scope-rebind'):
            if native_tuple is None:
                raise ValueError('Scope repair requires the exact idle native tuple')
            apply = args.operation == 'devsy-scope-rebind'
            if apply and not getattr(args, 'approve_scope_binding_rebind', False):
                raise ValueError('Explicit one-time scope binding approval is required')
            if args.local or LOCAL_CONFIGURED:
                raise ValueError('Scope binding repair requires the protected Pi workflow')
            return scope_binding_operation(native_tuple, sha, apply=apply)
        if args.operation=='status':
            result=remote('status')
            result['devsy_plan']=remote('devsy-plan',devsy_payload())
            result['smoke']=smoke(native_tuple) if result['healthy'] else {'status':'BLOCKED: managed service unhealthy'}
            return result
        if args.operation=='memoryd':
            if not (args.local and LOCAL_CONFIGURED):
                raise ValueError('MemoryD accessory deployment requires the private pinned local Kamal profile')
            return deploy_memoryd(sha,directory)
        if args.operation=='devsy-check':
            return {'operation':'devsy-check','plan':remote('devsy-plan',devsy_payload()),'mutated':False}
        if args.operation=='devsy-tap-reconcile-check':
            return _check_host_tap_reconciliation(native_tuple)
        if args.operation=='devsy-tap-reconcile':
            if not getattr(args, 'approve_host_tap_reconciliation', False):
                raise ValueError('explicit Homebrew tap reconciliation approval is required')
            return _reconcile_host_tap(
                native_tuple, sha, os.environ.get('GITHUB_RUN_ID', ''),
                os.environ.get('GITHUB_RUN_ATTEMPT', ''),
            )
        if args.operation=='devsy-tap-rollback-check':
            run_id = getattr(args, 'tap_reconciliation_run_id', '')
            attempt = getattr(args, 'tap_reconciliation_run_attempt', '')
            if not run_id or not attempt:
                raise ValueError('original tap reconciliation run id and attempt are required')
            return _check_host_tap_rollback(native_tuple, run_id, attempt)
        if args.operation=='devsy-tap-rollback':
            if not getattr(args, 'approve_host_tap_rollback', False):
                raise ValueError('explicit Homebrew tap rollback approval is required')
            run_id = getattr(args, 'tap_reconciliation_run_id', '')
            attempt = getattr(args, 'tap_reconciliation_run_attempt', '')
            if not run_id or not attempt:
                raise ValueError('original tap reconciliation run id and attempt are required')
            return _rollback_host_tap(native_tuple, run_id, attempt)
        if args.operation=='devsy-apply':
            if not getattr(args,'approve_host_devsy_apply',False):
                raise ValueError('explicit Host Devsy apply approval is required')
            return _apply_host_devsy(native_tuple,sha)
        if args.operation=='devsy-rollback':
            if not getattr(args,'approve_host_devsy_rollback',False):
                raise ValueError('explicit Host Devsy rollback approval is required')
            return _rollback_host_devsy(native_tuple)
        if args.operation=='rollback':
            current=remote('current');previous=remote('rollback-target')
            if current is None:raise ValueError('No recorded deployment generation exists')
            remote('profile')
            previous['publication_proof']=prove_images(previous['manifest'],previous)
            remote('images',previous['manifest'])
            state=remote('status')
            if state['inventory'].get('executor',{}).get('state')=='running':remote('backup')
            after=restore(previous,directory,native_tuple)
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
            devsy_plan=remote('devsy-plan',devsy_payload())
            smoke_result=smoke(native_tuple)
            return {'operation':args.operation,'authority':before['authority'],'inventory':before['inventory'],'devsy_plan':devsy_plan,'smoke':smoke_result,'pinned_images':manifest['images']}
        if args.operation=='cas' and before['authority']!='kamal':raise ValueError('Kamal adoption must precede accessory redeploy')
        if args.operation=='adopt' and before['authority']!='compose':raise ValueError('Adoption requires the sole Compose owner')
        if args.operation=='deploy' and before['authority']!='kamal':raise ValueError('Use explicit adoption first')
        remote('devsy-check',devsy_payload())
        smoke(native_tuple, require_native=True)
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
            after=remote('snapshot');smoke_result=smoke(native_tuple, require_native=True)
            if after['identity']!=before['identity']:raise RuntimeError('Post-deploy Executor identity changed')
            deployed_source=current['source_sha'] if args.operation=='cas' else sha
            remote('commit',{'authority':'kamal','source_sha':deployed_source,'manifest':manifest,'identity':after['identity'],'publication_proof':publication})
            return {'operation':args.operation,'authority':'kamal','inventory':after['inventory'],'smoke':smoke_result,'identity_preserved':True,'backup':backup,'source_sha':deployed_source,'controller_sha':sha}
        except Exception:
            # Report only our fixed phase names, never subprocess output or secrets.
            try:
                if args.operation=='cas':restore_cas(current,directory,native_tuple)
                else:restore(current,directory,native_tuple)
            except Exception:
                raise RuntimeError('Deployment failed at '+phase+'; automatic rollback FAILED; operator recovery required') from None
            raise RuntimeError('Deployment failed at '+phase+'; previous generation restored') from None


def main():
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('devsy-bridge-path-check','devsy-bridge-path-apply','devsy-scope-rebind-check','devsy-scope-rebind','preflight','status','memoryd','adopt','cas','deploy','rollback','devsy-check','devsy-apply','devsy-rollback','devsy-tap-reconcile-check','devsy-tap-reconcile','devsy-tap-rollback-check','devsy-tap-rollback'));p.add_argument('--cas-digest',default='');p.add_argument('--cas-revision',default='');p.add_argument('--approve-bridge-kubectl-path',action='store_true');p.add_argument('--approve-scope-binding-rebind',action='store_true');p.add_argument('--approve-full-stack',action='store_true');p.add_argument('--approve-host-devsy-apply',action='store_true');p.add_argument('--approve-host-devsy-rollback',action='store_true');p.add_argument('--approve-host-tap-reconciliation',action='store_true');p.add_argument('--approve-host-tap-rollback',action='store_true');p.add_argument('--tap-reconciliation-run-id',default=os.environ.get('TAP_RECONCILIATION_RUN_ID'));p.add_argument('--tap-reconciliation-run-attempt',default=os.environ.get('TAP_RECONCILIATION_RUN_ATTEMPT'));p.add_argument('--instance-profile',help='Absolute path to an owned mode-0600 private instance profile');p.add_argument('--native-target',default=os.environ.get('NATIVE_TARGET'));p.add_argument('--native-cwd',default=os.environ.get('NATIVE_CWD'));p.add_argument('--native-thread-id',default=os.environ.get('NATIVE_THREAD_ID'));p.add_argument('--local',action='store_true',help='Approved Pi break-glass, or bin/kamal with explicit private local config')
    args=p.parse_args()
    try:print(json.dumps(execute(args),indent=2))
    except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)

if __name__=='__main__':main()
