# Issue 16 migration preflight, 2026-10-11

Status: source preparation in progress; production migration blocked. No VM staging, state copy, backup claim, tunnel handoff, credential mutation, or daemon restart occurred.

Issue: https://github.com/joshyorko/mcp-tunnel-kit/issues/16

## Topology

Current verified route:
```text
ChatGPT -> OpenAI tunnel (Dakota) -> schema proxy -> Executor
  -> CAS at Dakota bridge 172.30.86.1:8088 -> Dakota native Unix socket
```

Proposed route, not deployed:
```text
ChatGPT -> same single tunnel (VM) -> schema proxy -> preserved Executor
  -> VM private CAS -> pinned SSH -> Dakota existing native Unix socket
```

The VM is `kamal-test-deploy`, 10.10.10.106, Ubuntu 24.04.5, user/UID kdlocpanda/1000. Existing alias and identity authenticate from Dakota with BatchMode=yes, ForwardAgent=no, StrictHostKeyChecking=yes. Pinned ED25519 fingerprint: SHA256:S6qJ1D1sigx5Dj2ZQH5XCP7DspX/gTWJemO9/Q+2Se8.

Resources: 6 CPUs, 7940 MiB memory, 2860 MiB available at inspection, no swap, 105 GiB available disk. Docker 29.8.1 and Compose 5.5.1. Existing containers: Fizzy, Campfire, two Cloudflare tunnels, Kamal proxy. Kamal owns loopback 80/443; SSH listens on 22. IPv4 routes cover 10.10.10.0/24, 172.17.0.0/16, 172.18.0.0/16. No inspected route overlaps proposed default 172.30.86.0/24. Recheck all routes and Docker IPAM immediately before staging.

## Blocking gates

1. VM to Dakota current verified address 192.168.1.136:22 returns Connection refused. Dakota sshd is inactive and no port 22 listener was found. VM user has no private SSH identity, agent, SSH config or pinned host entry for Dakota. Enabling SSH, provisioning identity/trust, or adding routes was not performed. A verified existing reverse connection is required before deployment.
2. Existing Devsy Kubernetes provider selects /home/kdlocpanda/.kube/config, context ror, namespace devsy. That exact kubeconfig lists only local and rancher. The bounded read fails: context "ror" does not exist. No substitute context or broader authority was used. VM bounded user inventory found no kubectl/devsy executable or kube/Devsy config; CAS image tools do not establish authorization.

## Live Dakota baseline

Supported control-plane-status reports Executor, CAS, schema proxy and tunnel running healthy; app-ready exited and host Devsy bridge ready. Bridge health is not provider acceptance.

Direct CAS MCP catalog contains 64 tools. list_targets, inspect_target(local), exact-cwd discover_threads and read_thread completed without MCP errors. read_thread returned current native operator thread 01a12bba-9641-79c1-9b29-93136f976fa6 at /home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit. This proves Dakota local reads only, not VM or ChatGPT acceptance.

Source baselines: mcp-tunnel-kit b04177131c8a73a35311ea47d2ff980957f22262; CAS 75acbaac83095f2dd49c2e1d432e4f553f7c0c7f. Existing uncommitted main changes are retained untouched.

Running image identities:
- Executor: sha256:89a2b829150d01bc26305f844159ca8064ea8a4ace047490d09b6a3c8bdcf600
- CAS and schema runtime: sha256:39b9f45a153bd6c06c1f42f57c93fa06fe6f1b8ea477105359413e59ab427237, CAS source label 75acbaac83095f2dd49c2e1d432e4f553f7c0c7f
- Tunnel: sha256:119799b778ba8411a124f53588f9dc837fd62ba03e5fadf77d675123c92ab58e

## State and rollback

Executor authoritative volume is codex-control-plane_executor-data mounted at /app/data. Preserve its entire content including keys. Private control-plane secrets, bootstrap app IDs and CAS dynamic owner/target state remain on Dakota. Runtime/receipt directories remain attached to the current writer. No new migration backup has been created or verified because preflight blocked before migration. No VM writer or tunnel exists from this work; rollback is unnecessary and Dakota remains production.

Before future cutover: verify a consistent backup and restore integrity, stage with no tunnel, prove exact remote native and qualified provider reads, verify independent operator/rollback, stop Dakota tunnel through supported lifecycle and verify exit, then start one VM tunnel. On failure stop VM tunnel and verify exit before restoring Dakota tunnel. Do not stop old control-plane services until end-to-end acceptance.

Workers: /root/cas_ssh and /root/vm_portability, both GPT-6 Luna medium. Root alone owns integration and live cutover.
