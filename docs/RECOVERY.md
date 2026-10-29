# Capture and stage a control-plane recovery bundle

Use this guide to capture the current control plane, encrypt it with age, and verify the bundle. Restore verified bundles into a new private staging directory. Staging does not write to live paths or start services.

## Install recovery tools on Bluefin

Run these commands on the Bluefin controller. Homebrew keeps these tools out of the immutable host image:

```sh
brew install age minio-mc
```

Configure an `mc` alias through your existing private MinIO credential process. Use a credential limited to the recovery bucket. Do not put MinIO credentials in this repository, in the recovery manifest, or in a command that enters shell history.

## Prepare private operator inputs

Keep the instance profile, native SSH profile, local Kamal config, SSH identity, pinned `known_hosts`, and Tailscale membership under the same trusted operator account used by the control-plane tools. See [Rebuild a control-plane host](REBUILD.md), [VM deployment](VM_DEPLOY.md), and [Native SSH](NATIVE_SSH.md) for those inputs.

`store_recovery.py` also requires a mode-`0600` storage profile. Create it only if it does not already exist:

```sh
storage_profile="$HOME/.config/mcp-control-plane/recovery-storage.json"
if [ ! -e "$storage_profile" ] && [ ! -L "$storage_profile" ]; then
  install -m 0600 config/recovery-storage.example.json "$storage_profile"
fi
```

Set its `mc_config_dir`, `minio_alias`, `bucket`, `removable_directory`, `recovery_identity`, and `unlock_identity` fields. The profile and both age identities stay outside the capture manifest.

`collect_recovery.py` requires absolute paths. It requires `.env.kamal.local`, both profiles, the tailnet requirements file, and the controller SSH files to be operator-owned with mode `0600`. The requirements file defaults to `tailnet-requirements.json` beside the instance profile. The native SSH state directory must be mode `0700`. It must contain the host key, authorized keys, rendered config, helper, and installed user service.

Create a private output parent. Every capture must use a new child directory:

```sh
umask 077
recovery_root="$HOME/.local/state/mcp-control-plane-recovery"
install -d -m 0700 "$recovery_root"
capture_id="$(date -u +%Y%m%d-%H%M%S)"
capture="$recovery_root/capture-$capture_id"
local_config="$PWD/.env.kamal.local"
```

Run capture from the repository checkout on Bluefin:

```sh
python3 scripts/collect_recovery.py \
  --local-config "$local_config" \
  --native-profile "$HOME/.config/mcp-control-plane/native-ssh.json" \
  --instance-profile "$HOME/.config/mcp-control-plane/instance.json" \
  --tailnet-requirements "$HOME/.config/mcp-control-plane/tailnet-requirements.json" \
  --output-dir "$capture"
```

The collector takes the existing VM lock and records the current generation. It briefly pauses and resumes the existing Executor for its data copy. It creates online SQLite backups for CAS, then checks that Executor identity and single-tunnel ownership remain unchanged. It does not restart production services. If capture fails, fix the prerequisite before trying again. The collector removes its incomplete local capture directory when it fails.

The output contains private plaintext. Keep it under the mode-`0700` recovery directory until encryption and verification finish. The manifest lists these logical members:

- `native-endpoint`: native SSH host key, authorized keys, config, helper, and user service.
- `instance-config`: private native and instance profiles, tailnet requirements, and `.env.kamal.local`.
- `operator-ssh`: controller SSH config, private identity, and pinned `known_hosts`.
- `vm-snapshot`: the Executor archive, essential VM state archive, CAS database copies with their source-path map, and `runtime-source.bundle` for the recorded source commit.
- `capture-receipt`: the generation, Executor digest, identity-preserved result, and single-tunnel result. Capture writes `capture-receipt.json`; restore stages this logical file as `capture-receipt` without the suffix.

The VM archives include encrypted Executor data, tunnel and service secrets, bootstrap state, Devsy configuration and context, kubeconfig, CAS target configuration, deployment ledgers, database snapshots, and the captured runtime Git bundle. The map at `vm-snapshot/cas-databases/manifest.json` identifies each SQLite snapshot's source path. The tailnet requirements file is not a full policy export. It records only the additive network grant needed by this endpoint. The collector never applies a tailnet change. Do not edit the capture manifest. Do not unpack the inner VM archives into live paths.

When the isolated MemoryD installation is healthy and registered, the capture also includes a verified whole-store backup, its manifest, and the content-addressed read-only adapter. The receipt records the store identity, active and archived record counts, approved scope, and pinned images. An absent installation is recorded explicitly; incomplete registration, transfers, or accessories stop capture. The portable transfer described in [MemoryD](CODEX_MEMORYD.md) covers active records only, not archived records.

MemoryD capture requires the source database plus its WAL to total at most 32 MiB and at least 512 MiB of available VM memory. It checks available volume space before starting a memory-limited Python helper with the source volume mounted read-only. The helper uses SQLite's online backup API, including committed WAL data. The released MemoryD CLI creates its backup from that isolated snapshot, never from the live source. Capture verifies a separate writable copy and checks that verification did not alter either copy. The helpers do not restart the live daemon. Capture retains its private `/data/.memoryd-recovery-<id>` staging directory, including on failure, for operator inspection. This staging data and the captured database contain private plaintext; account for their disk use and protect them accordingly.

Keep other operators and unmanaged writers from moving or removing the source database during collection. Capture refuses if the source identity changes or SQLite cannot read the WAL through the read-only mount.

Capture rejects a NULL or different value in any database table's `profile_id` or `workspace_id` column. It also checks the profile and workspace catalog IDs. MemoryD permits global `policy_events` with NULL scope, so such rows block capture until their scope is resolved. Tables without either scope column include global identity and import metadata, `repos`, and FTS tables. The column check cannot establish the scope of their contents; the whole-store snapshot includes them.

Capture refuses a database with any `sessions` or `visible_turns` rows. This excludes raw session and conversation history from recovery captures.

An in-progress legacy transfer blocks capture even if a later transfer used the same source database and scope. For an abandoned archived-inclusive transfer followed by an approved active-only transfer, retain both source manifests, the frozen source backup, and both staged bundle sets. Stop any unmanaged importers, then run this command from the private operator checkout only after deciding to leave the archived selection unimported:

```sh
CODEX_MEMORYD_HOME="$HOME/.codex-memoryd/dakota-codex-only" \
  CODEX_MEMORYD_RELEASE_BIN="$HOME/.local/opt/codex-memoryd/v0.1.0/bin/codex-memoryd" \
  bin/kamal accessory reconcile-legacy memoryd --approve-legacy-abandon
```

The command verifies the released binary, frozen selections, staged hashes, destination identity, and import ledger. It creates a separate verified private backup before making the original receipt read-only. It preserves the receipt contents and path, records the abandonment, and leaves the old bundles in place. The backup and staging files contain private plaintext. If the command stops, retain the files and inspect the reported state before retrying.

Guarded captures use recovery schema 3. Use the updated recovery tools to prepare and restore them; older tools reject this schema. The read-only receipt blocks known older managed importers, but it is not a security boundary against the file owner or direct Docker access. Do not change its mode or remove the abandonment record to bypass the guard.

## Configure private MinIO storage and age identities

Use two age identities. Identity A decrypts one bundle. Identity B decrypts the wrapped copy of identity A on the removable drive. Store identity B as a private MinIO object, separate from that drive. Keep MinIO account access available through a separate recovery channel.

Configure the MinIO alias in the private `mc` config directory named by the storage profile. Keep that directory private because it contains credentials. Use TLS and a credential limited to the recovery bucket. Do not put credentials on the command line or use `--insecure`. Create a dedicated bucket once. Set its anonymous policy to `private` and confirm it. Do not use a bucket with anonymous access or credentials available to untrusted users.

Read `mc_config_dir`, `minio_alias`, and `bucket` from the private storage profile. Use them to create and inspect the bucket:

```sh
mc_config_dir="/path/from-storage-profile"
minio_target="alias-from-storage-profile/bucket-from-storage-profile"
mc mb --config-dir "$mc_config_dir" "$minio_target"
mc anonymous --config-dir "$mc_config_dir" set private "$minio_target"
mc anonymous --config-dir "$mc_config_dir" get "$minio_target"
```

Create identity B once in the private recovery directory. Keep its private identity in the restricted operator directory and its public recipient file beside it:

```sh
key_dir="$HOME/.local/state/mcp-control-plane-recovery/keys"
install -d -m 0700 "$key_dir"
key_b="$key_dir/unlock-identity.txt"
age-keygen -o "$key_b"
age-keygen -y "$key_b" > "$key_dir/unlock-identity.recipient"
chmod 0600 "$key_b" "$key_dir/unlock-identity.recipient"
```

Set the storage profile's `unlock_identity` field to `key_b`. For each capture, set `recovery_identity` to identity A's private path. The profile's `mc_config_dir`, `minio_alias`, `bucket`, and `removable_directory` fields select private MinIO and removable storage. Keep the profile at mode `0600`.

Do not copy identity B to the removable drive. `store_recovery.py publish` stores it as `unlock-identity.txt` under the capture's private MinIO prefix. Restrict the bucket to the recovery operator and confirm that anonymous access is disabled.

`collect_recovery.py` does not include age identities or the storage profile. If you replace the controller, retrieve `unlock-identity.txt` from a verified capture in private MinIO. Set its mode to `0600`. Recreate the public recipient file with `age-keygen -y` before making another capture.

## Encrypt and verify each capture

Create a new identity A and recipient file for each capture. Keep identity A outside the capture directory:

```sh
key_a="$key_dir/$capture_id.agekey"
recipient_a="$key_dir/$capture_id.recipient"
bundle_dir="$recovery_root/encrypted-$capture_id"
mkdir -m 0700 "$bundle_dir"
bundle="$bundle_dir/control-plane.age"
age-keygen -o "$key_a"
age-keygen -y "$key_a" > "$recipient_a"
chmod 0600 "$key_a" "$recipient_a"
```

Set the storage profile's `recovery_identity` field to `key_a` before publishing.

Encrypt the collected logical members. The export command rejects an output path that already exists and excludes identity A from all declared inputs:

```sh
python3 scripts/control_plane_recovery.py export \
  --manifest "$capture/recovery-manifest.json" \
  --recipient-file "$recipient_a" \
  --exclude-identity "$key_a" \
  --output "$bundle"
```

Verify the exact encrypted bundle before copying it to storage:

```sh
python3 scripts/control_plane_recovery.py verify \
  --bundle "$bundle" \
  --identity "$key_a"
```

The command prints only a verified flag and member/file counts. Stop if decryption, digest validation, or archive validation fails.

Publish the bundle with a new private audit directory. The command creates the MinIO prefix and removable-drive run directory. It stores `control-plane.age` and `unlock-identity.txt` in MinIO. The private output and drive run receive `storage-receipt.json`. The drive also receives `control-plane.age`, a wrapped `recovery-key.age`, and `START-HERE.txt`.

```sh
publish_work="$recovery_root/publish-$capture_id"
python3 scripts/store_recovery.py publish \
  --storage-profile "$HOME/.config/mcp-control-plane/recovery-storage.json" \
  --bundle "$bundle" \
  --capture-id "$capture_id" \
  --output-dir "$publish_work"
```

Use a new capture ID and output directory for every run. Removable exFAT media cannot enforce Unix mode `0600`. The storage command puts only the encrypted bundle, wrapped recovery key, start guide, and storage receipt on the drive. It never copies either plaintext identity, profiles, capture files, or MinIO credentials there.

Add a separate archive of the public recovery tools to the drive run. Create it from the final trusted Git commit:

```sh
removable_directory="/path/from-storage-profile"
drive_dir="$removable_directory/$capture_id"
tools_commit="$(git rev-parse HEAD)"
git archive --format=tar "$tools_commit" | gzip -n > "$drive_dir/recovery-tools.tar.gz"
printf '%s\n' "$tools_commit" > "$drive_dir/recovery-tools-source.txt"
(cd "$drive_dir" && sha256sum recovery-tools.tar.gz > recovery-tools.sha256)
```

The archive contains tracked public code only. It contains no profiles, identities, or captured data. Keep `recovery-tools.tar.gz`, `recovery-tools.sha256`, and `recovery-tools-source.txt` beside `START-HERE.txt`.

On a replacement controller without a trusted checkout, verify and extract the tools into a new private directory:

```sh
tools_dir="$recovery_root/tools-$capture_id"
if [ -e "$tools_dir" ] || [ -L "$tools_dir" ]; then
  printf 'Refusing to reuse recovery-tools directory: %s\n' "$tools_dir" >&2
  exit 1
fi
mkdir -m 0700 "$tools_dir"
(cd "$drive_dir" && sha256sum -c recovery-tools.sha256)
tar -xzf "$drive_dir/recovery-tools.tar.gz" -C "$tools_dir"
cat "$drive_dir/recovery-tools-source.txt"
cd "$tools_dir"
```

Run recovery scripts from the extracted tool directory. Set `local_config` to the restored mode-`0600` `.env.kamal.local` after updating its SSH file references for this controller. Do not source that file as shell code. Regular deployment workflows still need a trusted Git checkout.

Read the bundle and key back from their storage locations. `verify-stored` uses the private MinIO `unlock-identity.txt` and the drive's `recovery-key.age`. It does not read the configured identity A path:

```sh
verify_work="$recovery_root/verify-$capture_id"
python3 scripts/store_recovery.py verify-stored \
  --storage-profile "$HOME/.config/mcp-control-plane/recovery-storage.json" \
  --bundle "$bundle" \
  --capture-id "$capture_id" \
  --output-dir "$verify_work"
```

Each command requires a new private output directory. `verify-stored` does not modify MinIO or the drive. It writes its receipt and verification staging files only to its new local output directory. Inspect its `storage-receipt.json`. Confirm `minio_private`, `minio_readback`, `drive_readback`, `two_location_key_recovery`, and `restored_files_compared`. Keep the MinIO account access and bucket policy available through a separate recovery channel.

## Verify and restore into staging

Restore only on a trusted Linux host with access to the private MinIO bucket and the removable drive. Set the storage variables from the private profile. Create a private, empty staging parent and download the encrypted identity B object and bundle:

```sh
umask 077
capture_id="replace-with-the-recorded-capture-id"
mc_config_dir="/path/from-storage-profile"
minio_alias="alias-from-storage-profile"
bucket="bucket-from-storage-profile"
removable_directory="directory-from-storage-profile"
drive_dir="$removable_directory/$capture_id"
restore_parent="$HOME/.local/state/mcp-control-plane-restore"
install -d -m 0700 "$restore_parent"
restore_root="$restore_parent/$capture_id"
mkdir -m 0700 "$restore_root"
minio_prefix="$minio_alias/$bucket/$capture_id"
mc cp --config-dir "$mc_config_dir" "$minio_prefix/unlock-identity.txt" "$restore_root/unlock-identity.txt"
mc cp --config-dir "$mc_config_dir" "$minio_prefix/control-plane.age" "$restore_root/control-plane.age"
chmod 0600 "$restore_root/unlock-identity.txt" "$restore_root/control-plane.age"
```

Decrypt identity A from the removable drive's wrapped key. Verify the bundle again after transfer:

```sh
age -d -i "$restore_root/unlock-identity.txt" \
  -o "$restore_root/recovery-identity.txt" "$drive_dir/recovery-key.age"
chmod 0600 "$restore_root/recovery-identity.txt"
python3 scripts/control_plane_recovery.py verify \
  --bundle "$restore_root/control-plane.age" \
  --identity "$restore_root/recovery-identity.txt"
```

Restore into a new child of the private staging parent:

```sh
python3 scripts/control_plane_recovery.py restore-stage \
  --bundle "$restore_root/control-plane.age" \
  --identity "$restore_root/recovery-identity.txt" \
  --destination "$restore_root/staged-$capture_id"
```

The command validates the complete encrypted archive before creating the destination. It rejects an existing destination, unsafe paths, symlinks, invalid ownership or modes, corruption, and missing members. It writes only beneath the new staging directory. Inspect the logical `capture-receipt` file and other members before preparing a generation.

Prepare a new generation from that staged bundle. The output directory must not already exist:

```sh
generation_dir="$restore_root/generation-$capture_id"
python3 scripts/prepare_recovery_generation.py \
  --restored-dir "$restore_root/staged-$capture_id" \
  --output-dir "$generation_dir"
```

Preparation validates the captured pins, generation metadata, identity, and archive layout, then writes the expected VM paths into a new private generation directory. It does not write to live VM paths or start services. Keep the staged bundle and prepared generation separate until the activation checks pass.

The prepared VM payload contains `executor-data/`, `state/`, `native-ssh/`, `vm.env`, and `generation.json`, plus `prepared-manifest.json`. The native endpoint keys, operator SSH keys, instance profile, capture receipt, and CAS database map stay in the outer decrypted staging tree. Do not transfer those outer inputs to the VM.

Before activation, prepare the replacement VM's runtime repository at the captured source commit. Read `source_sha` from the prepared generation metadata. Verify that the restored bundle contains exactly that commit:

```sh
source_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_sha"])' "$generation_dir/generation.json")"
runtime_bundle="$restore_root/staged-$capture_id/vm-snapshot/runtime-source.bundle"
git bundle verify "$runtime_bundle"
test "$(git bundle list-heads "$runtime_bundle")" = "$source_sha HEAD"
printf '%s\n' "$source_sha"
```

Transfer the bundle to a new private staging directory on the replacement VM. Use the pinned SSH config and alias from the private controller config and instance profile:

```sh
ssh_config="/absolute/path/from-private-controller-config"
vm_alias="alias-from-private-instance-profile"
vm_home="/home/operator"
vm_source_dir="$vm_home/.local/state/mcp-control-plane-recovery-staging/source-$capture_id"
vm_source_bundle="$vm_source_dir/runtime-source.bundle"
ssh -F "$ssh_config" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no \
  "$vm_alias" \
  "install -d -m 0700 '$vm_home/.local/state/mcp-control-plane-recovery-staging' && mkdir -m 0700 '$vm_source_dir' && test ! -e '$vm_source_bundle'"
scp -p -F "$ssh_config" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no \
  "$runtime_bundle" "$vm_alias:$vm_source_bundle"
source_sha256="$(sha256sum "$runtime_bundle" | cut -d' ' -f1)"
remote_sha256="$(ssh -F "$ssh_config" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no \
  "$vm_alias" "sha256sum '$vm_source_bundle' | cut -d' ' -f1")"
test "$source_sha256" = "$remote_sha256"
```

Replace `operator` and the alias with values from the private instance profile. `scp -p` preserves the bundle's mode `0600`. The remote `mkdir` refuses an existing source directory. The transfer uses the strict SSH pin and does not forward the agent.

On the replacement VM, clone the bundle into the empty `repo_dir` from the private instance profile. Use the VM account with Docker authority and set `source_sha` to the value printed above:

```sh
capture_id="replace-with-the-recorded-capture-id"
source_sha="paste-the-verified-source-SHA"
runtime_bundle="/home/operator/.local/state/mcp-control-plane-recovery-staging/source-$capture_id/runtime-source.bundle"
repo_dir="/absolute/repo-dir-from-private-instance-profile"
git bundle verify "$runtime_bundle"
test "$(git bundle list-heads "$runtime_bundle")" = "$source_sha HEAD"
if [ -e "$repo_dir" ] || [ -L "$repo_dir" ]; then
  printf 'Refusing to replace the VM repository: %s\n' "$repo_dir" >&2
  exit 1
fi
git clone "$runtime_bundle" "$repo_dir"
git -C "$repo_dir" checkout --detach "$source_sha"
test "$(git -C "$repo_dir" rev-parse HEAD)" = "$source_sha"
test -z "$(git -C "$repo_dir" status --porcelain)"
```

The activation tool does not sync or check out the runtime commit. Run recovery commands from the current trusted controller checkout or the verified public recovery-tools archive, not from the captured runtime checkout. Regular deployment workflows still need a trusted Git checkout.

Keep the captured network and state topology. A replacement host may use a new verified address and host-key pin, but its private instance profile must retain the captured bridge and state layout. The old generation is unsupported if those paths or the Executor identity change. Use the normal first-run path for a new instance with a different Executor identity.

## Plan and activate the prepared generation

The restore, prepare, and transfer commands do not start services. Transfer only the prepared VM generation to a new private staging path on the replacement VM. Replace `operator` with the VM user from the private instance profile:

```sh
vm_generation_dir="/home/operator/.local/state/mcp-control-plane-recovery-staging/$capture_id"
python3 scripts/transfer_recovery_generation.py \
  --local-config "$local_config" \
  --instance-profile "$HOME/.config/mcp-control-plane/instance.json" \
  --generation-dir "$generation_dir" \
  --destination "$vm_generation_dir"
```

The transfer command uses the pinned controller SSH configuration. It accepts only a new remote destination under the private recovery-staging directory. It does not transfer native endpoint keys, operator SSH keys, instance profiles, or the CAS source map. Those files stay in the outer local staging directory.

After transfer, run the activation command on the Bluefin controller without approval flags. This prints a read-only plan. PLAN may send read-only GET requests to GitHub and GHCR for image provenance. It does not create or modify the Docker network, and it is not an air gap:

```sh
python3 scripts/activate_recovery.py \
  --local-config "$local_config" \
  --instance-profile "$HOME/.config/mcp-control-plane/instance.json" \
  --generation-dir "$vm_generation_dir"
```

Review the plan and its generation, source commit, target paths, and service order. Stop the original VM and prevent it from restarting before activation. The command cannot verify that human attestation. Then repeat the same command with both approval flags:

```sh
python3 scripts/activate_recovery.py \
  --local-config "$local_config" \
  --instance-profile "$HOME/.config/mcp-control-plane/instance.json" \
  --generation-dir "$vm_generation_dir" \
  --original-stopped \
  --approve-activation
```

The command rejects a partial approval pair before connecting. It requires the replacement VM's runtime repository to be clean at the captured `source_sha` and the VM operator account to use UID/GID `1000:1000`. The Kamal Executor image runs as that account. Activation seeds the volume with archive-preserved ownership and does not change ownership. It refuses existing Executor volumes or controller containers, non-empty state paths, and a changed Executor identity. It checks image provenance and prepared-manifest digests remotely. It starts non-tunnel services first, checks health and identity, then starts the tunnel. It preserves recovered files and the named volume if activation fails. It never falls back to Compose. Stop the existing tunnel and all writers before activation.

When the generation contains MemoryD, activation restores its verified backup into a new isolated volume, starts the captured adapter, and checks the scoped read-only tools before starting the tunnel. The activation receipt records `memoryd_discovery: PASS` and `memoryd_restored: true` only after those checks succeed.

Older generations can contain a registration without a MemoryD backup. Those activate as `ACTIVATED_DEGRADED`, with `memoryd_discovery: UNAVAILABLE` and `memoryd_restored: false`; recover their MemoryD separately from a verified backup or suitable portable bundles, following [MemoryD](CODEX_MEMORYD.md). A generation with no registration records MemoryD as unregistered. The private VM receipt at `deployment/recovery-activation.json` records the result. Do not delete retained registration or transfer receipts to bypass a check.

On a failed activation, the new services are stopped where ownership can be verified. The recovered files, persistent volumes, and any uncertain restore helper remain for inspection; a private bridge firewall rule may also remain. Inspect the activation and MemoryD restore receipts before retrying. Do not delete a volume or start another tunnel without verifying which instance owns it.

A real encrypted bundle has been read back from private MinIO and removable media. The storage check recovered the wrapped identity and compared the restored files. This proves that bundle's encrypted readback and staging path. It does not prove a production VM was activated.
