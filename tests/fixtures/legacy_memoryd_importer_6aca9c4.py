"""Unmodified functions from vm_deploy_host.py at 6aca9c4d529d6298aac7d0a3751b2577ff3841b0.

Historical source SHA-256: 3a4242252d7c7bfbbcb7b582c812da240799b62f4831a35d20aea38f53d2d0dd.
This fixture is compiled only inside the legacy-fence regression.
"""

def private(path):
    s = path.lstat()
    if not path.is_file() or path.is_symlink() or s.st_uid != os.getuid() or s.st_mode & 0o777 != 0o600:
        raise ValueError('Private file ownership/mode mismatch')
    return path.read_bytes()

def memoryd_import_bundles(data):
    if not isinstance(data,dict) or set(data)!={'transfer_manifest_sha256'}:
        raise ValueError('MemoryD import request shape is invalid')
    transfer_id=data['transfer_manifest_sha256']
    if not isinstance(transfer_id,str) or not re.fullmatch(r'[a-f0-9]{64}',transfer_id):
        raise ValueError('MemoryD transfer identity is invalid')
    gate=memoryd_transfer_preflight()
    if not gate['ready']:
        raise ValueError('MemoryD transfer preflight blocked: '+gate['reason'])
    directory=STATE/'memoryd-transfer'/transfer_id[:16]
    manifest=json.loads(private(directory/'transfer.json'))
    _validate_memoryd_transfer_manifest(manifest)
    if manifest['transfer_manifest_sha256']!=transfer_id:
        raise ValueError('MemoryD transfer manifest identity mismatch')
    receipt_path=STATE/'bootstrap/memoryd-transfer.json'
    receipt=json.loads(private(receipt_path)) if receipt_path.exists() or receipt_path.is_symlink() else None
    if receipt and (receipt.get('transfer_manifest_sha256')!=transfer_id
                    or receipt.get('source_database_sha256')!=manifest['source_database_sha256']):
        raise ValueError('A different MemoryD transfer is already recorded')
    current_records=_memoryd_record_count()
    if receipt is None and current_records!=0:
        raise ValueError('MemoryD target is nonempty without a matching transfer receipt')
    backup_info=receipt.get('target_backup') if receipt else None
    if not backup_info:
        backup_path=f"/data/pre-transfer-{transfer_id[:12]}-{time.time_ns()}.db"
        created=_memoryd_cli_json(['backup','create','--local','--dest',backup_path])
        backup_manifest=created.get('manifest',{})
        run(['docker','exec','mcp-control-plane-memoryd','chmod','0600',
             backup_path,backup_path+'.manifest.json'])
        verified=_memoryd_cli_json(['backup','verify','--local','--path',backup_path])
        if verified.get('ok') is not True or backup_manifest.get('sha256')!=verified.get('manifest',{}).get('sha256'):
            raise ValueError('MemoryD target backup verification failed')
        backup_info={'path':backup_path,'sha256':backup_manifest['sha256'],'size_bytes':backup_manifest['size_bytes']}
    if receipt is None:
        receipt={'schema_version':1,'status':'in_progress',
                 'transfer_manifest_sha256':transfer_id,
                 'source_database_sha256':manifest['source_database_sha256'],
                 'source_instance_id':manifest['source_instance_id'],
                 'source_profile':manifest['source_profile'],'source_workspace':manifest['source_workspace'],
                 'target_profile':manifest['target_profile'],'target_workspace':manifest['target_workspace'],
                 'target_backup':backup_info,'bundles':{}}
        write(receipt_path,receipt)

    target_tmp=[];bundle_summaries=[];destination_instance_id=None
    def preview_apply(bundle,filename,*,idempotency=False):
        nonlocal destination_instance_id
        inspect=_memoryd_cli_json(['bundle','inspect',filename],timeout=180)
        _validate_memoryd_bundle_report(inspect,manifest,bundle)
        preview=_memoryd_cli_json(['bundle','import','--local','--preview',
            '--to-profile','personal','--to-workspace','dakota-codex-only',filename],timeout=300)
        if (preview.get('safe_to_apply') is not True
                or preview.get('integrity_status')!='verified'
                or preview.get('source_instance_id')!=manifest['source_instance_id']
                or preview.get('source_scope',{}).get('workspace')!='dakota-codex-only'
                or preview.get('destination_scope',{}).get('workspace')!='dakota-codex-only'):
            raise ValueError('MemoryD import preview rejected bundle scope or integrity')
        counts=preview.get('counts',{})
        if counts.get('rejected',0)!=0 or counts.get('conflicts',0)!=0:
            raise ValueError('MemoryD import preview has rejected records or conflicts')
        if idempotency and counts.get('create')!=0:
            raise ValueError('MemoryD duplicate replay planned new records')
        destination=preview.get('destination_instance_id')
        if destination_instance_id and destination_instance_id!=destination:
            raise ValueError('MemoryD destination instance changed between bundles')
        destination_instance_id=destination
        applied=_memoryd_cli_json(['bundle','import','--local','--apply','--plan-id',preview['plan_id'],
            '--to-profile','personal','--to-workspace','dakota-codex-only',filename],timeout=600)
        applied_receipt=applied.get('receipt',{})
        if applied_receipt.get('status')!='applied':
            raise ValueError('MemoryD bundle apply did not produce an applied receipt')
        return {'counts':counts,'receipt_id':applied_receipt.get('receipt_id'),
                'destination_instance_id':destination}

    try:
        for index,bundle in enumerate(manifest['bundles'],1):
            name=bundle['path'];host_path=directory/name
            info=host_path.lstat()
            if (host_path.is_symlink() or not host_path.is_file() or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=bundle['size_bytes']
                    or file_sha256(host_path)!=bundle['sha256']):
                raise ValueError('MemoryD bundle transfer file failed its host-side hash check')
            container_path=f"/tmp/memoryd-transfer-{transfer_id[:12]}-{index:02d}.bundle"
            run(['docker','cp',str(host_path),f'mcp-control-plane-memoryd:{container_path}'],timeout=120)
            run(['docker','exec','--user','0','mcp-control-plane-memoryd','chmod','0444',container_path])
            target_tmp.append(container_path)
            applied=preview_apply(bundle,container_path)
            receipt['bundles'][name]={'sha256':bundle['sha256'],'manifest_digest':bundle['manifest_digest'],
                                      'counts':applied['counts'],'receipt_id':applied['receipt_id']}
            write(receipt_path,receipt)
            bundle_summaries.append({'path':name,'counts':applied['counts']})
        if _memoryd_record_count()!=manifest['source_record_count']:
            raise ValueError('MemoryD target record count does not match Dakota source')
        status_data=_memoryd_cli_json(['status','--local']).get('data',{})
        if (status_data.get('active_profiles')!=['personal']
                or status_data.get('active_workspaces')!=['dakota-codex-only']):
            raise ValueError('MemoryD target profile/workspace boundary does not match source')
        idempotency=[]
        for index,bundle in enumerate(manifest['bundles'],1):
            container_path=f"/tmp/memoryd-transfer-{transfer_id[:12]}-{index:02d}.bundle"
            replay=preview_apply(bundle,container_path,idempotency=True)
            idempotency.append({'path':bundle['path'],'creates':replay['counts'].get('create',0),
                                'identity_reuses':replay['counts'].get('reuse_identity_exact',0),
                                'content_reuses':replay['counts'].get('reuse_content_exact',0)})
        if any(item['creates']!=0 for item in idempotency):
            raise ValueError('MemoryD duplicate-safe replay created records')
        if _memoryd_record_count()!=manifest['source_record_count']:
            raise ValueError('MemoryD record count changed during idempotency replay')
        recall=json.loads(_memoryd_cli(['recall','--local','--profile','personal','--workspace',
            'dakota-codex-only','--query','Dakota Codex durable memory']))
        recall_facts=len(recall.get('facts',[]));recall_citations=len(recall.get('citations',[]))
        if recall_facts==0 or recall_citations==0 or recall.get('policy',{}).get('authority')!='recall_not_authority':
            raise ValueError('MemoryD post-transfer recall smoke failed')
        receipt.update(status='complete',destination_instance_id=destination_instance_id,
                       imported_record_count=manifest['source_record_count'],
                       idempotency=idempotency,recall_facts=recall_facts,
                       recall_citations=recall_citations,completed_at_ns=time.time_ns())
        write(receipt_path,receipt)
        return {'status':'complete','source_instance_id':manifest['source_instance_id'],
                'destination_instance_id':destination_instance_id,
                'source_database_sha256':manifest['source_database_sha256'],
                'source_record_count':manifest['source_record_count'],
                'target_backup':backup_info,'bundles':bundle_summaries,
                'idempotency':idempotency,'recall_facts':recall_facts,
                'recall_citations':recall_citations}
    finally:
        if target_tmp:
            run(['docker','exec','--user','0','mcp-control-plane-memoryd','rm','-f',*target_tmp],timeout=60)
