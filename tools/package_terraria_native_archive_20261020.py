"""Bundle an audited native journal without thousands of duplicate file writes.

Only persisted, independently audited artifacts are accepted. Every archive member
is bound to its byte hash and reread after writing; no archive content is executed.
"""
import hashlib
import json
from pathlib import Path
import re
import zipfile

PRODUCER='2abbe851f83a5bcde7864dda26652cdb7083d10634fea796bf9506e375cea3a0'
AUDITOR='90d8b5371f848e67c1b628fb3fc3c5485553aff21bf8bb4ea384881056f9ed7f'
digest=lambda raw:hashlib.sha256(raw).hexdigest()


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def require(condition,message):
    if not condition:
        raise ValueError(message)


def verify_archive(archive,index):
    require(file_digest(archive)==index['archive_sha256'],'Archive hash mismatch')
    expected={r['name']:r for r in index['members']}
    require(len(expected)==len(index['members']),'Duplicate indexed member')
    with zipfile.ZipFile(archive,'r') as source:
        infos=source.infolist()
        require(len(infos)==len(expected) and {i.filename for i in infos}==set(expected),'Archive member universe mismatch')
        for info in infos:
            row=expected[info.filename]
            require(not info.is_dir() and info.file_size==row['bytes'],'Archive size/type mismatch')
            raw=source.read(info)
            require(digest(raw)==row['sha256'],'Archive member hash mismatch: '+info.filename)


def build_archive(root,audit_file,destination):
    root=Path(root).resolve();audit_file=Path(audit_file).resolve();destination=Path(destination).resolve()
    audit_raw=audit_file.read_bytes();audit=json.loads(audit_raw)
    require(audit['integrity_passed'] is True and audit['preflight_only'] is False,'Independent audit required')
    require(audit['producer_sha256']==PRODUCER and audit['auditor_sha256']==AUDITOR,'Unexpected producer/auditor')
    journal=(root/'journal.jsonl').read_bytes()
    require(not journal or journal.endswith(b'\n'),'Incomplete journal tail')
    lines=journal.splitlines(keepends=True)[:audit['attempted_rows']]
    prefix=b''.join(lines)
    require(len(lines)==audit['attempted_rows'] and digest(prefix)==audit['journal_sha256'],'Audited journal prefix changed')
    manifest_raw=(root/'manifest.input.json').read_bytes()
    require(digest(manifest_raw)==audit['manifest_sha256'],'Stored manifest changed')
    manifest=json.loads(manifest_raw);run=json.loads((root/'run.json').read_bytes())
    for key,value in dict(profile=manifest['profile'],manifest_sha256=audit['manifest_sha256'],
                          script_sha256=PRODUCER,engine_sha256=audit['engine_sha256'],
                          elf_sha256=audit['ELF_sha256'],syntax_tree_requested=True,
                          timeout_seconds=20,max_instructions=100000,max_payload_mb=64).items():
        require(type(run[key]) is type(value) and run[key]==value,'Stored run identity changed: '+key)
    preparation_sha=digest((root/'preparation.jsonl').read_bytes())
    require(run['preparation_sha256']==preparation_sha,'Stored preparation changed')
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/'exports.zip';index_path=destination/'archive-index.json'
    if archive.exists() or index_path.exists():
        require(archive.is_file() and index_path.is_file(),'Incomplete earlier archive preserved; inspect before retry')
        index=json.loads(index_path.read_text(encoding='utf8'))
        require(index['audit_sha256']==digest(audit_raw) and index['journal_sha256']==digest(prefix),'Earlier archive belongs to another snapshot')
        verify_archive(archive,index)
        return archive,index_path
    partial=destination/'exports.zip.partial'
    require(not partial.exists(),'Earlier partial archive preserved; use a fresh destination')
    members=[];names=set();statuses={}
    def member(target,name,raw,expected=None):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+',name) is not None and name not in ('.','..'),'Unsafe member name')
        require(name not in names,'Duplicate archive member');names.add(name)
        actual=digest(raw)
        if expected is not None:require(actual==expected,'Source hash mismatch: '+name)
        target.writestr(name,raw)
        members.append(dict(name=name,sha256=actual,bytes=len(raw)))
    with partial.open('xb') as carrier:
        with zipfile.ZipFile(carrier,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as target:
            member(target,'audit.json',audit_raw)
            member(target,'journal.jsonl',prefix,audit['journal_sha256'])
            for name in ('run.json','manifest.input.json','ApkNativeRangeExport.java','preparation.jsonl','restoration.json'):
                path=root/name
                if path.exists():
                    require(path.is_file() and not path.is_symlink(),'Unsafe input artifact')
                    expected=PRODUCER if name=='ApkNativeRangeExport.java' else audit['manifest_sha256'] if name=='manifest.input.json' else None
                    member(target,name,path.read_bytes(),expected)
            for line in lines:
                commit=json.loads(line);address=commit['address']
                require(re.fullmatch(r'0x[0-9a-f]+',address) is not None,'Invalid address')
                result_name='range_'+address+'.json'
                require(commit['result_file']==result_name,'Unexpected result name')
                result_path=root/result_name;require(not result_path.is_symlink(),'Result symlink')
                result_raw=result_path.read_bytes()
                member(target,result_name,result_raw,commit['result_sha256'])
                result=json.loads(result_raw)
                require(result['address']==address and result['script_sha256']==PRODUCER
                        and result['manifest_sha256']==audit['manifest_sha256']
                        and result['elf_sha256']==audit['ELF_sha256'],'Result identity mismatch')
                if result.get('preparation_status')=='ready':
                    require(result.get('all_manifest_boundaries_preparation_sha256')==preparation_sha,'Result/preparation binding mismatch')
                else:
                    require(result['status']=='range_error' and result.get('preparation_status')=='conflict','Unexpected unbound preparation failure')
                status=result['status'];statuses[status]=statuses.get(status,0)+1
                if status=='decompiled':
                    c_name='range_'+address+'.c'
                    require(result['c_file']==c_name,'Unexpected C name')
                    path=root/c_name;require(not path.is_symlink(),'C symlink')
                    raw=path.read_bytes();require(len(raw)==result['c_bytes'],'C byte count mismatch')
                    member(target,c_name,raw,result['c_sha256'])
            require(statuses==audit['status_counts'],'Export status universe changed')
    index=dict(schema_version=1,audit_sha256=digest(audit_raw),journal_sha256=digest(prefix),
               archive_sha256=file_digest(partial),members=members,
               attempted_rows=audit['attempted_rows'],status_counts=statuses,
               semantic_equivalence_verified=False,original_source_recovered=False)
    verify_archive(partial,index)
    require(digest(b''.join((root/'journal.jsonl').read_bytes().splitlines(keepends=True)[:audit['attempted_rows']]))==digest(prefix),'Journal prefix changed during packaging')
    partial.rename(archive)
    with index_path.open('x',encoding='utf8') as stream:
        json.dump(index,stream,indent=2);stream.write('\n')
    return archive,index_path
