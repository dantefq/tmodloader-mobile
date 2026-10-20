"""Prepare isolated portable baseline inputs and an inert build PS1. Never runs tools.

Root must explicitly run this after independently reviewing the pinned ZIP.
No downloads, subprocesses, compiler invocation, Ghidra launch, or frozen edits.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

ARCHIVE_SHA='1bcf74d06b724aeecaa6412ca85f5b26fb1da770e7cdcefa9263c9c5c3ad34b6'
GRADLE_SHA='dc1ede0c8d40aa5a4bfe3d9b997e5570d87a5c71c535c8afadca7a6415d9674b'
TOP='llvm-mingw-20260908-ucrt-x86_64'
RESERVED={'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}

def require(ok,message):
    if not ok:raise ValueError(message)

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def inside(p,root):
    require(p.resolve().is_relative_to(root.resolve()),f'Outside intended root: {p}')
    return p

def regular(p):
    require(p.is_file() and not p.is_symlink(),f'Not regular file: {p}')
    require(not (getattr(p.lstat(),'st_file_attributes',0)&0x400),f'Reparse file: {p}')

def zip_inventory(z):
    rows=[];seen={};total=0
    for v in z.infolist():
        name=v.filename
        require(not ('\\' in name or ':' in name or '\x00' in name),f'Unsafe ZIP name: {name!r}')
        parts=PurePosixPath(name).parts
        require(parts and parts[0]==TOP and not name.startswith('/'),f'Unexpected ZIP root: {name!r}')
        require(all(x not in ('','.','..') and x.rstrip(' .')==x and x.split('.')[0].upper() not in RESERVED for x in parts),f'Unsafe path component: {name!r}')
        # PurePosixPath normalizes dots, so inspect the original representation too.
        require(all(x not in ('','.','..') for x in name.rstrip('/').split('/')),f'Normalized path ambiguity: {name!r}')
        mode=(v.external_attr>>16)&0xffff;kind=stat.S_IFMT(mode)
        require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and not stat.S_ISLNK(mode),f'ZIP nonregular entry: {name!r}')
        require(not(v.flag_bits&1),f'Encrypted ZIP member: {name!r}')
        require(not(v.external_attr&0x400),f'ZIP reparse entry: {name!r}')
        key='/'.join(parts).casefold();require(key not in seen,f'Case/duplicate collision: {name!r}')
        seen[key]=v.is_dir();total+=v.file_size
        require(0<=v.file_size<=1024**3 and total<=4*1024**3,'Unexpected ZIP expanded size')
        rows.append((v,parts))
    require(rows,'Empty ZIP')
    for key in seen:
        parents=key.split('/')[:-1]
        for i in range(1,len(parents)+1):
            parent='/'.join(parents[:i]);require(parent not in seen or seen[parent],f'File/directory collision: {key}')
    return rows,total

def records(root):
    result=[]
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink() and not(getattr(p.lstat(),'st_file_attributes',0)&0x400),f'Reparse path: {p}')
        if p.is_file():
            regular(p);result.append(dict(path=p.relative_to(root).as_posix(),bytes=p.stat().st_size,sha256=sha(p)))
    return result

BUILD_PS=r'''# Prepared baseline build only. Does not launch or install Ghidra.
$ErrorActionPreference='Stop'
$diagRoot=$PSScriptRoot
$diagManifestPath=Join-Path $diagRoot 'preparation-manifest.json'
$diagManifest=Get-Content -LiteralPath $diagManifestPath -Raw | ConvertFrom-Json
$diagManifestHash=(Get-FileHash -LiteralPath $diagManifestPath).Hash.ToLower()
if ((Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower() -ne $diagManifest.builder_sha256) { throw 'Builder source changed' }
$diagDeadline=[DateTime]::UtcNow.AddHours(3)
function Assert-DiagIdle {
    $diagProcesses=@(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq 'decompile.exe' -or
        ($_.Name -in @('java.exe','javaw.exe') -and $_.CommandLine -match 'ghidra|analyzeHeadless|terraria-re-20261012') -or
        ($_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -match 'terraria_angr_.*probe|angr.*supervis')
    })
    if ($diagProcesses.Count) { throw 'Analysis engine is active; preserve partial build and stop' }
    if ([DateTime]::UtcNow -gt $diagDeadline) { throw 'Finite build deadline reached' }
}
function Assert-DiagLongBudgetComplete {
    $diagPlan=Get-Content -LiteralPath $diagManifest.long_budget_plan -Raw | ConvertFrom-Json
    $diagSummary=Get-Content -LiteralPath $diagManifest.long_budget_summary -Raw | ConvertFrom-Json
    $diagExpected=@($diagPlan.addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $diagReported=@($diagSummary.planned_addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($diagSummary.finished_planned_attempts -ne $true -or @($diagSummary.not_yet_audited_planned_addresses).Count -ne 0) { throw 'LongBudget planned work is unfinished' }
    if ($diagExpected.Count -ne $diagReported.Count) { throw 'LongBudget plan mismatch' }
    foreach ($diagAddress in $diagExpected) { if ($diagAddress -notin $diagReported) { throw 'LongBudget plan mismatch' } }
    if ($diagExpected.Count -eq 0 -and $diagSummary.remaining_hard_methods_without_C -ne 0) { throw 'Empty LongBudget plan with unresolved functions' }
    $diagDone=@($diagSummary.attempts | ForEach-Object { [string]$_.address })
    foreach ($diagStage in $diagManifest.prior_stages) {
        $diagPriorPath=Join-Path $diagManifest.delivery "$diagStage/summary.json"
        if(Test-Path -LiteralPath $diagPriorPath){
            $diagPrior=Get-Content -LiteralPath $diagPriorPath -Raw | ConvertFrom-Json
            $diagDone+=@($diagPrior.conditional_candidates | ForEach-Object { [string]$_.address })
        }
    }
    foreach ($diagAddress in $diagExpected) { if ($diagAddress -notin $diagDone) { throw 'LongBudget result/recovery evidence missing' } }
    if ($diagPlan.producer_sha256 -ne (Get-FileHash -LiteralPath $diagManifest.long_budget_producer).Hash.ToLower() -or $diagPlan.auditor_sha256 -ne (Get-FileHash -LiteralPath $diagManifest.long_budget_auditor).Hash.ToLower()) { throw 'LongBudget plan source identity differs' }
}
function Assert-DiagFiles([string]$diagBase,$diagRows) {
    $diagActual=@(Get-ChildItem -LiteralPath $diagBase -Recurse -File)
    if($diagActual.Count -ne @($diagRows).Count){throw 'Input file count differs'}
    foreach($diagRow in $diagRows){
        $diagFile=Join-Path $diagBase $diagRow.path
        $diagItem=Get-Item -LiteralPath $diagFile
        if(($diagItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $diagItem.Length -ne $diagRow.bytes -or (Get-FileHash -LiteralPath $diagFile).Hash.ToLower() -ne $diagRow.sha256){throw "Input differs: $diagFile"}
    }
}
Assert-DiagIdle
Assert-DiagLongBudgetComplete
if ((Get-FileHash -LiteralPath $diagManifest.archive).Hash.ToLower() -ne $diagManifest.archive_sha256) { throw 'Pinned archive differs' }
if ((Get-FileHash -LiteralPath $diagManifest.original_gradle).Hash.ToLower() -ne $diagManifest.gradle_sha256) { throw 'Original Gradle differs' }
Assert-DiagFiles (Join-Path $diagRoot 'toolchain') $diagManifest.toolchain_files
Assert-DiagFiles (Join-Path $diagRoot 'source') $diagManifest.snapshot_files
Assert-DiagIdle
$diagBuild=Join-Path $diagRoot 'baseline-build'
if(Test-Path -LiteralPath $diagBuild){throw 'Existing complete/partial build must be preserved; use reviewed fresh preparation'}
New-Item -ItemType Directory -Path $diagBuild | Out-Null
$diagRecord=@{status='building';preparation_manifest_sha256=$diagManifestHash;start_UTC=[DateTime]::UtcNow.ToString('o');compiler=$diagManifest.compiler;source_count=79;compiled=@();analysis_executed=$false;C_coverage_addition=0}
$diagRecordPath=Join-Path $diagBuild 'build-manifest.json'
function Save-DiagRecord { $diagRecord | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $diagRecordPath -Encoding utf8 }
$diagCxx=[string]$diagManifest.compiler
$diagSources=@($diagManifest.sources | ForEach-Object { [string]$_ })
if($diagSources.Count -ne 79 -or @($diagSources | Sort-Object -Unique).Count -ne 79){throw 'Expected exact79source list'}
$diagObjects=@()
Save-DiagRecord
try {
    Assert-DiagIdle
    $diagVersionLog=Join-Path $diagBuild 'compiler-version.log'
    & $diagCxx '--version' *> $diagVersionLog
    if($LASTEXITCODE -ne 0){throw 'Compiler version query failed'}
    $diagRecord.compiler_version_log_sha256=(Get-FileHash -LiteralPath $diagVersionLog).Hash.ToLower()
    $diagTargetLog=Join-Path $diagBuild 'compiler-target.log'
    & $diagCxx '-dumpmachine' *> $diagTargetLog
    if($LASTEXITCODE -ne 0){throw 'Compiler target query failed'}
    $diagTarget=(Get-Content -LiteralPath $diagTargetLog -Raw).Trim()
    if($diagTarget -notmatch '^x86_64-w64-(windows-gnu|mingw32)$'){throw "Unexpected compiler target: $diagTarget"}
    $diagRecord.compiler_target=$diagTarget
    $diagRecord.compiler_target_log_sha256=(Get-FileHash -LiteralPath $diagTargetLog).Hash.ToLower()
    Assert-DiagIdle
    Save-DiagRecord
    foreach($diagName in $diagSources){
        Assert-DiagIdle
        $diagStem=[IO.Path]::GetFileNameWithoutExtension($diagName)
        $diagOutput=Join-Path $diagBuild "$diagStem.o"
        $diagLog=Join-Path $diagBuild "$diagStem.log"
        $diagArgs=@($diagManifest.compile_flags | ForEach-Object { [string]$_ })+@('-c',(Join-Path $diagRoot "source/$diagName"),'-o',$diagOutput)
        & $diagCxx @diagArgs *> $diagLog
        $diagExit=$LASTEXITCODE
        Assert-DiagIdle
        if($diagExit -ne 0 -or -not(Test-Path -LiteralPath $diagOutput)){throw "Compile failed: $diagName (exit $diagExit)"}
        $diagRecord.compiled+=@{source=$diagName;argv=$diagArgs;object_sha256=(Get-FileHash -LiteralPath $diagOutput).Hash.ToLower();log_sha256=(Get-FileHash -LiteralPath $diagLog).Hash.ToLower()}
        $diagObjects+=$diagOutput
        Save-DiagRecord
    }
    Assert-DiagIdle
    $diagRsp=Join-Path $diagBuild 'objects.rsp'
    $diagLines=@($diagObjects | ForEach-Object { '"'+$_.Replace('\','/')+'"' })
    [IO.File]::WriteAllText($diagRsp,($diagLines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
    $diagExe=Join-Path $diagBuild 'decompile.exe'
    $diagLink=@(('@'+$diagRsp),'-Xlinker','--stack','-Xlinker','33554432,4096','-o',$diagExe)
    if($diagLink.Count -ne 7 -or $diagLink[4] -ne '33554432,4096'){throw 'Link argv shape differs'}
    & $diagCxx @diagLink *> (Join-Path $diagBuild 'link.log')
    $diagExit=$LASTEXITCODE
    Assert-DiagIdle
    if($diagExit -ne 0 -or -not(Test-Path -LiteralPath $diagExe)){throw "Link failed: $diagExit"}
    $diagRecord.link_argv=$diagLink
    $diagRecord.engine_sha256=(Get-FileHash -LiteralPath $diagExe).Hash.ToLower()
    $diagRecord.status='linked_uninspected_unexecuted'
    $diagRecord.note='PE architecture/stack/import checks and runtime DLL review are required before separately authorized smoke. This script never executes the produced engine.'
} catch {
    $diagRecord.status='failed_or_engine_became_busy';$diagRecord.error=$_.Exception.Message
    throw
} finally { $diagRecord.end_UTC=[DateTime]::UtcNow.ToString('o');Save-DiagRecord }
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'))
    p.add_argument('--name',default='portable-decompiler-baseline-prep-20261017')
    p.add_argument('--delivery',type=Path,default=Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'))
    a=p.parse_args();lab=a.lab.resolve();require(lab.is_dir(),'Lab missing')
    require(re.fullmatch(r'portable-decompiler-baseline-prep-[a-zA-Z0-9-]+',a.name) is not None,'Invalid fresh preparation name')
    dest=inside(lab/a.name,lab);require(not dest.exists(),'Preparation destination already exists; preserve partial attempt')
    archive=inside(lab/'toolchains'/f'{TOP}.zip',lab);regular(archive);require(sha(archive)==ARCHIVE_SHA,'Archive digest differs')
    component=lab/'ghidra-stack32/Ghidra/Features/Decompiler'
    gradle=component/'build.gradle';regular(gradle);require(sha(gradle)==GRADLE_SHA,'Frozen Gradle differs')
    text=gradle.read_text();start=text.index('decompile(NativeExecutableSpec)');end=text.index('} // end decompile',start)
    sources=re.findall(r'^\s*include "([^"]+\.cc)"',text[start:end],re.M)
    require(len(sources)==79 and len(set(sources))==79,'Unexpected active source list')
    cpp=component/'src/decompile/cpp';snapshot=[]
    for f in sorted(cpp.iterdir()):
        if f.suffix in ('.cc','.hh','.h'):
            regular(f);snapshot.append((f,f.name,sha(f)))
    require(set(sources)<={v[1] for v in snapshot},'Missing selected source')
    require(snapshot,'No snapshot files')
    with zipfile.ZipFile(archive) as z:
        members,total=zip_inventory(z)
        # Mutations begin only after all archive/source/path prechecks. No recursive cleanup on failure.
        dest.mkdir();tc=dest/'toolchain';tc.mkdir();src=dest/'source';src.mkdir()
        for info,parts in members:
            target=inside(tc.joinpath(*parts),tc)
            if info.is_dir():target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as f,target.open('xb') as out:shutil.copyfileobj(f,out,1024*1024)
                require(target.stat().st_size==info.file_size,'Extracted length differs')
        for original,name,digest in snapshot:
            shutil.copyfile(original,src/name);require(sha(src/name)==digest and sha(original)==digest,'Snapshot changed during copy')
    compiler=tc/TOP/'bin/x86_64-w64-mingw32-clang++.exe';regular(compiler)
    builder=dest/'build-baseline.ps1';builder.write_text(BUILD_PS,encoding='utf8',newline='\n')
    tools=Path(__file__).resolve().parent
    manifest=dict(schema='portable-ghidra-baseline-preparation-v1',created_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),preparer_sha256=sha(Path(__file__)),archive=str(archive),archive_sha256=ARCHIVE_SHA,archive_uncompressed_bytes=total,archive_entry_count=len(members),original_gradle=str(gradle.resolve()),gradle_sha256=GRADLE_SHA,source_snapshot_unmodified=True,sources=sources,snapshot_files=records(src),toolchain_files=records(tc),compiler=str(compiler.resolve()),compiler_sha256=sha(compiler),compile_flags=['-std=c++11','-O2','-Wall','-Wno-sign-compare','-D_WINDOWS','-DWINDOWS','-DWIN32','-DWIN64'],builder_sha256=sha(builder),delivery=str(a.delivery.resolve()),long_budget_plan=str(lab/'long-budget-c-plan-20261017.json'),long_budget_summary=str(a.delivery.resolve()/'long-budget-c-continuation-20261017/summary.json'),long_budget_producer=str(tools/'TerrariaLongBudgetCProbe.java'),long_budget_auditor=str(tools/'audit_terraria_long_budget_c.py'),prior_stages=['ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016','long-budget-c-continuation-20261017'],build_executed=False,engine_executed=False,C_coverage_addition=0)
    (dest/'preparation-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(prepared=str(dest),builder=str(builder),source_count=79,build_executed=False)))

if __name__=='__main__':main()
