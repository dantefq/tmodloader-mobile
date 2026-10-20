# Builds two trace-only units against the verified 77 remaining baseline objects.
# Never loads or executes the resulting engine.
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){throw 'PowerShell 7 required'}
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaBase="$terrariaLab/portable-decompiler-baseline-prep-20261017"
$terrariaTrace="$terrariaLab/portable-decompiler-trace-source-20261017"
$terrariaSupervisor="$terrariaBase/build-baseline-after-resource-error.ps1"
function Get-TerrariaHash([string]$p){return (Get-FileHash -LiteralPath $p).Hash.ToLower()}
if((Get-TerrariaHash $terrariaSupervisor) -ne 'bbea3347b043708c405f3c40cd0ce8ce489b0db0c36501952a508c3fdb84fb25'){throw 'Supervisor changed'}
if((Get-TerrariaHash "$terrariaTrace/trace-source-manifest.json") -ne '66032dc9194647d8b9b2296b6d53168ade2dc22bea62e00b313171804e01ce7b'){throw 'Trace snapshot manifest changed'}
$terrariaPrepared=Get-Content "$terrariaBase/preparation-manifest.json" -Raw | ConvertFrom-Json
$terrariaBaseline=Get-Content "$terrariaBase/baseline-build/build-manifest.json" -Raw | ConvertFrom-Json
$terrariaSnapshot=Get-Content "$terrariaTrace/trace-source-manifest.json" -Raw | ConvertFrom-Json
$terrariaSmoke=Get-Content "$terrariaLab/pseudocode-portable-baseline-c-smoke-20261017/audit.json" -Raw | ConvertFrom-Json
if(-not $terrariaSmoke.integrity_passed -or -not $terrariaSmoke.c_smoke -or $terrariaSmoke.eligible_for_new_C_coverage){throw 'Baseline C smoke required'}
if($terrariaSmoke.result_sha256 -ne (Get-TerrariaHash "$terrariaLab/pseudocode-portable-baseline-c-smoke-20261017/result.json")){throw 'Smoke identity changed'}
if($terrariaBaseline.engine_sha256 -ne '5d39674818484db40000dd0a3171493661ed6e3efd01a80de47cc21321eac40c' -or $terrariaBaseline.compiled.Count -ne 79){throw 'Unexpected baseline'}
if(@(Compare-Object $terrariaSnapshot.sources $terrariaPrepared.sources -SyncWindow 0).Count){throw 'Source order differs'}
foreach($terrariaFile in $terrariaSnapshot.trace_snapshot_files){
    if([IO.Path]::GetFileName($terrariaFile.path) -ne $terrariaFile.path){throw 'Unexpected snapshot path'}
    if((Get-TerrariaHash "$terrariaTrace/source/$($terrariaFile.path)") -ne $terrariaFile.sha256){throw 'Trace source changed'}
}
$diagRoot=$terrariaBase
$diagDeadline=[DateTime]::UtcNow.AddMinutes(20)
$diagCxx=$terrariaPrepared.compiler
$terrariaTokens=$null;$terrariaErrors=$null
$terrariaAst=[Management.Automation.Language.Parser]::ParseFile($terrariaSupervisor,[ref]$terrariaTokens,[ref]$terrariaErrors)
if($terrariaErrors.Count){throw 'Supervisor parse failure'}
foreach($terrariaName in @('Assert-DiagIdle','Save-DiagRecord','Invoke-DiagCompiler')){
    $terrariaFn=@($terrariaAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $terrariaName},$true))
    if($terrariaFn.Count -ne 1){throw 'Expected one supervisor function'}
    . ([scriptblock]::Create($terrariaFn[0].Extent.Text))
}
Assert-DiagIdle
$terrariaBuild="$terrariaTrace/incremental-build-20261018"
if(Test-Path -LiteralPath $terrariaBuild){throw 'Preserve previous build'}
New-Item -ItemType Directory -Path $terrariaBuild | Out-Null
$diagRecordPath="$terrariaBuild/build-manifest.json"
$diagRecord=@{status='building';baseline_manifest_sha256=(Get-TerrariaHash "$terrariaBase/baseline-build/build-manifest.json");trace_manifest_sha256=(Get-TerrariaHash "$terrariaTrace/trace-source-manifest.json");supervisor_sha256=(Get-TerrariaHash $terrariaSupervisor);builder_sha256=(Get-TerrariaHash $PSCommandPath);engine_executed=$false;C_coverage_addition=0;objects=@();started_UTC=[DateTime]::UtcNow.ToString('o')}
Save-DiagRecord
try {
    $terrariaObjects=@()
    foreach($terrariaRow in $terrariaBaseline.compiled){
        Assert-DiagIdle
        $terrariaName=[string]$terrariaRow.source
        $terrariaStem=[IO.Path]::GetFileNameWithoutExtension($terrariaName)
        $terrariaObject="$terrariaBase/baseline-build/$terrariaStem.o"
        if((Get-TerrariaHash $terrariaObject) -ne $terrariaRow.object_sha256){throw 'Baseline object changed'}
        $terrariaRebuilt=$terrariaName -in @('action.cc','ghidra_process.cc')
        if($terrariaRebuilt){
            $terrariaObject="$terrariaBuild/$terrariaStem.o"
            $terrariaArgs=@($terrariaPrepared.compile_flags | ForEach-Object {[string]$_})+@('-c',"$terrariaTrace/source/$terrariaName",'-o',$terrariaObject)
            Invoke-DiagCompiler $terrariaArgs "$terrariaBuild/$terrariaStem.log"
            if($LASTEXITCODE -ne 0){throw "Trace compile failed: $terrariaName"}
        }
        $diagRecord.objects+=@{source=$terrariaName;object=$terrariaObject;rebuilt=$terrariaRebuilt;sha256=(Get-TerrariaHash $terrariaObject)}
        $terrariaObjects+=$terrariaObject
        Save-DiagRecord
    }
    Assert-DiagIdle
    $terrariaRsp="$terrariaBuild/objects.rsp"
    [IO.File]::WriteAllText($terrariaRsp,(@($terrariaObjects | ForEach-Object {'"'+$_.Replace('\','/')+'"'}) -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
    Invoke-DiagCompiler @(('@'+$terrariaRsp),'-Xlinker','--stack','-Xlinker','33554432,4096','-o',"$terrariaBuild/decompile.exe") "$terrariaBuild/link.log"
    if($LASTEXITCODE -ne 0){throw 'Trace link failed'}
    $diagRecord.engine_sha256=Get-TerrariaHash "$terrariaBuild/decompile.exe"
    $diagRecord.status='linked_uninspected_unexecuted'
}catch{$diagRecord.status='failed';$diagRecord.error=$_.Exception.Message;throw}
finally{$diagRecord.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-DiagRecord}
