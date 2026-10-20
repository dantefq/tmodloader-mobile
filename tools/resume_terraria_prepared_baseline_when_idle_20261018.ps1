# Resume only previously prepared inputs. No extraction, installation or engine execution.
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaPreparation=Join-Path $terrariaLab 'portable-decompiler-baseline-prep-20261017'
$terrariaStatePath=Join-Path $terrariaLab 'portable-baseline-resume-20261018.json'
$terrariaPriorPath=Join-Path $terrariaLab 'portable-baseline-continuation-20261017.json'
$terrariaSummaryPath='C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012/long-budget-c-continuation-20261017/summary.json'
if(Test-Path -LiteralPath $terrariaStatePath){throw 'Resume already recorded; inspect before repeating'}
$terrariaPrior=Get-Content -LiteralPath $terrariaPriorPath -Raw | ConvertFrom-Json
if($terrariaPrior.status -ne 'waiting_for_completed_long_budget_and_idle_engine' -or $terrariaPrior.build_executed -or $terrariaPrior.engine_executed){throw 'Prior state differs from reviewed interrupted checkpoint'}
$terrariaOther=@(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.Name -match '^(pwsh|powershell)\.exe$' -and $_.CommandLine -match '-File\s+.*(run_terraria_portable_baseline_when_idle|resume_terraria_prepared_baseline_when_idle)' })
if($terrariaOther.Count){throw 'Another baseline continuation exists'}
$terrariaManifestPath=Join-Path $terrariaPreparation 'preparation-manifest.json'
$terrariaManifest=Get-Content -LiteralPath $terrariaManifestPath -Raw | ConvertFrom-Json
$terrariaManifestHash=(Get-FileHash -LiteralPath $terrariaManifestPath).Hash.ToLower()
$terrariaBuilder=Join-Path $terrariaPreparation 'build-baseline.ps1'
if((Get-FileHash -LiteralPath $terrariaBuilder).Hash.ToLower() -ne $terrariaManifest.builder_sha256){throw 'Builder identity differs'}
if(Test-Path -LiteralPath (Join-Path $terrariaPreparation 'baseline-build')){throw 'Build already started; inspect preserved evidence'}
$terrariaDeadline=[DateTime]::UtcNow.AddHours(6)
$terrariaState=@{status='waiting_for_completed_long_budget_and_idle_engine';start_UTC=[DateTime]::UtcNow.ToString('o');deadline_UTC=$terrariaDeadline.ToString('o');prior_state_sha256=(Get-FileHash -LiteralPath $terrariaPriorPath).Hash.ToLower();preparation_manifest_sha256=$terrariaManifestHash;runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower();build_executed=$false;engine_executed=$false;C_coverage_addition=0}
function Save-TerrariaResume { $terrariaState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $terrariaStatePath -Encoding utf8 }
Save-TerrariaResume
try {
    while($true){
        if([DateTime]::UtcNow -gt $terrariaDeadline){throw 'Finite resume deadline reached'}
        $terrariaSummary=Get-Content -LiteralPath $terrariaSummaryPath -Raw | ConvertFrom-Json
        $terrariaBusy=@(Get-CimInstance Win32_Process | Where-Object {
            $_.Name -eq 'decompile.exe' -or
            ($_.Name -in @('java.exe','javaw.exe') -and $_.CommandLine -match 'ghidra|analyzeHeadless|terraria-re-20261012') -or
            ($_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -match 'terraria_angr_.*probe|angr.*supervis')
        })
        if($terrariaSummary.finished_planned_attempts -eq $true -and @($terrariaSummary.not_yet_audited_planned_addresses).Count -eq 0 -and $terrariaBusy.Count -eq 0){break}
        Start-Sleep -Seconds 30
    }
    if($terrariaSummary.remaining_hard_methods_without_C -eq 0){
        $terrariaState.status='skipped_all_planned_C_recovered'
    }else{
        if((Get-FileHash -LiteralPath $terrariaManifestPath).Hash.ToLower() -ne $terrariaManifestHash){throw 'Prepared manifest changed while waiting'}
        $terrariaState.status='building_unmodified_portable_baseline';$terrariaState.build_executed=$true;Save-TerrariaResume
        & $terrariaBuilder
        $terrariaBuild=Get-Content -LiteralPath (Join-Path $terrariaPreparation 'baseline-build/build-manifest.json') -Raw | ConvertFrom-Json
        if($terrariaBuild.status -ne 'linked_uninspected_unexecuted'){throw 'Build did not reach reviewed link checkpoint'}
        $terrariaState.status='linked_pending_PE_and_runtime_review';$terrariaState.engine_sha256=$terrariaBuild.engine_sha256
    }
}catch{
    $terrariaState.status='failed';$terrariaState.error=$_.Exception.Message;throw
}finally{
    $terrariaState.end_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaResume
}
