# One finite local continuation; no scheduler or system installation.
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaDelivery='C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'
$terrariaTools=$PSScriptRoot
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$terrariaPreparation=Join-Path $terrariaLab 'portable-decompiler-baseline-prep-20261017'
$terrariaPreparer=Join-Path $terrariaTools 'prepare_terraria_portable_decompiler_baseline.py'
$terrariaPreparerHash=(Get-FileHash -LiteralPath $terrariaPreparer).Hash.ToLower()
$terrariaDeadline=[DateTime]::UtcNow.AddHours(6)
$terrariaStatePath=Join-Path $terrariaLab 'portable-baseline-continuation-20261017.json'
if(Test-Path -LiteralPath $terrariaStatePath){throw 'Existing continuation record must be inspected before any resume'}
$terrariaState=@{status='waiting_for_verified_archive';start_UTC=[DateTime]::UtcNow.ToString('o');deadline_UTC=$terrariaDeadline.ToString('o');preparer_sha256=$terrariaPreparerHash;runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower();build_executed=$false;engine_executed=$false;C_coverage_addition=0}
function Save-TerrariaBaselineState { $terrariaState | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $terrariaStatePath -Encoding utf8 }
function Assert-TerrariaBaselineDeadline { if([DateTime]::UtcNow -gt $terrariaDeadline){throw 'Finite continuation deadline reached; inspect saved state before resume'} }
function Test-TerrariaBaselineBusy {
    return @((Get-CimInstance Win32_Process) | Where-Object {
        $_.Name -eq 'decompile.exe' -or
        ($_.Name -in @('java.exe','javaw.exe') -and $_.CommandLine -match 'ghidra|analyzeHeadless|terraria-re-20261012') -or
        ($_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -match 'terraria_angr_.*probe|angr.*supervis')
    }).Count -gt 0
}
Save-TerrariaBaselineState
try {
    $terrariaVerified=Join-Path $terrariaLab 'toolchains/llvm-mingw-20260908-download-verified.json'
    while(-not(Test-Path -LiteralPath $terrariaVerified)) { Assert-TerrariaBaselineDeadline; Start-Sleep -Seconds 30 }
    $terrariaDownload=Get-Content -LiteralPath $terrariaVerified -Raw | ConvertFrom-Json
    if($terrariaDownload.sha256 -ne '1bcf74d06b724aeecaa6412ca85f5b26fb1da770e7cdcefa9263c9c5c3ad34b6'){throw 'Download identity differs'}
    if((Get-FileHash -LiteralPath $terrariaPreparer).Hash.ToLower() -ne $terrariaPreparerHash){throw 'Preparer changed while waiting'}
    if(Test-Path -LiteralPath $terrariaPreparation){throw 'Existing preparation must be independently inspected'}
    $terrariaState.status='preparing_sources_and_toolchain';Save-TerrariaBaselineState
    & $terrariaPython $terrariaPreparer --lab $terrariaLab --delivery $terrariaDelivery
    if($LASTEXITCODE -ne 0){throw 'Preparation failed; preserve partial destination'}
    $terrariaState.status='waiting_for_completed_long_budget_and_idle_engine';Save-TerrariaBaselineState
    Write-Output 'Portable inputs prepared. Waiting for the completed LongBudget plan before any compiler invocation.'
    $terrariaSummaryPath=Join-Path $terrariaDelivery 'long-budget-c-continuation-20261017/summary.json'
    while($true) {
        Assert-TerrariaBaselineDeadline
        $terrariaSummary=Get-Content -LiteralPath $terrariaSummaryPath -Raw | ConvertFrom-Json
        if($terrariaSummary.finished_planned_attempts -eq $true -and @($terrariaSummary.not_yet_audited_planned_addresses).Count -eq 0 -and -not(Test-TerrariaBaselineBusy)){break}
        Start-Sleep -Seconds 30
    }
    if($terrariaSummary.remaining_hard_methods_without_C -eq 0){
        $terrariaState.status='skipped_all_planned_C_recovered'
        Write-Output 'All planned C recovered; diagnostic baseline build is unnecessary.'
    } else {
        $terrariaState.status='building_unmodified_portable_baseline';$terrariaState.build_executed=$true;Save-TerrariaBaselineState
        & (Join-Path $terrariaPreparation 'build-baseline.ps1')
        $terrariaBuild=Get-Content -LiteralPath (Join-Path $terrariaPreparation 'baseline-build/build-manifest.json') -Raw | ConvertFrom-Json
        if($terrariaBuild.status -ne 'linked_uninspected_unexecuted'){throw 'Baseline did not reach the expected unexecuted link checkpoint'}
        $terrariaState.status='linked_pending_PE_and_runtime_review'
        $terrariaState.engine_sha256=$terrariaBuild.engine_sha256
        Write-Output 'Portable baseline linked; engine remains unexecuted pending independent PE/runtime review.'
    }
} catch {
    $terrariaState.status='failed';$terrariaState.error=$_.Exception.Message
    throw
} finally {
    $terrariaState.end_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaBaselineState
}
