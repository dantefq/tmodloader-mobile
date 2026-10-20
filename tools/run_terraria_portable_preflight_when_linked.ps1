# Finite source/static-only continuation. Never launches a generated engine.
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaTools=$PSScriptRoot
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$terrariaPreparation=Join-Path $terrariaLab 'portable-decompiler-baseline-prep-20261017'
$terrariaBuildState=Join-Path $terrariaLab 'portable-baseline-resume-20261018.json'
$terrariaStatePath=Join-Path $terrariaLab 'portable-preflight-continuation-20261018.json'
$terrariaPE=Join-Path $terrariaLab 'pe-review-portable-baseline-20261018.json'
$terrariaSources=Join-Path $terrariaLab 'portable-baseline-smoke-sources-20261018'
$terrariaInspector=Join-Path $terrariaTools 'review_terraria_decompiler_pe.py'
$terrariaGenerator=Join-Path $terrariaTools 'prepare_terraria_portable_smoke_sources.py'
if(Test-Path -LiteralPath $terrariaStatePath){throw 'Existing preflight continuation must be inspected'}
function Assert-TerrariaPinnedPreflightTools {
    if((Get-FileHash -LiteralPath $terrariaInspector).Hash.ToLower() -ne 'fcecf18468c6c0568eca73c8cd1250f287ca81f7cb26199b69815518e36a78e8'){throw 'Reviewed PE inspector differs'}
    if((Get-FileHash -LiteralPath $terrariaGenerator).Hash.ToLower() -ne '513f51f8dc62dafaf682a7e444425e7ba7b1b660d9f8008762cfd8450f3781b3'){throw 'Reviewed smoke generator differs'}
}
Assert-TerrariaPinnedPreflightTools
$terrariaDeadline=[DateTime]::UtcNow.AddHours(6)
$terrariaState=@{status='waiting_for_baseline_link';started_UTC=[DateTime]::UtcNow.ToString('o');deadline_UTC=$terrariaDeadline.ToString('o');runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower();engine_executed=$false;compiler_invoked=$false;C_coverage_addition=0}
function Save-TerrariaPreflight { $terrariaState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $terrariaStatePath -Encoding utf8 }
Save-TerrariaPreflight
try {
    while($true){
        if([DateTime]::UtcNow -gt $terrariaDeadline){throw 'Finite preflight deadline reached'}
        if(Test-Path -LiteralPath $terrariaBuildState){
            $terrariaBaseline=Get-Content -LiteralPath $terrariaBuildState -Raw | ConvertFrom-Json
            if($terrariaBaseline.status -eq 'failed'){throw ('Baseline continuation failed: '+$terrariaBaseline.error)}
            if($terrariaBaseline.status -eq 'skipped_all_planned_C_recovered'){
                $terrariaState.status='skipped_all_planned_C_recovered';break
            }
            if($terrariaBaseline.status -eq 'linked_pending_PE_and_runtime_review'){break}
        }
        Start-Sleep -Seconds 30
    }
    if($terrariaState.status -ne 'skipped_all_planned_C_recovered'){
        $terrariaBuildPath=Join-Path $terrariaPreparation 'baseline-build/build-manifest.json'
        $terrariaBuild=Get-Content -LiteralPath $terrariaBuildPath -Raw | ConvertFrom-Json
        if($terrariaBuild.status -ne 'linked_uninspected_unexecuted' -or $terrariaBuild.engine_sha256 -ne $terrariaBaseline.engine_sha256){throw 'Linked baseline identity mismatch'}
        if((Test-Path -LiteralPath $terrariaPE) -or (Test-Path -LiteralPath $terrariaSources)){throw 'Preserve existing preflight output'}
        $terrariaState.status='static_PE_review';Save-TerrariaPreflight
        Assert-TerrariaPinnedPreflightTools
        & $terrariaPython $terrariaInspector (Join-Path $terrariaPreparation 'baseline-build/decompile.exe') --expect-sha256 $terrariaBuild.engine_sha256 --output $terrariaPE
        if($LASTEXITCODE -ne 0){throw 'Portable PE preflight rejected the linked engine'}
        $terrariaReview=Get-Content -LiteralPath $terrariaPE -Raw | ConvertFrom-Json
        if($terrariaReview.header_gates_passed -ne $true -or @($terrariaReview.static_gate_failures).Count -ne 0 -or $terrariaReview.launch_eligible -ne $false){throw 'Unexpected PE preflight result'}
        $terrariaState.status='preparing_separate_smoke_sources';Save-TerrariaPreflight
        Assert-TerrariaPinnedPreflightTools
        & $terrariaPython $terrariaGenerator --preparation $terrariaPreparation --pe-review $terrariaPE --output $terrariaSources
        if($LASTEXITCODE -ne 0){throw 'Portable source preparation failed'}
        $terrariaSourceManifest=Get-Content -LiteralPath (Join-Path $terrariaSources 'smoke-source-manifest.json') -Raw | ConvertFrom-Json
        foreach($terrariaSource in $terrariaSourceManifest.source_files){
            if([IO.Path]::GetFileName($terrariaSource.path) -ne $terrariaSource.path){throw 'Unexpected generated source path'}
            if((Get-FileHash -LiteralPath (Join-Path $terrariaSources $terrariaSource.path)).Hash.ToLower() -ne $terrariaSource.sha256){throw 'Generated source identity differs'}
        }
        $terrariaSelfTest= & $terrariaPython (Join-Path $terrariaSources 'audit_terraria_portable_baseline_c_smoke.py') $terrariaLab (Join-Path $terrariaSources 'TerrariaPortableBaselineCSmoke.java') --self-test
        if($LASTEXITCODE -ne 0){throw 'Portable generated auditor self-test failed'}
        $terrariaSelfTest | Set-Content -LiteralPath (Join-Path $terrariaSources 'auditor-self-test.json') -Encoding utf8
        $terrariaAudited=$terrariaSelfTest | ConvertFrom-Json
        if($terrariaAudited.integrity_passed -ne $true){throw 'Generated auditor self-test did not pass'}
        $terrariaState.status='sources_and_static_preflight_ready_pending_deployment_and_actual_C_smoke'
        $terrariaState.engine_sha256=$terrariaBuild.engine_sha256
        $terrariaState.PE_review_sha256=(Get-FileHash -LiteralPath $terrariaPE).Hash.ToLower()
        $terrariaState.smoke_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $terrariaSources 'smoke-source-manifest.json')).Hash.ToLower()
        $terrariaState.self_test_sha256=(Get-FileHash -LiteralPath (Join-Path $terrariaSources 'auditor-self-test.json')).Hash.ToLower()
    }
}catch{
    $terrariaState.status='failed';$terrariaState.error=$_.Exception.Message;throw
}finally{
    $terrariaState.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaPreflight
}
