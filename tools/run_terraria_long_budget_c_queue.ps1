# Sequential budget-only experiment. Default waits for the Branch-preserving plan; explicit checkpoint override records incomplete prior work.
param([switch]$StartFromCurrentCheckpoint)
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaTools='C:/Private/Documents/ChatGPT/universal-modder 2/tools'
$terrariaDelivery='C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$terrariaDeadline=[DateTime]::UtcNow.AddHours(10)
$terrariaWaitDeadline=[DateTime]::UtcNow.AddHours(3)
$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
$env:APPDATA="$terrariaLab/ghidra-appdata"
function Test-TerrariaBusy {
    $terrariaProcesses=@(Get-CimInstance Win32_Process | Where-Object {
        ($_.Name -in @('java.exe','decompile.exe') -and ($_.CommandLine -like '*terraria-re-20261012*' -or $_.ExecutablePath -like '*terraria-re-20261012*')) -or
        ($_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -match 'terraria_angr_.*probe|angr.*supervis')
    })
    return ($terrariaProcesses.Count -gt 0)
}
function Test-TerrariaPriorPlan([string]$terrariaPlanName,[string]$terrariaSummaryName) {
    $terrariaPlanPath="$terrariaLab/$terrariaPlanName"
    $terrariaSummaryPath="$terrariaDelivery/$terrariaSummaryName/summary.json"
    if (-not (Test-Path -LiteralPath $terrariaPlanPath) -or -not (Test-Path -LiteralPath $terrariaSummaryPath)) { return $false }
    $terrariaPlan=Get-Content -LiteralPath $terrariaPlanPath -Raw | ConvertFrom-Json
    $terrariaSummary=Get-Content -LiteralPath $terrariaSummaryPath -Raw | ConvertFrom-Json
    $terrariaExpected=@($terrariaPlan.addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $terrariaReported=@($terrariaSummary.planned_addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($terrariaExpected.Count -eq 0 -and $terrariaReported.Count -eq 0 -and $terrariaSummary.remaining_hard_methods_without_C -eq 0 -and $terrariaSummary.finished_planned_attempts -eq $true) { return $true }
    if ($terrariaExpected.Count -eq 0 -or $terrariaReported.Count -eq 0) { throw 'Empty previous target plan with unresolved coverage: inspect queue; do not silently begin fallback.' }
    if (@(Compare-Object -ReferenceObject $terrariaExpected -DifferenceObject $terrariaReported).Count -ne 0) { return $false }
    $terrariaDone=@($terrariaSummary.attempts | ForEach-Object { [string]$_.address } | Sort-Object -Unique)
    foreach ($terrariaEarlierStage in @('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016')) {
        $terrariaEarlierPath="$terrariaDelivery/$terrariaEarlierStage/summary.json"
        if (Test-Path -LiteralPath $terrariaEarlierPath) {
            $terrariaEarlierSummary=Get-Content -LiteralPath $terrariaEarlierPath -Raw | ConvertFrom-Json
            $terrariaDone+=@($terrariaEarlierSummary.conditional_candidates | ForEach-Object { [string]$_.address })
        }
    }
    if (@($terrariaExpected | Where-Object { $_ -notin $terrariaDone }).Count -gt 0) { return $false }
    return ($terrariaSummary.finished_planned_attempts -eq $true -and @($terrariaSummary.not_yet_audited_planned_addresses).Count -eq 0)
}
Write-Output 'Waiting for the explicit audited Branch-preserving target plan and an idle lab Ghidra engine.'
if ($StartFromCurrentCheckpoint) {
    if (Test-TerrariaBusy) { throw 'An engine is active; cannot change profile now.' }
    $terrariaPrior=@()
    foreach ($terrariaStage in @('noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016')) {
        $terrariaSource="$terrariaDelivery/$terrariaStage/summary.json"
        $terrariaSummary=Get-Content -LiteralPath $terrariaSource -Raw | ConvertFrom-Json
        $terrariaPrior+=@{stage=$terrariaStage;summary_sha256=(Get-FileHash -LiteralPath $terrariaSource).Hash.ToLower();finished_planned_attempts=$terrariaSummary.finished_planned_attempts;not_yet_audited_planned_addresses=$terrariaSummary.not_yet_audited_planned_addresses}
    }
    @{reason='Explicit StartFromCurrentCheckpoint selects a separate long-budget C profile from current audited coverage; prior incomplete plans remain recorded without claiming completion.';recorded_UTC=[DateTime]::UtcNow.ToString('o');prior_plans_claimed_complete=$false;prior_checkpoints=$terrariaPrior} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$terrariaLab/long-budget-c-strategy-checkpoint-20261017.json" -Encoding utf8
}
while (-not $StartFromCurrentCheckpoint) {
    $terrariaUntypedReady=Test-TerrariaPriorPlan 'branch-preserving-c-plan-20261016.json' 'branch-preserving-c-continuation-20261016'
    if ($terrariaUntypedReady -and -not (Test-TerrariaBusy)) { break }
    if ([DateTime]::UtcNow -gt $terrariaWaitDeadline) { throw 'Prior models did not finish before deadline; inspect preserved results.' }
    Start-Sleep -Seconds 30
}
function Update-TerrariaCheckpoints {
    & $terrariaPython "$terrariaTools/package_terraria_long_budget_c_continuation.py"
    if ($LASTEXITCODE -ne 0) { throw 'Long-budget C checkpoint failed' }
    & $terrariaPython "$terrariaTools/package_terraria_coarse_continuation.py"
    if ($LASTEXITCODE -ne 0) { throw 'Coverage checkpoint failed' }
    & $terrariaPython "$terrariaTools/package_terraria_native_continuation.py" --lab $terrariaLab --delivery $terrariaDelivery
    if ($LASTEXITCODE -ne 0) { throw 'Master checkpoint failed' }
}
function Invoke-TerrariaLongBudget([string]$terrariaName,[string]$terrariaAddress,[bool]$terrariaSmoke=$false) {
    if ([DateTime]::UtcNow -gt $terrariaDeadline) { throw 'Finite queue deadline reached; preserve pending plan for explicit resume.' }
    if (Test-TerrariaBusy) { throw 'Another lab Ghidra/decompiler is active; refusing concurrent launch.' }
    $terrariaOutput="pseudocode-long-budget-c-$terrariaName-20261017"
    $terrariaFolder="$terrariaLab/$terrariaOutput"
    $terrariaResult="$terrariaFolder/result.json"
    $terrariaLog="$terrariaLab/$terrariaOutput.log"
    if (Test-Path -LiteralPath $terrariaResult) {
        Write-Output "Recorded result exists; audit without repeating decompilation: $terrariaOutput"
    } else {
        if ((Test-Path -LiteralPath $terrariaFolder) -or (Test-Path -LiteralPath $terrariaLog)) { throw "Partial attempt exists; preserve and inspect before any new trial: $terrariaOutput" }
        $terrariaScriptArgs=@($terrariaLab,"$terrariaTools/TerrariaLongBudgetCProbe.java",$terrariaOutput,$terrariaAddress)
        if ($terrariaSmoke) { $terrariaScriptArgs+='c-smoke' }
        & "$terrariaLab/ghidra-stack32/support/analyzeHeadless.bat" "$terrariaLab/ghidra-project-noreturn-v5" TerrariaAndroidFinal -process libil2cpp.so -readOnly -noanalysis -scriptPath $terrariaTools -postScript TerrariaLongBudgetCProbe.java @terrariaScriptArgs -log $terrariaLog
        if ($LASTEXITCODE -ne 0) { throw "Ghidra process failed: $terrariaOutput" }
    }
    & $terrariaPython "$terrariaTools/audit_terraria_long_budget_c.py" $terrariaLab "$terrariaTools/TerrariaLongBudgetCProbe.java" $terrariaOutput $terrariaAddress
    if ($LASTEXITCODE -ne 0) { throw "Independent audit failed: $terrariaOutput" }
    Update-TerrariaCheckpoints
    if ($terrariaSmoke) {
        $terrariaSmokeResult=Get-Content -LiteralPath $terrariaResult -Raw | ConvertFrom-Json
        if ($terrariaSmokeResult.status -ne 'decompiled_conditional_candidate') { throw 'Real small C smoke failed; do not proceed to hard targets.' }
    }
}
Invoke-TerrariaLongBudget 'smoke' '0x74129c' $true
$terrariaRecovered=@('0x12f63e8','0x12e2cb8')
foreach ($terrariaStage in @('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016','long-budget-c-continuation-20261017')) {
    $terrariaSummaryPath="$terrariaDelivery/$terrariaStage/summary.json"
    if (Test-Path -LiteralPath $terrariaSummaryPath) {
        $terrariaSummary=Get-Content -LiteralPath $terrariaSummaryPath -Raw | ConvertFrom-Json
        $terrariaRecovered+=@($terrariaSummary.conditional_candidates | ForEach-Object { [string]$_.address })
    }
}
$terrariaTargets=@(
    [pscustomobject]@{name='recipes';address='0x1635538'},
    [pscustomobject]@{name='bestiary';address='0xb1ab78'},
    [pscustomobject]@{name='processdata';address='0x11242ec'},
    [pscustomobject]@{name='drawproj';address='0xfcbda0'},
    [pscustomobject]@{name='drawnormal';address='0x911f1c'},
    [pscustomobject]@{name='drawnpc1';address='0xf6954c'},
    [pscustomobject]@{name='drawnpc2';address='0xf9a914'},
    [pscustomobject]@{name='kill';address='0x1484e54'}
)
$terrariaPlanPath="$terrariaLab/long-budget-c-plan-20261017.json"
if (Test-Path -LiteralPath $terrariaPlanPath) {
    $terrariaPlan=Get-Content -LiteralPath $terrariaPlanPath -Raw | ConvertFrom-Json
    if ($terrariaPlan.producer_sha256 -ne (Get-FileHash -LiteralPath "$terrariaTools/TerrariaLongBudgetCProbe.java").Hash.ToLower() -or $terrariaPlan.auditor_sha256 -ne (Get-FileHash -LiteralPath "$terrariaTools/audit_terraria_long_budget_c.py").Hash.ToLower()) { throw 'Saved long-budget plan belongs to different sources; preserve evidence and inspect.' }
    $terrariaAddresses=@($terrariaPlan.addresses | ForEach-Object { [string]$_ })
    $terrariaAllowed=@($terrariaTargets | ForEach-Object { $_.address })
    if (@($terrariaAddresses | Where-Object { $_ -notin $terrariaAllowed }).Count -gt 0) { throw 'Saved plan contains an unreviewed address.' }
    $terrariaPlanned=@($terrariaTargets | Where-Object { $_.address -in $terrariaAddresses })
} else {
    $terrariaPlanned=@($terrariaTargets | Where-Object { $_.address -notin $terrariaRecovered })
    $terrariaAddresses=@($terrariaPlanned | ForEach-Object { $_.address })
    @{ model='long-budget-C';created_UTC=[DateTime]::UtcNow.ToString('o');addresses=$terrariaAddresses;read_only_project='ghidra-project-noreturn-v5';producer_sha256=(Get-FileHash -LiteralPath "$terrariaTools/TerrariaLongBudgetCProbe.java").Hash.ToLower();auditor_sha256=(Get-FileHash -LiteralPath "$terrariaTools/audit_terraria_long_budget_c.py").Hash.ToLower() } | ConvertTo-Json | Set-Content -LiteralPath $terrariaPlanPath -Encoding utf8
}
Update-TerrariaCheckpoints
foreach ($terrariaTarget in $terrariaPlanned) {
    if ($terrariaTarget.address -in $terrariaRecovered) { continue }
    Invoke-TerrariaLongBudget $terrariaTarget.name $terrariaTarget.address
}
Update-TerrariaCheckpoints
Write-Output 'Long-budget C queue completed with independently audited checkpoints.'
