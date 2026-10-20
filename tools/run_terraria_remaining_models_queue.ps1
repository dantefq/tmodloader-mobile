# Sequential active-session continuation. Never launches alongside the coarse queue.
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaTools='C:/Private/Documents/ChatGPT/universal-modder 2/tools'
$terrariaDelivery='C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
$env:APPDATA="$terrariaLab/ghidra-appdata"
Write-Output 'Waiting for the audited coarse queue; next models use separate readonly project copies.'
$terrariaDeadline=[DateTime]::UtcNow.AddHours(2)
while ($true) {
    $terrariaReady=$true
    foreach ($terrariaName in @('drawproj','hiteffect','kill','recipes')) {
        $terrariaFolder="$terrariaLab/pseudocode-coarse-$terrariaName-20261015"
        if (-not (Test-Path -LiteralPath "$terrariaFolder/result.json") -or -not (Test-Path -LiteralPath "$terrariaFolder/audit.json")) { $terrariaReady=$false }
    }
    $terrariaBusy=Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('java.exe','decompile.exe') -and $_.CommandLine -like '*terraria-re-20261012*' }
    if ($terrariaReady -and -not $terrariaBusy) { break }
    if ([DateTime]::UtcNow -gt $terrariaDeadline) { throw 'Previous queue did not complete; inspect saved state.' }
    Start-Sleep -Seconds 30
}
function Invoke-TerrariaModel([string]$terrariaKind,[string]$terrariaName,[string]$terrariaAddress,[bool]$terrariaSmoke=$false) {
    if ($terrariaKind -eq 'extended') {
        $terrariaScript='TerrariaExtendedNoreturnProbe.java'
        $terrariaAuditor='audit_terraria_extended_noreturn.py'
        $terrariaPackager='package_terraria_extended_noreturn_continuation.py'
        $terrariaOutput="pseudocode-extended-noreturn-$terrariaName-20261015"
    } elseif ($terrariaKind -eq 'coarse') {
        $terrariaScript='TerrariaNoreturnCoarseProbe.java'
        $terrariaAuditor='audit_terraria_noreturn_coarse_probe_v2.py'
        $terrariaPackager='package_terraria_noreturn_coarse_continuation.py'
        $terrariaOutput="pseudocode-noreturn-coarse-$terrariaName-20261015"
    } else { throw 'Unknown model' }
    $terrariaScriptArgs=@($terrariaLab,"$terrariaTools/$terrariaScript",$terrariaOutput,$terrariaAddress)
    if ($terrariaKind -eq 'extended' -and $terrariaSmoke) { $terrariaScriptArgs+='transaction-smoke' }
    if (-not (Test-Path -LiteralPath "$terrariaLab/$terrariaOutput/result.json")) {
        & "$terrariaLab/ghidra-stack32/support/analyzeHeadless.bat" "$terrariaLab/ghidra-project-noreturn-v5" TerrariaAndroidFinal -process libil2cpp.so -readOnly -noanalysis -scriptPath $terrariaTools -postScript $terrariaScript @terrariaScriptArgs -log "$terrariaLab/$terrariaOutput.log"
        if ($LASTEXITCODE -ne 0) { throw "Ghidra process failed: $terrariaKind/$terrariaName" }
    }
    & $terrariaPython "$terrariaTools/$terrariaAuditor" $terrariaLab "$terrariaTools/$terrariaScript" $terrariaOutput $terrariaAddress
    if ($LASTEXITCODE -ne 0) { throw "Independent model audit failed: $terrariaKind/$terrariaName" }
    & $terrariaPython "$terrariaTools/$terrariaPackager"
    if ($LASTEXITCODE -ne 0) { throw 'Model checkpoint failed' }
    & $terrariaPython "$terrariaTools/package_terraria_coarse_continuation.py"
    if ($LASTEXITCODE -ne 0) { throw 'Coverage checkpoint failed' }
    & $terrariaPython "$terrariaTools/package_terraria_native_continuation.py" --lab $terrariaLab --delivery $terrariaDelivery
    if ($LASTEXITCODE -ne 0) { throw 'Master checkpoint failed' }
}
Invoke-TerrariaModel 'coarse' 'smoke' 'transaction-smoke' $true
Invoke-TerrariaModel 'extended' 'transaction-smoke' '0x11242ec' $true
$terrariaCoverage=Get-Content -LiteralPath "$terrariaDelivery/coarse-continuation-20261015/summary.json" -Raw | ConvertFrom-Json
$terrariaRemaining=@($terrariaCoverage.remaining_methods | ForEach-Object { $_.address })
if ($terrariaRemaining.Count -ne $terrariaCoverage.remaining_hard_methods_without_C) { throw 'Remaining-method enumeration disagrees with audited count' }
$terrariaTargets=@(@('coarse','bestiary','0xb1ab78'),@('extended','processdata','0x11242ec'),@('coarse','recipes','0x1635538'),@('extended','kill','0x1484e54'),@('extended','drawproj','0xfcbda0'),@('extended','drawnormal','0x911f1c'),@('extended','drawnpc1','0xf6954c'),@('extended','drawnpc2','0xf9a914'))
$terrariaPlanned=@($terrariaTargets | Where-Object { $_[2] -in $terrariaRemaining })
if ($terrariaPlanned.Count -ne $terrariaRemaining.Count) { throw 'Target plan does not cover every remaining method' }
foreach ($terrariaKind in @('coarse','extended')) {
    $terrariaAddresses=@($terrariaPlanned | Where-Object { $_[0] -eq $terrariaKind } | ForEach-Object { $_[2] })
    $terrariaPlanName=if ($terrariaKind -eq 'coarse') { 'noreturn-coarse-plan-20261015.json' } else { 'extended-noreturn-plan-20261015.json' }
    @{ model=$terrariaKind; created_UTC=[DateTime]::UtcNow.ToString('o'); addresses=$terrariaAddresses; read_only_project='ghidra-project-noreturn-v5'; prior_coarse_summary_sha256=(Get-FileHash -LiteralPath "$terrariaDelivery/coarse-continuation-20261015/summary.json").Hash.ToLower() } | ConvertTo-Json | Set-Content -LiteralPath "$terrariaLab/$terrariaPlanName" -Encoding utf8
}
foreach ($terrariaTarget in $terrariaPlanned) { Invoke-TerrariaModel $terrariaTarget[0] $terrariaTarget[1] $terrariaTarget[2] }
Write-Output 'Remaining model queue completed, with independently audited checkpoints.'
