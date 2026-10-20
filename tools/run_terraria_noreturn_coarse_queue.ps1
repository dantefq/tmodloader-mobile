# Active-session continuation, not a recurring scheduler. One Ghidra process at a time.
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaTools='C:/Private/Documents/ChatGPT/universal-modder 2/tools'
$terrariaDelivery='C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
$env:APPDATA="$terrariaLab/ghidra-appdata"
Write-Output 'Waiting for the four independently audited coarse attempts; no second decompiler is launched.'
$terrariaDeadline=[DateTime]::UtcNow.AddHours(2)
while ($true) {
    $terrariaReady=$true
    foreach ($terrariaName in @('drawproj','hiteffect','kill','recipes')) {
        $terrariaFolder="$terrariaLab/pseudocode-coarse-$terrariaName-20261015"
        if (-not (Test-Path -LiteralPath "$terrariaFolder/result.json") -or -not (Test-Path -LiteralPath "$terrariaFolder/audit.json")) { $terrariaReady=$false }
    }
    $terrariaBusy=Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('java.exe','decompile.exe') -and $_.CommandLine -like '*terraria-re-20261012*' }
    if ($terrariaReady -and -not $terrariaBusy) { break }
    if ([DateTime]::UtcNow -gt $terrariaDeadline) { throw 'Previous queue did not complete; preserve state and inspect it before continuing.' }
    Start-Sleep -Seconds 30
}
function Invoke-TerrariaConditionalProbe([string]$terrariaName,[string]$terrariaAddress) {
    $terrariaOutput="pseudocode-noreturn-coarse-$terrariaName-20261015"
    if (-not (Test-Path -LiteralPath "$terrariaLab/$terrariaOutput/result.json")) {
        & "$terrariaLab/ghidra-stack32/support/analyzeHeadless.bat" "$terrariaLab/ghidra-project-noreturn-v5" TerrariaAndroidFinal -process libil2cpp.so -readOnly -noanalysis -scriptPath $terrariaTools -postScript TerrariaNoreturnCoarseProbe.java $terrariaLab "$terrariaTools/TerrariaNoreturnCoarseProbe.java" $terrariaOutput $terrariaAddress -log "$terrariaLab/$terrariaOutput.log"
        if ($LASTEXITCODE -ne 0) { throw "Ghidra process failed: $terrariaName" }
    }
    & $terrariaPython "$terrariaTools/audit_terraria_noreturn_coarse_probe.py" $terrariaLab "$terrariaTools/TerrariaNoreturnCoarseProbe.java" $terrariaOutput $terrariaAddress
    if ($LASTEXITCODE -ne 0) { throw "Independent model audit failed: $terrariaName" }
    & $terrariaPython "$terrariaTools/package_terraria_noreturn_coarse_continuation.py"
    if ($LASTEXITCODE -ne 0) { throw 'Conditional checkpoint failed' }
    & $terrariaPython "$terrariaTools/package_terraria_coarse_continuation.py"
    if ($LASTEXITCODE -ne 0) { throw 'Coarse checkpoint refresh failed' }
    & $terrariaPython "$terrariaTools/package_terraria_native_continuation.py" --lab $terrariaLab --delivery $terrariaDelivery
    if ($LASTEXITCODE -ne 0) { throw 'Master checkpoint failed' }
}
Invoke-TerrariaConditionalProbe 'smoke' 'transaction-smoke'
$terrariaRemaining=(Get-Content -LiteralPath "$terrariaDelivery/coarse-continuation-20261015/summary.json" -Raw | ConvertFrom-Json).remaining_methods.address
$terrariaTargets=@(@('bestiary','0xb1ab78'),@('processdata','0x11242ec'),@('recipes','0x1635538'),@('hiteffect','0x11b1bf4'),@('kill','0x1484e54'),@('drawproj','0xfcbda0'),@('drawnormal','0x911f1c'),@('drawnpc1','0xf6954c'),@('drawnpc2','0xf9a914'))
$terrariaPlanned=@($terrariaTargets | Where-Object { $_[1] -in $terrariaRemaining })
@{ profile='conditional-standard-cxx-throw-noreturn-aggregate-unsplit-typed-v4-stack32-v1'; created_UTC=[DateTime]::UtcNow.ToString('o'); addresses=$terrariaRemaining; read_only_project='ghidra-project-noreturn-v5'; prior_coarse_summary_sha256=(Get-FileHash -LiteralPath "$terrariaDelivery/coarse-continuation-20261015/summary.json").Hash.ToLower() } | ConvertTo-Json | Set-Content -LiteralPath "$terrariaLab/noreturn-coarse-plan-20261015.json" -Encoding utf8
foreach ($terrariaTarget in $terrariaPlanned) { Invoke-TerrariaConditionalProbe $terrariaTarget[0] $terrariaTarget[1] }
Write-Output 'Conditional model queue completed; every accepted result has an independent audit and private checkpoint.'
