$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
$env:APPDATA="$terrariaLab/ghidra-appdata-portable-trace"
foreach($terrariaMode in @('off','on')){
    if(@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'decompile.exe' -or ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'terraria-re-20261012')}).Count){throw 'Another analysis engine active'}
    $terrariaTitle=(Get-Culture).TextInfo.ToTitleCase($terrariaMode)
    $terrariaSources="$terrariaLab/portable-trace-$terrariaMode-smoke-sources-20261018"
    $terrariaClass="TerrariaPortableTrace$($terrariaTitle)CSmoke"
    $terrariaFolder="pseudocode-portable-trace-$terrariaMode-c-smoke-20261017"
    if(Test-Path -LiteralPath "$terrariaLab/$terrariaFolder"){throw 'Preserve prior smoke'}
    if($terrariaMode -eq 'off'){Remove-Item Env:TERRARIA_DECOMP_TRACE_FILE -ErrorAction SilentlyContinue}
    else{$env:TERRARIA_DECOMP_TRACE_FILE="$terrariaLab/portable-trace-on-smoke-20261018"}
    & "$terrariaLab/ghidra-portable-trace-20261018/support/analyzeHeadless.bat" "$terrariaLab/ghidra-project-portable-smoke-20261018" TerrariaAndroidFinal -process libil2cpp.so -readOnly -noanalysis -scriptPath $terrariaSources -postScript "$terrariaClass.java" $terrariaLab "$terrariaSources/$terrariaClass.java" $terrariaFolder 0x74129c c-smoke -log "$terrariaLab/portable-trace-$terrariaMode-smoke-20261018.ghidra.log"
    if($LASTEXITCODE -ne 0){throw "Ghidra failed: $terrariaMode"}
    & $terrariaPython "$terrariaSources/audit_terraria_portable_trace_$($terrariaMode)_c_smoke.py" $terrariaLab "$terrariaSources/$terrariaClass.java" $terrariaFolder 0x74129c
    if($LASTEXITCODE -ne 0){throw "Trace smoke audit failed: $terrariaMode"}
}
