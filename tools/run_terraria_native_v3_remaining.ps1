param(
    [ValidateSet('libexternal_wrapper.so','libc++_shared.so','libpairipcore.so','libpdaprotect.so','libunity.so')]
    [string[]]$Libraries=@('libexternal_wrapper.so','libc++_shared.so','libunity.so')
)
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$terrariaSourceSHA='2abbe851f83a5bcde7864dda26652cdb7083d10634fea796bf9506e375cea3a0'
foreach($terrariaLibrary in $Libraries){
    $terrariaSlug=$terrariaLibrary.Replace('.so','').Replace('+','p')
    $terrariaAudit="$terrariaLab/other-native-$terrariaSlug-final-v3-audit-20261019.json"
    if(Test-Path -LiteralPath $terrariaAudit){throw "Prior final audit exists; inspect before another run: $terrariaAudit"}
    $terrariaOutput="$terrariaLab/other-native-range-c-$terrariaSlug-sample-v3-20261019"
    $terrariaResume=Test-Path -LiteralPath $terrariaOutput
    & "$PSScriptRoot/run_terraria_other_native_export.ps1" -Library $terrariaLibrary -Attempt sample-v3 -SourceVersion v3 -SourceSHA $terrariaSourceSHA -Seconds 7200 -Resume:$terrariaResume
    $terrariaLatest=Get-ChildItem $terrariaLab -Filter "other-native-export-$terrariaSlug-sample-v3-*.json" | Where-Object Name -notlike '*.controlled-stop.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $terrariaState=Get-Content -LiteralPath $terrariaLatest.FullName -Raw | ConvertFrom-Json
    if($terrariaState.status -ne 'process_returned_pending_audit' -or -not $terrariaState.producer_progress.all_rows_attempted){throw "Queue did not complete; preserved $($terrariaLatest.FullName)"}
    & $terrariaPython "$PSScriptRoot/audit_terraria_native_v3_library.py" $terrariaLibrary
    if($LASTEXITCODE -ne 0){throw "Independent audit failed for $terrariaLibrary"}
}
