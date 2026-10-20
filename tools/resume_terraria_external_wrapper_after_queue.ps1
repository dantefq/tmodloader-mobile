param(
    [Parameter(Mandatory)][int]$WaitPID,
    [Parameter(Mandatory)][datetimeoffset]$WaitStartedUTC
)
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaPython='C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$terrariaOwner=Get-CimInstance Win32_Process -Filter "ProcessId=$WaitPID"
if(-not $terrariaOwner -or $terrariaOwner.Name -ne 'pwsh.exe' -or $terrariaOwner.CommandLine -notmatch 'run_terraria_native_v3_remaining.ps1'){
    throw 'Expected queue process identity not found'
}
$terrariaWaitProcess=Get-Process -Id $WaitPID
if([math]::Abs(($terrariaWaitProcess.StartTime.ToUniversalTime()-$WaitStartedUTC.UtcDateTime).TotalMilliseconds) -gt 1){throw 'Queue creation time changed'}
$terrariaReceipt="$terrariaLab/external_wrapper-restored-wait-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')).json"
$terrariaState=[ordered]@{status='waiting_for_owned_serial_queue';waiting_PID=$WaitPID;waiting_started_UTC=$WaitStartedUTC.ToString('o');started_UTC=[DateTime]::UtcNow.ToString('o');restored_library='libexternal_wrapper.so'}
function Save-TerrariaRestoreState{[IO.File]::WriteAllText($terrariaReceipt,($terrariaState|ConvertTo-Json -Depth 5))}
Save-TerrariaRestoreState
try{
    while(-not $terrariaWaitProcess.WaitForExit(1000)){}
    $terrariaState.status='resuming_restored_external_wrapper';Save-TerrariaRestoreState
    & "$PSScriptRoot/run_terraria_native_v3_remaining.ps1" -Libraries 'libexternal_wrapper.so'
    $terrariaState.status='native_queue_returned_pending_delivery';Save-TerrariaRestoreState
    & $terrariaPython "$PSScriptRoot/summarize_terraria_native_v3_audits.py"
    if($LASTEXITCODE -ne 0){throw 'Scope checkpoint failed'}
    & $terrariaPython "$PSScriptRoot/package_terraria_other_native_exports.py"
    if($LASTEXITCODE -ne 0){throw 'Native delivery verification failed'}
    & $terrariaPython "$PSScriptRoot/package_terraria_apk_scope.py"
    if($LASTEXITCODE -ne 0){throw 'APK scope delivery verification failed'}
    $terrariaState.status='restored_queue_and_delivery_completed'
}catch{
    $terrariaState.status='restored_queue_failed';$terrariaState.error=$_.Exception.Message;throw
}finally{
    $terrariaState.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaRestoreState
    $terrariaWaitProcess.Dispose()
}
$terrariaState|ConvertTo-Json -Depth 5
