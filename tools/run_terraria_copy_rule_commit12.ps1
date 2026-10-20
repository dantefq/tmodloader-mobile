param([ValidateSet('smoke','drawnpc1','drawnpc2','kill')][string]$Target='smoke',[ValidateRange(30,2100)][int]$Seconds=300,[ValidatePattern('^[a-z][a-z0-9-]{0,24}$')][string]$Attempt)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){throw 'PowerShell 7 required'}
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaSources="$terrariaLab/copy-rule-off-sources-20261019"
$terrariaAddress=@{smoke='0x74129c';drawnpc1='0xf6954c';drawnpc2='0xf9a914';kill='0x1484e54'}[$Target]
if($Target -eq 'smoke' -and $Attempt){throw 'Smoke must retain its fixed profile folder'}
$terrariaName=if($Attempt){"$Target-$Attempt"}else{$Target}
$terrariaFolder="pseudocode-copy-rule-off-c-$terrariaName-20261019"
$terrariaStatePath="$terrariaLab/copy-rule-off-$terrariaName-20261019.json"
if((Test-Path -LiteralPath $terrariaStatePath) -or (Test-Path -LiteralPath "$terrariaLab/$terrariaFolder")){throw 'Preserve previous attempt'}
if(@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'decompile.exe' -or ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'terraria-re-20261012')}).Count){throw 'Another analysis engine active'}
$terrariaSourceManifest=Get-Content "$terrariaSources/source-manifest.json" -Raw | ConvertFrom-Json
foreach($terrariaFile in $terrariaSourceManifest.source_files){
    if([IO.Path]::GetFileName($terrariaFile.name) -ne $terrariaFile.name -or (Get-FileHash "$terrariaSources/$($terrariaFile.name)").Hash.ToLower() -ne $terrariaFile.sha256){throw 'Diagnostic source changed'}
}
if((Get-FileHash "$terrariaLab/ghidra-guard-range-20261019/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe").Hash.ToLower() -ne $terrariaSourceManifest.engine_sha256){throw 'Engine changed'}
$terrariaLauncher="$terrariaLab/copy-rule-off-$terrariaName-launch-20261019.ps1"
if(Test-Path -LiteralPath $terrariaLauncher){throw 'Preserve previous launcher'}
$terrariaSmokeArg=if($Target -eq 'smoke'){' c-smoke'}else{''}
$terrariaCommand=@"
`$ErrorActionPreference='Stop'
`$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
`$env:APPDATA='$terrariaLab/ghidra-appdata-guard-range-20261019'
`$env:TERRARIA_DECOMP_TRACE_FILE='$terrariaLab/copy-rule-off-$terrariaName-20261019'
& '$terrariaLab/ghidra-guard-range-20261019/support/analyzeHeadless.bat' '$terrariaLab/ghidra-project-portable-smoke-20261018' TerrariaAndroidFinal -process libil2cpp.so -readOnly -noanalysis -scriptPath '$terrariaSources' -postScript TerrariaCopyRuleOffProbe.java '$terrariaLab' '$terrariaSources/TerrariaCopyRuleOffProbe.java' '$terrariaFolder' '$terrariaAddress'$terrariaSmokeArg -log '$terrariaLab/copy-rule-off-$terrariaName-20261019.ghidra.log'
exit `$LASTEXITCODE
"@
[IO.File]::WriteAllText($terrariaLauncher,$terrariaCommand,[Text.UTF8Encoding]::new($false))
$terrariaInfo=[Diagnostics.ProcessStartInfo]::new()
$terrariaInfo.FileName=(Get-Process -Id $PID).Path
$terrariaInfo.UseShellExecute=$false;$terrariaInfo.CreateNoWindow=$true
$terrariaInfo.RedirectStandardOutput=$true;$terrariaInfo.RedirectStandardError=$true
foreach($terrariaArg in @('-NoProfile','-File',$terrariaLauncher)){$terrariaInfo.ArgumentList.Add($terrariaArg)}
$terrariaProcess=[Diagnostics.Process]::new();$terrariaProcess.StartInfo=$terrariaInfo
$terrariaNativeTimeout=if($Target -eq 'smoke'){60}else{1800}
$terrariaState=@{status='starting';target=$Target;attempt=$Attempt;address=$terrariaAddress;external_deadline_seconds=$Seconds;native_timeout_seconds=$terrariaNativeTimeout;runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower();sampled_tree_private_limit_bytes=12884901888;peak_tree_private_bytes=0;minimum_free_commit_KiB=4194304;C_coverage_addition=0;timed_out_observed=$false;started_UTC=[DateTime]::UtcNow.ToString('o')}
function Save-TerrariaDiagnostic { [IO.File]::WriteAllText($terrariaStatePath,($terrariaState | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
$terrariaStarted=$false
try {
    if(-not $terrariaProcess.Start()){throw 'Launch failed'}
    $terrariaStarted=$true;$terrariaState.root_PID=$terrariaProcess.Id;$terrariaState.status='running';Save-TerrariaDiagnostic
    $terrariaStdout=$terrariaProcess.StandardOutput.ReadToEndAsync();$terrariaStderr=$terrariaProcess.StandardError.ReadToEndAsync()
    $terrariaDeadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    while(-not $terrariaProcess.WaitForExit(1000)){
        $terrariaSnapshot=@(Get-CimInstance Win32_Process)
        $terrariaIds=[Collections.Generic.HashSet[int]]::new();[void]$terrariaIds.Add($terrariaProcess.Id)
        do {$terrariaAdded=$false;foreach($terrariaChild in $terrariaSnapshot){if($terrariaIds.Contains([int]$terrariaChild.ParentProcessId) -and $terrariaChild.CreationDate -ge $terrariaProcess.StartTime -and $terrariaIds.Add([int]$terrariaChild.ProcessId)){$terrariaAdded=$true}}}while($terrariaAdded)
        $terrariaPrivate=[long]0
        foreach($terrariaId in $terrariaIds){try{$terrariaPrivate+=(Get-Process -Id $terrariaId -ErrorAction Stop).PrivateMemorySize64}catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}}
        $terrariaState.current_tree_private_bytes=$terrariaPrivate
        if($terrariaPrivate -gt $terrariaState.peak_tree_private_bytes){$terrariaState.peak_tree_private_bytes=$terrariaPrivate}
        $terrariaMemory=Get-CimInstance Win32_OperatingSystem
        $terrariaStop=$null
        if($terrariaPrivate -gt 12884901888){$terrariaStop='sampled_owned_tree_memory_limit'}
        elseif($terrariaMemory.FreeVirtualMemory -lt 4194304){$terrariaStop='free_commit_below_4GiB'}
        elseif([DateTime]::UtcNow -gt $terrariaDeadline){$terrariaStop='external_diagnostic_deadline'}
        Save-TerrariaDiagnostic
        if($terrariaStop){$terrariaState.external_stop_reason=$terrariaStop;$terrariaProcess.Kill($true);break}
    }
    $terrariaProcess.WaitForExit()
    [IO.File]::WriteAllText("$terrariaStatePath.stdout.log",$terrariaStdout.GetAwaiter().GetResult())
    [IO.File]::WriteAllText("$terrariaStatePath.stderr.log",$terrariaStderr.GetAwaiter().GetResult())
    $terrariaState.exit_code=$terrariaProcess.ExitCode
    if(Test-Path -LiteralPath "$terrariaLab/$terrariaFolder/result.json"){
        $terrariaResult=Get-Content "$terrariaLab/$terrariaFolder/result.json" -Raw | ConvertFrom-Json
        $terrariaState.status='result_returned_pending_audit';$terrariaState.timed_out_observed=$terrariaResult.timed_out
        & 'C:/Private/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe' "$terrariaSources/audit_terraria_copy_rule_off.py" $terrariaLab "$terrariaSources/TerrariaCopyRuleOffProbe.java" $terrariaFolder $terrariaAddress
        if($LASTEXITCODE -ne 0){throw 'Diagnostic result audit failed'}
        $terrariaState.status='result_audited';$terrariaState.producer_status=$terrariaResult.status
    }else{$terrariaState.status='interrupted_without_result'}
}catch{$terrariaState.status='runner_error';$terrariaState.error=$_.Exception.Message;throw}
finally{
    if($terrariaStarted -and -not $terrariaProcess.HasExited){$terrariaProcess.Kill($true);$terrariaProcess.WaitForExit()}
    $terrariaProcess.Dispose();$terrariaState.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaDiagnostic
}
