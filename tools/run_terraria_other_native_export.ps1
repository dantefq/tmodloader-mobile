param(
    [Parameter(Mandatory)][ValidateSet('libmain.so','libGNS_Wrapper.so','libexternal_wrapper.so','libc++_shared.so','libpairipcore.so','libpdaprotect.so','libunity.so')][string]$Library,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]{0,24}$')][string]$Attempt,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceSHA,
    [ValidateSet('v1','v2','v3')][string]$SourceVersion='v1',
    [ValidateRange(0,100000)][int]$MaxRows=0,
    [ValidateRange(30,7200)][int]$Seconds=1800,
    [switch]$Resume
)
$ErrorActionPreference='Stop'
$terrariaScope=Get-Content -LiteralPath "$PSScriptRoot/terraria_apk_scope_preferences.json" -Raw | ConvertFrom-Json
if($Library -in $terrariaScope.excluded_native_libraries){throw "Library excluded by user: $Library"}
if($PSVersionTable.PSVersion.Major -lt 7){throw 'PowerShell 7 required'}
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaSources=if($SourceVersion -eq 'v3'){"$terrariaLab/other-native-exporter-v3-sources-20261019"}elseif($SourceVersion -eq 'v2'){"$terrariaLab/other-native-exporter-v2-sources-20261019"}else{"$terrariaLab/other-native-exporter-sources-20261019"}
$terrariaSource="$terrariaSources/ApkNativeRangeExport.java"
if((Get-FileHash $terrariaSource).Hash.ToLower() -ne $SourceSHA){throw 'Frozen exporter source differs'}
$terrariaManifestFolder=if($SourceVersion -eq 'v3'){"$terrariaLab/other-native-range-v3-manifests-20261019"}elseif($SourceVersion -eq 'v2'){"$terrariaLab/other-native-range-v2-manifests-20261019"}else{"$terrariaLab/other-native-range-manifests-20261019"}
$terrariaInventory=Get-Content "$terrariaManifestFolder/summary.json" -Raw | ConvertFrom-Json
$terrariaEntry=@($terrariaInventory | Where-Object library -eq $Library)
if($terrariaEntry.Count -ne 1){throw 'Unique manifest required'}
$terrariaManifest="$terrariaManifestFolder/$Library.manifest.json"
$terrariaManifestSHA=(Get-FileHash $terrariaManifest).Hash.ToLower()
if($terrariaManifestSHA -ne $terrariaEntry[0].manifest_sha256){throw 'Manifest differs from prepared inventory'}
$terrariaInput=Get-Content $terrariaManifest -Raw | ConvertFrom-Json
if((Get-FileHash -LiteralPath $terrariaInput.binary_path).Hash.ToLower() -ne $terrariaInput.elf_sha256){throw 'Input ELF changed'}
$terrariaRuntime="$terrariaLab/ghidra-guard-range-20261019"
if((Get-FileHash "$terrariaRuntime/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe").Hash.ToLower() -ne $terrariaInput.engine_sha256){throw 'Engine changed'}
if(@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'decompile.exe' -or ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'terraria-re-20261012')}).Count){throw 'Another analysis engine is active'}
$terrariaSafe=$Library.Replace('.so','').Replace('+','p')
$terrariaOutput="$terrariaLab/other-native-range-c-$terrariaSafe-$Attempt-20261019"
if((Test-Path $terrariaOutput) -ne [bool]$Resume){throw 'Fresh output required, or explicit resume for an existing output'}
$terrariaRunID=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')
$terrariaStatePath="$terrariaLab/other-native-export-$terrariaSafe-$Attempt-$terrariaRunID.json"
$terrariaProject="$terrariaLab/other-native-project-$terrariaSafe-$Attempt-$terrariaRunID"
New-Item -ItemType Directory -Path $terrariaProject | Out-Null
$terrariaLauncher="$terrariaLab/other-native-export-$terrariaSafe-$Attempt-$terrariaRunID.ps1"
$terrariaExtra=if($MaxRows){" $MaxRows"}else{''}
if($Resume){$terrariaExtra+=' resume'}
$terrariaCommand=@"
`$ErrorActionPreference='Stop'
`$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
`$env:APPDATA='$terrariaLab/ghidra-appdata-other-native-20261019'
`$env:TERRARIA_DECOMP_TRACE_FILE=`$null
& '$terrariaRuntime/support/analyzeHeadless.bat' '$terrariaProject' ApkNative -import '$($terrariaInput.binary_path)' -processor 'AARCH64:LE:64:v8A' -loader-imagebase '0x0' -readOnly -noanalysis -scriptPath '$terrariaSources' -postScript ApkNativeRangeExport.java '$($terrariaInput.binary_path)' '$terrariaManifest' '$terrariaManifestSHA' '$terrariaSource' '$terrariaOutput'$terrariaExtra -log '$terrariaStatePath.ghidra.log'
exit `$LASTEXITCODE
"@
[IO.File]::WriteAllText($terrariaLauncher,$terrariaCommand,[Text.UTF8Encoding]::new($false))
$terrariaInfo=[Diagnostics.ProcessStartInfo]::new()
$terrariaInfo.FileName=(Get-Process -Id $PID).Path
$terrariaInfo.UseShellExecute=$false;$terrariaInfo.CreateNoWindow=$true
$terrariaInfo.RedirectStandardOutput=$true;$terrariaInfo.RedirectStandardError=$true
foreach($terrariaArg in @('-NoProfile','-File',$terrariaLauncher)){$terrariaInfo.ArgumentList.Add($terrariaArg)}
$terrariaProcess=[Diagnostics.Process]::new();$terrariaProcess.StartInfo=$terrariaInfo
$terrariaState=@{status='starting';library=$Library;attempt=$Attempt;resume=[bool]$Resume;max_new_rows=$MaxRows;manifest_rows=$terrariaEntry[0].rows;manifest_sha256=$terrariaManifestSHA;script_sha256=$SourceSHA;engine_sha256=$terrariaInput.engine_sha256;output=$terrariaOutput;project=$terrariaProject;started_UTC=[DateTime]::UtcNow.ToString('o');external_deadline_seconds=$Seconds;sampled_tree_private_limit_bytes=8589934592;minimum_free_commit_KiB=4194304;peak_tree_private_bytes=0;runner_sha256=(Get-FileHash $PSCommandPath).Hash.ToLower();semantic_equivalence_verified=$false;C_coverage_addition=0}
function Save-TerrariaNativeState { [IO.File]::WriteAllText($terrariaStatePath,($terrariaState | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
$terrariaStarted=$false
try{
    if(-not $terrariaProcess.Start()){throw 'Launch failed'}
    $terrariaStarted=$true;$terrariaState.root_PID=$terrariaProcess.Id;$terrariaState.status='running';Save-TerrariaNativeState
    $terrariaStdout=$terrariaProcess.StandardOutput.ReadToEndAsync();$terrariaStderr=$terrariaProcess.StandardError.ReadToEndAsync()
    $terrariaDeadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    while(-not $terrariaProcess.WaitForExit(1000)){
        $terrariaSnapshot=@(Get-CimInstance Win32_Process)
        $terrariaIds=[Collections.Generic.HashSet[int]]::new();[void]$terrariaIds.Add($terrariaProcess.Id)
        do{$terrariaAdded=$false;foreach($terrariaChild in $terrariaSnapshot){if($terrariaIds.Contains([int]$terrariaChild.ParentProcessId) -and $terrariaChild.CreationDate -ge $terrariaProcess.StartTime -and $terrariaIds.Add([int]$terrariaChild.ProcessId)){$terrariaAdded=$true}}}while($terrariaAdded)
        $terrariaPrivate=[long]0
        foreach($terrariaId in $terrariaIds){try{$terrariaPrivate+=(Get-Process -Id $terrariaId -ErrorAction Stop).PrivateMemorySize64}catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}}
        $terrariaState.current_tree_private_bytes=$terrariaPrivate
        if($terrariaPrivate -gt $terrariaState.peak_tree_private_bytes){$terrariaState.peak_tree_private_bytes=$terrariaPrivate}
        $terrariaMemory=Get-CimInstance Win32_OperatingSystem
        $terrariaStop=$null
        if($terrariaPrivate -gt 8589934592){$terrariaStop='sampled_owned_tree_memory_limit'}
        elseif($terrariaMemory.FreeVirtualMemory -lt 4194304){$terrariaStop='free_commit_below_4GiB'}
        elseif([DateTime]::UtcNow -gt $terrariaDeadline){$terrariaStop='external_deadline'}
        Save-TerrariaNativeState
        if($terrariaStop){$terrariaState.external_stop_reason=$terrariaStop;$terrariaProcess.Kill($true);break}
    }
    $terrariaProcess.WaitForExit()
    $terrariaStdoutText=$terrariaStdout.GetAwaiter().GetResult()
    $terrariaStderrText=$terrariaStderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText("$terrariaStatePath.stdout.log",$terrariaStdoutText)
    [IO.File]::WriteAllText("$terrariaStatePath.stderr.log",$terrariaStderrText)
    $terrariaState.exit_code=$terrariaProcess.ExitCode
    $terrariaState.status=if($terrariaState.external_stop_reason){'externally_stopped'}elseif($terrariaProcess.ExitCode -ne 0){'process_failed'}else{'process_returned_pending_audit'}
    if(($terrariaStdoutText+$terrariaStderrText) -match 'REPORT SCRIPT ERROR:'){$terrariaState.status='script_failed_pending_audit';$terrariaState.script_error_reported=$true}
    if(Test-Path "$terrariaOutput/progress.json"){$terrariaState.producer_progress=Get-Content "$terrariaOutput/progress.json" -Raw | ConvertFrom-Json}
}catch{$terrariaState.status='runner_error';$terrariaState.error=$_.Exception.Message;throw}
finally{
    if($terrariaStarted -and -not $terrariaProcess.HasExited){$terrariaProcess.Kill($true);$terrariaProcess.WaitForExit()}
    $terrariaProcess.Dispose();$terrariaState.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaNativeState
}
$terrariaState | ConvertTo-Json -Depth 8
