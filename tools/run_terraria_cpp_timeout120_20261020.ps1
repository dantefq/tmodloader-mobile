# Reviewed selection: 7 exports; full preparation/source-byte universe: 2,275 rows.
# Prepared supervisor only. Native execution occurs only when explicitly invoked.
# all_selected_rows_attempted is NOT all_rows_attempted and is NOT C success.
param([switch]$Resume)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){throw 'PowerShell 7 required'}
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaPrivate="$terrariaLab/other-native-cpp-timeout120-20261020"
$terrariaProfile='apk-native-bounded-range-C-v4-cpp-timeout120-selected7'
$terrariaSourceSHA='8f24ea06bd542078f5184da3a1158b7a9f3ccd159a75b3eda88e5103700e2b6b'
$terrariaManifestSHA='83a27b656288583f80a872456dac6a49ee4560a92752fd50900725f9db2bd953'
$terrariaAuditorSHA='2596fd0136bead3a579b33d854fccc17fe4dda057afa63b362c25ac03426f35d'
$terrariaEngineSHA='d64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
$terrariaElfSHA='218ecc677aa79e1974f3968d2e0ecd0172c4f517188d04ebd7d45cbb285b5d03'
$terrariaSelected=@('0xa3f28','0xb25c0','0xc3238','0xc3920','0xc3d08','0xc3e34','0xc421c')
function Assert-TerrariaHash([string]$Path,[string]$SHA){
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() -ne $SHA){throw "Pinned input changed: $Path"}
}
function Test-TerrariaSamePath([string]$Left,[string]$Right){return [IO.Path]::GetFullPath($Left) -eq [IO.Path]::GetFullPath($Right)}
Assert-TerrariaHash "$terrariaPrivate/invocation.json" '1098630a509b712d92188debb5028d852c1c63dc6bed3b1b577e6a7ab666623c'
$terrariaInvocation=Get-Content -LiteralPath "$terrariaPrivate/invocation.json" -Raw | ConvertFrom-Json
$terrariaSource="$terrariaPrivate/sources/ApkNativeRangeExport.java"
$terrariaSources="$terrariaPrivate/sources"
$terrariaManifest="$terrariaPrivate/libc++_shared.so.manifest.json"
$terrariaOutput="$terrariaPrivate/output"
$terrariaAuditor="$terrariaPrivate/sources/tools/profile/audit_cpp_timeout120.py"
if(-not (Test-TerrariaSamePath $terrariaInvocation.script_directory $terrariaSources) -or $terrariaInvocation.script_name -ne 'ApkNativeRangeExport.java') {throw 'Invocation source identity differs'}
$terrariaExpectedPost=@($terrariaInvocation.post_script_arguments)
if($terrariaExpectedPost.Count -ne 5 -or -not (Test-TerrariaSamePath $terrariaExpectedPost[1] $terrariaManifest) -or $terrariaExpectedPost[2] -ne $terrariaManifestSHA -or -not (Test-TerrariaSamePath $terrariaExpectedPost[3] $terrariaSource) -or -not (Test-TerrariaSamePath $terrariaExpectedPost[4] $terrariaOutput)){throw 'Invocation argument identity differs'}
Assert-TerrariaHash $terrariaSource $terrariaSourceSHA
Assert-TerrariaHash $terrariaManifest $terrariaManifestSHA
Assert-TerrariaHash $terrariaAuditor $terrariaAuditorSHA
Assert-TerrariaHash "$terrariaSources/tools/prove_apk_stackchk_imports.py" '1b261576562c6b0b4452046f6cbb8982d2221cd82d3c6f3662a980190ff6dd33'
Assert-TerrariaHash "$terrariaSources/tools/prove_libmain_stackchk_import.py" 'b3fc8f7a171a177f97cf7b8be5d1514e312daf8d9661a32851bd800e2edffd3a'
$terrariaInput=Get-Content -LiteralPath $terrariaManifest -Raw | ConvertFrom-Json
if($terrariaInput.profile -ne $terrariaProfile -or @($terrariaInput.rows).Count -ne 2275 -or ($terrariaInput.export_addresses -join ',') -ne ($terrariaSelected -join ',') -or $terrariaInput.limits.timeout_seconds -ne 120 -or $terrariaInput.limits.max_instructions -ne 100000 -or $terrariaInput.limits.max_payload_mb -ne 64){throw 'Reviewed profile/selection/universe/limits differ'}
Assert-TerrariaHash $terrariaInput.baseline_manifest_file 'fb6e63a17459d06cc00cbb5835e00268e2e4ae78825b47c0faedda35c8551f10'
Assert-TerrariaHash $terrariaInput.noreturn_import_proof_file $terrariaInput.noreturn_import_proof_sha256
Assert-TerrariaHash $terrariaInput.binary_path $terrariaElfSHA
if(-not (Test-TerrariaSamePath $terrariaInput.binary_path $terrariaExpectedPost[0]) -or $terrariaInput.elf_sha256 -ne $terrariaElfSHA -or $terrariaInput.engine_sha256 -ne $terrariaEngineSHA){throw 'Original ELF/engine identity differs'}
$terrariaScope=Get-Content -LiteralPath "$PSScriptRoot/terraria_apk_scope_preferences.json" -Raw | ConvertFrom-Json
if('libc++_shared.so' -in $terrariaScope.excluded_native_libraries){throw 'Library excluded by user'}
$terrariaRuntime="$terrariaLab/ghidra-guard-range-20261019"
$terrariaEngine="$terrariaRuntime/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe"
Assert-TerrariaHash $terrariaEngine $terrariaEngineSHA
if((Test-Path -LiteralPath $terrariaOutput) -ne [bool]$Resume){throw 'Fresh output required; explicit -Resume required for an existing output'}
if($Resume -and ((Get-Item -LiteralPath $terrariaOutput).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Resume output redirects through junction/symlink'}
# Producer rechecks all run/journal identities and original boundaries before a resume.
function Assert-TerrariaEngineIdle {
    if(@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'decompile.exe' -or ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'terraria-re-20261012')}).Count){throw 'Another analysis engine is active'}
}
Assert-TerrariaEngineIdle
if((Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory -lt 4194304){throw 'Free commit below 4 GiB before launch'}
$terrariaRunID=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')
$terrariaStatePath="$terrariaPrivate/supervisor-$terrariaRunID.json"
$terrariaProject="$terrariaPrivate/project-$terrariaRunID"
$terrariaLauncher="$terrariaPrivate/launcher-$terrariaRunID.ps1"
$terrariaAuditPath="$terrariaPrivate/audit-$terrariaRunID.json"
$terrariaExtra=if($Resume){' resume'}else{''}
$terrariaCommand=@"
`$ErrorActionPreference='Stop'
`$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12.1'
`$env:APPDATA='$terrariaLab/ghidra-appdata-other-native-20261019'
`$env:TERRARIA_DECOMP_TRACE_FILE=`$null
& '$terrariaRuntime/support/analyzeHeadless.bat' '$terrariaProject' ApkNative -import '$($terrariaInput.binary_path)' -processor 'AARCH64:LE:64:v8A' -loader-imagebase '0x0' -readOnly -noanalysis -scriptPath '$terrariaSources' -postScript ApkNativeRangeExport.java '$($terrariaInput.binary_path)' '$terrariaManifest' '$terrariaManifestSHA' '$terrariaSource' '$terrariaOutput'$terrariaExtra -log '$terrariaStatePath.ghidra.log'
exit `$LASTEXITCODE
"@
$terrariaInfo=[Diagnostics.ProcessStartInfo]::new()
$terrariaInfo.FileName=(Get-Process -Id $PID).Path
$terrariaInfo.UseShellExecute=$false;$terrariaInfo.CreateNoWindow=$true
$terrariaInfo.RedirectStandardOutput=$true;$terrariaInfo.RedirectStandardError=$true
foreach($terrariaArg in @('-NoProfile','-File',$terrariaLauncher)){$terrariaInfo.ArgumentList.Add($terrariaArg)}
$terrariaProcess=[Diagnostics.Process]::new();$terrariaProcess.StartInfo=$terrariaInfo
$terrariaState=@{status='starting';library='libc++_shared.so';profile=$terrariaProfile;resume=[bool]$Resume;reviewed_selected_exports=7;full_boundary_universe_rows=2275;export_addresses=$terrariaSelected;manifest_sha256=$terrariaManifestSHA;script_sha256=$terrariaSourceSHA;auditor_sha256=$terrariaAuditorSHA;engine_sha256=$terrariaEngineSHA;ELF_sha256=$terrariaElfSHA;output=$terrariaOutput;project=$terrariaProject;audit_output=$terrariaAuditPath;started_UTC=[DateTime]::UtcNow.ToString('o');external_deadline_seconds=1800;per_selected_function_timeout_seconds=120;sampled_tree_private_limit_bytes=8589934592;minimum_free_commit_KiB=4194304;peak_tree_private_bytes=0;runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower();semantic_equivalence_verified=$false;original_source_recovered=$false;C_coverage_addition=0}
function Save-TerrariaCppState { [IO.File]::WriteAllText($terrariaStatePath,($terrariaState | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false)) }
$terrariaStarted=$false;$terrariaReturned=$false;$terrariaLock=$null
try{
    # Serializes this supervisor; the root must retain its broader serial queue.
    $terrariaLock=[IO.File]::Open("$terrariaPrivate/supervisor.lock",[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    Assert-TerrariaEngineIdle
    New-Item -ItemType Directory -Path $terrariaProject -ErrorAction Stop | Out-Null
    [IO.File]::WriteAllText($terrariaLauncher,$terrariaCommand,[Text.UTF8Encoding]::new($false))
    if(-not $terrariaProcess.Start()){throw 'Launch failed'}
    $terrariaStarted=$true;$terrariaState.root_PID=$terrariaProcess.Id;$terrariaState.root_started_local=$terrariaProcess.StartTime.ToString('o');$terrariaState.status='running';Save-TerrariaCppState
    $terrariaStdout=$terrariaProcess.StandardOutput.ReadToEndAsync();$terrariaStderr=$terrariaProcess.StandardError.ReadToEndAsync()
    $terrariaDeadline=[DateTime]::UtcNow.AddSeconds(1800)
    while(-not $terrariaProcess.WaitForExit(1000)){
        $terrariaSnapshot=@(Get-CimInstance Win32_Process)
        $terrariaIds=[Collections.Generic.HashSet[int]]::new();[void]$terrariaIds.Add($terrariaProcess.Id)
        do{$terrariaAdded=$false;foreach($terrariaChild in $terrariaSnapshot){if($terrariaIds.Contains([int]$terrariaChild.ParentProcessId) -and $terrariaChild.CreationDate -ge $terrariaProcess.StartTime -and $terrariaIds.Add([int]$terrariaChild.ProcessId)){$terrariaAdded=$true}}}while($terrariaAdded)
        $terrariaPrivateBytes=[long]0
        foreach($terrariaId in $terrariaIds){try{$terrariaPrivateBytes+=(Get-Process -Id $terrariaId -ErrorAction Stop).PrivateMemorySize64}catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}}
        $terrariaState.current_tree_private_bytes=$terrariaPrivateBytes;$terrariaState.sampled_UTC=[DateTime]::UtcNow.ToString('o')
        if($terrariaPrivateBytes -gt $terrariaState.peak_tree_private_bytes){$terrariaState.peak_tree_private_bytes=$terrariaPrivateBytes}
        $terrariaMemory=Get-CimInstance Win32_OperatingSystem
        $terrariaStop=$null
        if($terrariaPrivateBytes -gt 8589934592){$terrariaStop='sampled_owned_tree_memory_limit'}
        elseif($terrariaMemory.FreeVirtualMemory -lt 4194304){$terrariaStop='free_commit_below_4GiB'}
        elseif([DateTime]::UtcNow -gt $terrariaDeadline){$terrariaStop='external_deadline'}
        Save-TerrariaCppState
        if($terrariaStop){$terrariaState.external_stop_reason=$terrariaStop;$terrariaProcess.Kill($true);break}
    }
    $terrariaProcess.WaitForExit();$terrariaReturned=$true
    $terrariaStdoutText=$terrariaStdout.GetAwaiter().GetResult();$terrariaStderrText=$terrariaStderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText("$terrariaStatePath.stdout.log",$terrariaStdoutText)
    [IO.File]::WriteAllText("$terrariaStatePath.stderr.log",$terrariaStderrText)
    $terrariaState.exit_code=$terrariaProcess.ExitCode
    $terrariaGhidraText=if(Test-Path -LiteralPath "$terrariaStatePath.ghidra.log"){Get-Content -LiteralPath "$terrariaStatePath.ghidra.log" -Raw}else{''}
    $terrariaState.script_error_reported=($terrariaStdoutText+$terrariaStderrText+$terrariaGhidraText) -match 'REPORT SCRIPT ERROR:'
    $terrariaState.status=if($terrariaState.external_stop_reason){'externally_stopped'}elseif($terrariaProcess.ExitCode -ne 0){'process_failed_pending_audit'}elseif($terrariaState.script_error_reported){'script_failed_pending_audit'}else{'process_returned_pending_audit'}
    Save-TerrariaCppState
    # Fresh per-invocation audit; failed/partial runs cannot be promoted by exit code alone.
    Assert-TerrariaHash $terrariaAuditor $terrariaAuditorSHA
    $terrariaAuditArgs=@('--elf',$terrariaInput.binary_path,'--manifest',$terrariaManifest,'--manifest-sha256',$terrariaManifestSHA,'--producer',$terrariaSource,'--producer-sha256',$terrariaSourceSHA,'--engine',$terrariaEngine,'--output-dir',$terrariaOutput,'--audit-output',$terrariaAuditPath)
    $terrariaAuditText=& $terrariaInvocation.audit_python $terrariaAuditor @terrariaAuditArgs 2>&1
    $terrariaAuditExit=$LASTEXITCODE
    [IO.File]::WriteAllText("$terrariaStatePath.audit.log",($terrariaAuditText -join [Environment]::NewLine))
    $terrariaState.audit_exit_code=$terrariaAuditExit
    if($terrariaAuditExit -ne 0 -or -not (Test-Path -LiteralPath $terrariaAuditPath)){$terrariaState.status='audit_failed';throw 'Independent persisted-result audit failed; original artifacts preserved'}
    $terrariaAudit=Get-Content -LiteralPath $terrariaAuditPath -Raw | ConvertFrom-Json
    $terrariaState.audit_sha256=(Get-FileHash -LiteralPath $terrariaAuditPath).Hash.ToLower()
    $terrariaState.audited_attempted_selected_rows=$terrariaAudit.attempted_rows
    $terrariaState.audited_status_counts=$terrariaAudit.status_counts
    $terrariaState.all_selected_rows_attempted=$terrariaAudit.all_selected_rows_attempted
    if($terrariaAudit.integrity_passed -ne $true -or $terrariaAudit.preflight_only -ne $false -or $terrariaAudit.producer_sha256 -ne $terrariaSourceSHA -or $terrariaAudit.auditor_sha256 -ne $terrariaAuditorSHA -or $terrariaAudit.manifest_sha256 -ne $terrariaManifestSHA -or $terrariaAudit.total_manifest_rows -ne 2275 -or $terrariaAudit.selected_export_rows -ne 7 -or $terrariaAudit.attempted_rows -ne 7 -or $terrariaAudit.all_selected_rows_attempted -ne $true -or $terrariaAudit.all_rows_attempted -ne $false -or ($terrariaAudit.export_addresses -join ',') -ne ($terrariaSelected -join ',')){$terrariaState.status='selected_attempts_incomplete_or_identity_mismatch';throw 'All seven selected attempts and full 2275-row preparation universe must pass audit'}
    if($terrariaAudit.import_restoration_record_present -ne $true -or $terrariaAudit.preparation_ready_count -ne 2275 -or $terrariaAudit.preparation_conflict_count -ne 0){$terrariaState.status='selected_attempts_incomplete_or_identity_mismatch';throw 'All boundaries must prepare cleanly and the conditional import restoration record must be present'}
    if($terrariaState.external_stop_reason -or $terrariaProcess.ExitCode -ne 0 -or $terrariaState.script_error_reported){$terrariaState.status='audited_artifacts_with_process_failure';throw 'Artifacts audited but process lifecycle did not return cleanly'}
    $terrariaState.status='all_selected_attempts_audited'
}catch{
    if($terrariaState.status -notin @('audit_failed','selected_attempts_incomplete_or_identity_mismatch','audited_artifacts_with_process_failure')){$terrariaState.status='runner_error'}
    $terrariaState.error=$_.Exception.Message
    throw
}finally{
    if($terrariaStarted -and -not $terrariaProcess.HasExited){$terrariaProcess.Kill($true);$terrariaProcess.WaitForExit();$terrariaState.cleanup_terminated_owned_tree=$true}
    $terrariaState.process_return_observed=$terrariaReturned
    $terrariaProcess.Dispose();if($null -ne $terrariaLock){$terrariaLock.Dispose()}
    $terrariaState.ended_UTC=[DateTime]::UtcNow.ToString('o');Save-TerrariaCppState
}
$terrariaState | ConvertTo-Json -Depth 12
