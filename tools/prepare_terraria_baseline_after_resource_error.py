"""Prepare an explicit fallback gate; preserve unfinished LongBudget results and inputs."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil

LAB = Path('C:/Temp/terraria-re-20261012')
BASE = LAB / 'portable-decompiler-baseline-prep-20261017'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Source anchor not unique: ' + old[:80])
    return text.replace(old, new, 1)


def main():
    manifest_path = BASE / 'preparation-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    original = BASE / 'build-baseline.ps1'
    if sha(original) != manifest['builder_sha256'] or (BASE / 'baseline-build').exists():
        raise ValueError('Original builder changed or a build already exists')
    interruption = LAB / 'interrupted-long-budget-drawnpc1-resource-error-20261018/interruption.json'
    error = json.loads(interruption.read_text(encoding='utf-8-sig'))
    if error['status'] != 'interrupted_without_result' or not error['observed_errors']:
        raise ValueError('Observed resource-error checkpoint required')
    summary_path = Path(manifest['long_budget_summary'])
    summary = json.loads(summary_path.read_text(encoding='utf-8-sig'))
    if summary['finished_planned_attempts'] or summary['remaining_hard_methods_without_C'] != 3:
        raise ValueError('Unexpected prior checkpoint; re-inspect strategy')
    evidence = [manifest_path, original, interruption, summary_path, Path(manifest['long_budget_plan'])]
    for name in ('long-budget-queue-resume-20261018.stdout.log', 'long-budget-queue-resume-20261018.stderr.log'):
        evidence.append(interruption.parent / name)
    strategy_path = BASE / 'resource-error-baseline-strategy.json'
    builder = BASE / 'build-baseline-after-resource-error.ps1'
    provenance_path = BASE / 'resource-error-baseline-build-provenance.json'
    if any(p.exists() for p in (strategy_path, builder, provenance_path)):
        raise FileExistsError('Preserve existing fallback preparation')
    snapshot = BASE / 'resource-error-strategy-inputs'
    snapshot.mkdir()
    frozen = []
    for index, path in enumerate(evidence):
        target = snapshot / (str(index) + '-' + path.name)
        shutil.copyfile(path, target)
        if sha(target) != sha(path):
            raise ValueError('Evidence changed during snapshot')
        frozen.append(dict(path=str(target), original_path=str(path), sha256=sha(target)))
    strategy = dict(schema='explicit-baseline-fallback-after-resource-error-v2',
                    recorded_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    reason='Observed Java OutOfMemoryError/native-thread creation failure; no DrawNPC1 result. Compile an unmodified alternative baseline before further heavy analysis.',
                    original_long_budget_plan_complete=False, remaining_C_methods=summary['remaining_methods'],
                    no_timeout_inferred=True, compiler_only=True, engine_execution_allowed=False,
                    inputs=frozen, C_coverage_addition=0)
    strategy_path.write_text(json.dumps(strategy, indent=2) + '\n', encoding='utf8')
    strategy_sha = sha(strategy_path)
    text = original.read_text(encoding='utf8')
    text = once(text, "$ErrorActionPreference='Stop'", "$ErrorActionPreference='Stop'\nif($PSVersionTable.PSVersion.Major -lt 7){throw 'PowerShell 7 required for ArgumentList and process-tree termination'}")
    text = once(text, "if ((Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower() -ne $diagManifest.builder_sha256) { throw 'Builder source changed' }",
                "$diagDerived=Get-Content -LiteralPath (Join-Path $diagRoot 'resource-error-baseline-build-provenance.json') -Raw | ConvertFrom-Json\n"
                "if ((Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower() -ne $diagDerived.derived_builder_sha256) { throw 'Derived builder changed' }\n"
                "if ((Get-FileHash -LiteralPath (Join-Path $diagRoot 'build-baseline.ps1')).Hash.ToLower() -ne $diagManifest.builder_sha256) { throw 'Original builder changed' }")
    start = text.index('function Assert-DiagLongBudgetComplete {')
    end = text.index('function Assert-DiagFiles(', start)
    gate = '''function Assert-DiagLongBudgetComplete {
    $diagStrategyPath=Join-Path $diagRoot 'resource-error-baseline-strategy.json'
    if((Get-FileHash -LiteralPath $diagStrategyPath).Hash.ToLower() -ne 'STRATEGY_SHA'){throw 'Strategy changed'}
    $diagStrategy=Get-Content -LiteralPath $diagStrategyPath -Raw | ConvertFrom-Json
    if($diagStrategy.original_long_budget_plan_complete -ne $false -or $diagStrategy.compiler_only -ne $true -or $diagStrategy.engine_execution_allowed -ne $false){throw 'Unexpected strategy scope'}
    foreach($diagInput in $diagStrategy.inputs){
        if((Get-FileHash -LiteralPath $diagInput.path).Hash.ToLower() -ne $diagInput.sha256){throw 'Strategy evidence changed'}
    }
}
'''.replace('STRATEGY_SHA', strategy_sha)
    text = text[:start] + gate + text[end:]
    text = once(text, "    if ($diagProcesses.Count) { throw 'Analysis engine is active; preserve partial build and stop' }",
                "    if ($diagProcesses.Count) { throw 'Analysis engine is active; preserve partial build and stop' }\n"
                "    $diagMemory=Get-CimInstance Win32_OperatingSystem\n"
                "    if($diagMemory.FreeVirtualMemory -lt 4194304){throw 'Less than 4GiB commit headroom; preserve build and stop'}")
    text = once(text, "$diagRecord=@{status='building';", "$diagRecord=@{status='building';execution_strategy_sha256='" + strategy_sha + "';derived_builder_sha256=$diagDerived.derived_builder_sha256;")
    atomic = '''function Save-DiagRecord {
    $diagTemp=$diagRecordPath+'.tmp'
    [IO.File]::WriteAllText($diagTemp,($diagRecord | ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
    for($diagRetry=0;$diagRetry -lt 40;$diagRetry++){
        try {[IO.File]::Move($diagTemp,$diagRecordPath,$true);return}
        catch [IO.IOException] {if($diagRetry -eq 39){throw};Start-Sleep -Milliseconds 100}
    }
}'''
    text = once(text, 'function Save-DiagRecord { $diagRecord | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $diagRecordPath -Encoding utf8 }', atomic)
    native = '''function Invoke-DiagCompiler([string[]]$diagArgv,[string]$diagLog) {
    $diagRecord.active_native_command=@{argv=$diagArgv;log=$diagLog;sampled_tree_private_byte_limit=4294967296;peak_tree_private_bytes=0}
    Save-DiagRecord
    $diagInfo=[Diagnostics.ProcessStartInfo]::new()
    $diagInfo.FileName=$diagCxx
    $diagInfo.UseShellExecute=$false
    $diagInfo.CreateNoWindow=$true
    $diagInfo.RedirectStandardOutput=$true
    $diagInfo.RedirectStandardError=$true
    foreach($diagArg in $diagArgv){$diagInfo.ArgumentList.Add($diagArg)}
    $diagProcess=[Diagnostics.Process]::new()
    $diagProcess.StartInfo=$diagInfo
    $diagStarted=$false
    $diagStop=$null
    try {
        if(-not $diagProcess.Start()){throw 'Compiler process did not start'}
        $diagStarted=$true
        $diagOut=$diagProcess.StandardOutput.ReadToEndAsync()
        $diagErr=$diagProcess.StandardError.ReadToEndAsync()
        while(-not $diagProcess.WaitForExit(500)){
            $diagProcess.Refresh()
            $diagMemory=Get-CimInstance Win32_OperatingSystem
            $diagSnapshot=@(Get-CimInstance Win32_Process)
            $diagIds=[Collections.Generic.HashSet[int]]::new()
            [void]$diagIds.Add($diagProcess.Id)
            do {
                $diagAdded=$false
                foreach($diagChild in $diagSnapshot){
                    if($diagIds.Contains([int]$diagChild.ParentProcessId) -and $diagChild.CreationDate -ge $diagProcess.StartTime -and $diagIds.Add([int]$diagChild.ProcessId)){$diagAdded=$true}
                }
            }while($diagAdded)
            $diagTreePrivate=[long]0
            foreach($diagId in $diagIds){
                try {$diagOwned=Get-Process -Id $diagId -ErrorAction Stop; $diagTreePrivate+=$diagOwned.PrivateMemorySize64}
                catch [Microsoft.PowerShell.Commands.ProcessCommandException] {}
            }
            if($diagTreePrivate -gt $diagRecord.active_native_command.peak_tree_private_bytes){$diagRecord.active_native_command.peak_tree_private_bytes=$diagTreePrivate}
            if($diagTreePrivate -gt 4294967296){$diagStop='Compiler process-tree private memory exceeded 4GiB'}
            elseif($diagMemory.FreeVirtualMemory -lt 4194304){$diagStop='Less than 4GiB free commit headroom'}
            elseif([DateTime]::UtcNow -gt $diagDeadline){$diagStop='Compiler deadline exceeded'}
            if($diagStop){$diagProcess.Kill($true);break}
        }
        $diagProcess.WaitForExit()
        $diagStdout=$diagOut.GetAwaiter().GetResult()
        $diagStderr=$diagErr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($diagLog,$diagStdout+$diagStderr,[Text.UTF8Encoding]::new($false))
        $script:LASTEXITCODE=$diagProcess.ExitCode
        $diagRecord.active_native_command.exit_code=$diagProcess.ExitCode
        $diagRecord.active_native_command.stop_reason=$diagStop
        Save-DiagRecord
        if($diagStop){throw $diagStop}
    } finally {
        if($diagStarted -and -not $diagProcess.HasExited){$diagProcess.Kill($true);$diagProcess.WaitForExit()}
        $diagProcess.Dispose()
    }
}
'''
    text = once(text, '    foreach($diagName in $diagSources){', '    foreach($diagName in $diagSources){')
    text = once(text, 'Save-DiagRecord\ntry {', native + 'Save-DiagRecord\ntry {')
    text = once(text, "    & $diagCxx '--version' *> $diagVersionLog", "    Invoke-DiagCompiler @('--version') $diagVersionLog")
    text = once(text, "    & $diagCxx '-dumpmachine' *> $diagTargetLog", "    Invoke-DiagCompiler @('-dumpmachine') $diagTargetLog")
    text = once(text, '        & $diagCxx @diagArgs *> $diagLog', '        Invoke-DiagCompiler $diagArgs $diagLog')
    text = once(text, "    & $diagCxx @diagLink *> (Join-Path $diagBuild 'link.log')", "    Invoke-DiagCompiler $diagLink (Join-Path $diagBuild 'link.log')")
    builder.write_text(text, encoding='utf8', newline='\n')
    provenance = dict(generator_sha256=sha(Path(__file__)), original_builder_sha256=sha(original),
                      derived_builder_sha256=sha(builder), strategy_sha256=strategy_sha,
                      changes=['explicit unfinished-plan fallback gate with frozen snapshots', 'builder provenance', 'sampled compiler-tree supervision: 4GiB private threshold/free-commit floor; finite deadline; PowerShell7', 'atomic state replacement with transient-lock retries'],
                      native_sources_changed=False, compiler_or_linker_flags_changed=False,
                      compiler_invoked=False, engine_executed=False, C_coverage_addition=0)
    provenance_path.write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf8')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
