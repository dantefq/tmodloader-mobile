"""Prepare an explicit fallback gate; preserve unfinished LongBudget results and inputs."""
import datetime
import hashlib
import json
from pathlib import Path

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
    strategy = dict(schema='explicit-baseline-fallback-after-resource-error-v1',
                    recorded_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    reason='Observed Java OutOfMemoryError/native-thread creation failure; no DrawNPC1 result. Compile an unmodified alternative baseline before further heavy analysis.',
                    original_long_budget_plan_complete=False, remaining_C_methods=summary['remaining_methods'],
                    no_timeout_inferred=True, compiler_only=True, engine_execution_allowed=False,
                    inputs=[dict(path=str(p), sha256=sha(p)) for p in evidence], C_coverage_addition=0)
    strategy_path.write_text(json.dumps(strategy, indent=2) + '\n', encoding='utf8')
    strategy_sha = sha(strategy_path)
    text = original.read_text(encoding='utf8')
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
    builder.write_text(text, encoding='utf8', newline='\n')
    provenance = dict(generator_sha256=sha(Path(__file__)), original_builder_sha256=sha(original),
                      derived_builder_sha256=sha(builder), strategy_sha256=strategy_sha,
                      changes=['explicit unfinished-plan fallback gate', 'builder provenance', '4GiB free-commit checks between commands'],
                      native_sources_changed=False, compiler_or_linker_flags_changed=False,
                      compiler_invoked=False, engine_executed=False, C_coverage_addition=0)
    provenance_path.write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf8')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
