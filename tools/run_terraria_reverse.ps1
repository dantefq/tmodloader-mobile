param(
    [Parameter(Mandatory=$true)][string]$Apk,
    [Parameter(Mandatory=$true)][string]$Lab,
    [string]$Python = 'C:/Private\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',
    [string]$Java = 'C:\Program Files\Java\jdk-21.0.12.1\bin\java.exe',
    [ValidateRange(1,3600)][int]$NativeTimeoutSeconds = 30,
    [ValidateRange(1,1000000)][int]$MaxInstructions = 100000,
    [switch]$SkipNative
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskApk = (Resolve-Path -LiteralPath $Apk).Path
$taskLab = [IO.Path]::GetFullPath($Lab)
if ($taskLab.Equals($taskRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $taskLab.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Game-derived output must stay outside the source repository.'
}
New-Item -ItemType Directory -Force -Path $taskLab | Out-Null
$taskReports = Join-Path $taskRoot 'reports\terraria-re-20261012'
New-Item -ItemType Directory -Force -Path $taskReports | Out-Null

function Invoke-CheckedPython {
    param([string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Analysis step failed: $($Arguments[0])" }
}

Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_android_catalog.py'), '--apk', $taskApk,
    '--private-output', (Join-Path $taskLab 'android'), '--summary', (Join-Path $taskReports 'android-summary.json'),
    '--extract-unity-payload', (Join-Path $taskLab 'assets'))
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_jni_catalog.py'), '--apk', $taskApk,
    '--dex-catalog', (Join-Path $taskLab 'android\classes.dex.json'),
    '--private-output', (Join-Path $taskLab 'android-native'), '--summary', (Join-Path $taskReports 'jni-summary.json'))
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_native_map.py'), $taskApk,
    '--output', (Join-Path $taskLab 'native'), '--report', (Join-Path $taskReports 'native-summary.json'))
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_unwind_ranges.py'),
    '--native', (Join-Path $taskLab 'native'), '--report', (Join-Path $taskReports 'unwind-summary.json'))
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_metadata_catalog.py'), $taskApk,
    '--output', (Join-Path $taskLab 'metadata'), '--summary', (Join-Path $taskReports 'metadata-summary.json'),
    '--native-method-map', (Join-Path $taskLab 'native\method-addresses.json'),
    '--native-type-map', (Join-Path $taskLab 'native\il2cpp-types.json'),
    '--native-type-layouts', (Join-Path $taskLab 'native\type-layouts.json'), '--decode-constants')
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'prepare_terraria_seeds.py'),
    (Join-Path $taskLab 'native\method-addresses.json'), (Join-Path $taskLab 'native\method-seeds.tsv'))
Invoke-CheckedPython @((Join-Path $PSScriptRoot 'prepare_terraria_signatures.py'), '--lab', $taskLab)

$taskNativeFailure = $null
try {
if (-not $SkipNative) {
    $taskEngine = Join-Path $taskRoot '.tools\terraria-re\ghidra\ghidra_12.1.4_PUBLIC'
    $taskUtility = Join-Path $taskEngine 'Ghidra\Framework\Utility\lib\Utility.jar'
    if (-not (Test-Path -LiteralPath $taskUtility)) { throw 'Portable Ghidra is missing; see tools/prepare_terraria_re_tools.py.' }
    foreach ($taskSubdir in @('ghidra-project','ghidra-home','ghidra-appdata','ghidra-tmp')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $taskLab $taskSubdir) | Out-Null
    }
    # Only this child process receives private application configuration paths.
    $taskOldAppData = $env:APPDATA
    $taskOldLocalAppData = $env:LOCALAPPDATA
    try {
        $env:APPDATA = Join-Path $taskLab 'ghidra-appdata'
        $env:LOCALAPPDATA = $env:APPDATA
        $taskProjectName = 'Terraria-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
        & $Java -Xmx6G '-Djava.system.class.loader=ghidra.GhidraClassLoader' `
            "-Duser.home=$(Join-Path $taskLab 'ghidra-home')" "-Djava.io.tmpdir=$(Join-Path $taskLab 'ghidra-tmp')" `
            -cp $taskUtility ghidra.GhidraLauncher ghidra.app.util.headless.AnalyzeHeadless `
            (Join-Path $taskLab 'ghidra-project') $taskProjectName `
            -import (Join-Path $taskLab 'native\libil2cpp.so') -processor 'AARCH64:LE:64:v8A' -loader-imagebase '0x0' -noanalysis `
            -scriptPath $PSScriptRoot -preScript TerrariaSeedMethods.java (Join-Path $taskLab 'native\method-seeds.tsv') `
            -postScript TerrariaDisassembleBodies.java (Join-Path $taskLab 'native\unwind-function-ranges.tsv') (Join-Path $taskLab 'pseudocode') `
            -postScript TerrariaMarkTailCalls.java (Join-Path $taskLab 'native\unwind-function-ranges.tsv') (Join-Path $taskLab 'pseudocode') `
            -postScript TerrariaMarkTerminalCalls.java (Join-Path $taskLab 'native\unwind-function-ranges.tsv') (Join-Path $taskLab 'pseudocode') `
            -postScript TerrariaApplySignatures.java (Join-Path $taskLab 'native\signatures.tsv') (Join-Path $taskLab 'pseudocode') `
            -max-cpu 4 *> (Join-Path $taskReports 'ghidra-prepare.log')
        if ($LASTEXITCODE -ne 0) { throw 'Ghidra preparation failed; inspect ghidra-prepare.log.' }
        # A completed preparation checkpoint survives interrupted exports/retries.
        & $Java -Xmx6G '-Djava.system.class.loader=ghidra.GhidraClassLoader' `
            "-Duser.home=$(Join-Path $taskLab 'ghidra-home')" "-Djava.io.tmpdir=$(Join-Path $taskLab 'ghidra-tmp')" `
            -cp $taskUtility ghidra.GhidraLauncher ghidra.app.util.headless.AnalyzeHeadless `
            (Join-Path $taskLab 'ghidra-project') $taskProjectName -process 'libil2cpp.so' -noanalysis -scriptPath $PSScriptRoot `
            -postScript TerrariaExportMethods.java (Join-Path $taskLab 'native\method-seeds.tsv') (Join-Path $taskLab 'pseudocode') $NativeTimeoutSeconds true $MaxInstructions `
            -max-cpu 4 *> (Join-Path $taskReports 'ghidra-export.log')
        if ($LASTEXITCODE -ne 0) { throw 'Ghidra failed; inspect the private log and per-function coverage.' }
        Invoke-CheckedPython @((Join-Path $PSScriptRoot 'verify_terraria_export.py'), '--lab', $taskLab)
        Invoke-CheckedPython @((Join-Path $PSScriptRoot 'audit_terraria_pseudocode.py'), '--lab', $taskLab)
        Invoke-CheckedPython @((Join-Path $PSScriptRoot 'terraria_callgraph.py'), '--lab', $taskLab)
    } finally {
        $env:APPDATA = $taskOldAppData
        $env:LOCALAPPDATA = $taskOldLocalAppData
    }
}
} catch {
    $taskNativeFailure = $_
    $_.ToString() | Set-Content -LiteralPath (Join-Path $taskLab 'native-export-failure.txt') -Encoding UTF8
} finally {
    # A failed native pass must still expose actual coverage and missing addresses.
    Invoke-CheckedPython @((Join-Path $PSScriptRoot 'build_terraria_explorer.py'), '--lab', $taskLab)
    Invoke-CheckedPython @((Join-Path $PSScriptRoot 'build_terraria_report.py'), '--lab', $taskLab, '--reports', $taskReports)
}
if ($null -ne $taskNativeFailure) { throw $taskNativeFailure }
Write-Output "Private analysis: $taskLab"
