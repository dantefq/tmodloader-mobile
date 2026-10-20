param([ValidateSet('kill','drawnpc1','drawnpc2')][string]$Target='kill',[ValidateSet('guard-range-on','portable-branch-long','copy-rule-off')][string]$ProfilePrefix='guard-range-on',[ValidatePattern('^[a-z][a-z0-9-]{0,24}$')][string]$Attempt)
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaRunTarget=if($Attempt){"$Target-$Attempt"}else{$Target}
$terrariaPath="$terrariaLab/$ProfilePrefix-$terrariaRunTarget-20261019.json"
$terrariaData=$null
for($terrariaTry=0;$terrariaTry -lt 5;$terrariaTry++){
    $terrariaStream=[IO.File]::Open($terrariaPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try{$terrariaReader=[IO.StreamReader]::new($terrariaStream);$terrariaText=$terrariaReader.ReadToEnd();$terrariaReader.Dispose()}finally{$terrariaStream.Dispose()}
    try{$terrariaData=$terrariaText | ConvertFrom-Json;break}catch{if($terrariaTry -eq 4){throw};Start-Sleep -Milliseconds 100}
}
$terrariaEngines=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'decompile.exe' -and $_.ExecutablePath -like '*terraria-re-20261012*'})
$terrariaCPU=[double]0
foreach($terrariaEngine in $terrariaEngines){$terrariaCPU+=(Get-Process -Id $terrariaEngine.ProcessId).CPU}
$terrariaTrace=Get-ChildItem $terrariaLab -Filter "$ProfilePrefix-$terrariaRunTarget-20261019.pid*.log"
$terrariaLast=if($terrariaTrace){Get-Content -LiteralPath $terrariaTrace[-1].FullName -Tail 1 | Select-Object -Last 1}else{''}
$terrariaStart=[DateTime]$terrariaData.started_UTC
[pscustomobject]@{status=$terrariaData.status;elapsed_wall_seconds=[math]::Round(([DateTime]::UtcNow-$terrariaStart.ToUniversalTime()).TotalSeconds,1);sampled_private_GiB=[math]::Round($terrariaData.current_tree_private_bytes/1GB,3);peak_private_GiB=[math]::Round($terrariaData.peak_tree_private_bytes/1GB,3);engine_PIDs=@($terrariaEngines.ProcessId);engine_CPU_seconds=[math]::Round($terrariaCPU,1);last_trace_record=$terrariaLast} | ConvertTo-Json -Depth 4
