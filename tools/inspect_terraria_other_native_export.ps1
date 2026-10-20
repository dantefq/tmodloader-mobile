param([Parameter(Mandatory)][ValidateSet('libmain.so','libGNS_Wrapper.so','libunity.so','libexternal_wrapper.so','libc++_shared.so','libpairipcore.so','libpdaprotect.so')][string]$Library,[ValidatePattern('^[a-z][a-z0-9-]{0,24}$')][string]$Attempt='sample-v3')
$ErrorActionPreference='Stop'
$terrariaLab='C:/Temp/terraria-re-20261012'
$terrariaSafe=$Library.Replace('.so','').Replace('+','p')
$terrariaFile=Get-ChildItem $terrariaLab -Filter "other-native-export-$terrariaSafe-$Attempt-*.json" | Where-Object Name -notlike '*.controlled-stop.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $terrariaFile){throw 'No matching run state'}
function Read-TerrariaSharedJSON([string]$Path){
    for($terrariaTry=0;$terrariaTry -lt 5;$terrariaTry++){
        $terrariaStream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try{$terrariaReader=[IO.StreamReader]::new($terrariaStream);$terrariaText=$terrariaReader.ReadToEnd();$terrariaReader.Dispose()}finally{$terrariaStream.Dispose()}
        try{return ($terrariaText | ConvertFrom-Json)}catch{if($terrariaTry -eq 4){throw};Start-Sleep -Milliseconds 100}
    }
}
$terrariaState=Read-TerrariaSharedJSON $terrariaFile.FullName
$terrariaProgressPath="$($terrariaState.output)/progress.json"
$terrariaProgress=if(Test-Path $terrariaProgressPath){Read-TerrariaSharedJSON $terrariaProgressPath}else{$null}
$terrariaProcesses=@(Get-CimInstance Win32_Process)
$terrariaIDs=[Collections.Generic.HashSet[int]]::new();[void]$terrariaIDs.Add([int]$terrariaState.root_PID)
$terrariaStart=([DateTime]$terrariaState.started_UTC).ToUniversalTime()
do{$terrariaAdded=$false;foreach($terrariaChild in $terrariaProcesses){if($terrariaIDs.Contains([int]$terrariaChild.ParentProcessId) -and $terrariaChild.CreationDate.ToUniversalTime() -ge $terrariaStart -and $terrariaIDs.Add([int]$terrariaChild.ProcessId)){$terrariaAdded=$true}}}while($terrariaAdded)
$terrariaOwned=@($terrariaProcesses | Where-Object {$terrariaIDs.Contains([int]$_.ProcessId) -and $_.CreationDate.ToUniversalTime() -ge $terrariaStart})
$terrariaCPU=[double]0
foreach($terrariaChild in $terrariaOwned){try{$terrariaCPU+=(Get-Process -Id $terrariaChild.ProcessId -ErrorAction Stop).CPU}catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}}
[pscustomobject]@{state_path=$terrariaFile.FullName;status=$terrariaState.status;owned_process_count=$terrariaOwned.Count;elapsed_wall_seconds=[math]::Round(([DateTime]::UtcNow-$terrariaStart).TotalSeconds,1);CPU_seconds=[math]::Round($terrariaCPU,1);sampled_private_GiB=[math]::Round($terrariaState.current_tree_private_bytes/1GB,3);peak_private_GiB=[math]::Round($terrariaState.peak_tree_private_bytes/1GB,3);producer_progress=$terrariaProgress;counts_independently_audited=$false} | ConvertTo-Json -Depth 5
