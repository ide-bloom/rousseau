<#
.SYNOPSIS
  Samples CPU and memory of the running Rousseau sensor host (see docs/performance.md).
.PARAMETER Seconds
  Measurement window.
.PARAMETER ProcessId
  Process to sample (default: the oldest rousseau.exe running `run` or `service`).
#>
param(
    [int]$Seconds = 300,
    [int]$ProcessId = 0
)
$ErrorActionPreference = 'Stop'
if ($ProcessId -eq 0) {
    $candidates = Get-CimInstance Win32_Process -Filter "Name = 'rousseau.exe'" |
        Where-Object { $_.CommandLine -match '\s(run|service)(\s|$)' } |
        Sort-Object CreationDate
    if (-not $candidates) { throw 'No rousseau.exe running `run` or `service` found.' }
    $ProcessId = $candidates[0].ProcessId
}
$p = Get-Process -Id $ProcessId
$cores = [Environment]::ProcessorCount
$cpu0 = $p.TotalProcessorTime.TotalMilliseconds
$t0 = Get-Date
$peak = 0
$samples = 0
Write-Host "Sampling pid $ProcessId for $Seconds s on $cores logical processors..."
while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
    Start-Sleep -Milliseconds 250
    $p.Refresh()
    if ($p.WorkingSet64 -gt $peak) { $peak = $p.WorkingSet64 }
    $samples++
}
$p.Refresh()
$wall = ((Get-Date) - $t0).TotalMilliseconds
$cpu = ($p.TotalProcessorTime.TotalMilliseconds - $cpu0) / $wall / $cores * 100
[pscustomobject]@{
    Pid             = $ProcessId
    Seconds         = [math]::Round($wall / 1000)
    Samples         = $samples
    CpuPercent      = [math]::Round($cpu, 2)
    PeakWorkingSetMB = [math]::Round($peak / 1MB, 1)
    PrivateBytesMB  = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
    WithinBudget    = ($cpu -lt 3) -and ($peak -lt 150MB)
} | Format-List
Write-Host 'ETW lost-event counters: run `rousseau doctor`.'
