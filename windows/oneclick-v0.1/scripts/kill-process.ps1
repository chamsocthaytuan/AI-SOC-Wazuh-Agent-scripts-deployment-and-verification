# Legacy alias for callers of kill-process.ps1: one implementation only.
[CmdletBinding()]
param([Parameter(ValueFromPipeline=$true)][string]$RawInput)
process {
    if (-not $RawInput) { $RawInput = [Console]::In.ReadLine() }
    if ($RawInput) { & (Join-Path $PSScriptRoot 'kill-process-win.ps1') -RawInput $RawInput; if (-not $?) { exit 1 } }
}
