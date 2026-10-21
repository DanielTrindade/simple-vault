[CmdletBinding()]
param([Parameter(Mandatory)] [string]$LogPath)

$ErrorActionPreference = 'Stop'
$exitCode = 0
Start-Transcript -LiteralPath $LogPath -Force | Out-Null
try {
    & (Join-Path $PSScriptRoot 'Install-SVault.ps1') -SkipBuild
}
catch {
    Write-Output $_.Exception.Message
    Write-Output $_.InvocationInfo.PositionMessage
    $exitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit $exitCode
