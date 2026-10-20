<#
.SYNOPSIS
    Remove a instalacao do SVault (servico, conta de servico e binarios).

.DESCRIPTION
    Execute em uma sessao elevada. Os dados do cofre em C:\ProgramData\SVault sao
    preservados por padrao; use -PurgeData para remove-los tambem.
#>
[CmdletBinding()]
param(
    [string]$ServiceAccount = 'svault_svc',
    [string]$ServiceName = 'SVaultBroker',
    [string]$InstallRoot = 'C:\SVault',
    [string]$DataRoot = 'C:\ProgramData\SVault',
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este script exige uma sessao elevada.'
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    & sc.exe delete $ServiceName | Out-Null
    Write-Host "Servico $ServiceName removido."
}

$user = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
if ($null -ne $user) {
    Remove-LocalUser -Name $ServiceAccount
    Write-Host "Conta $ServiceAccount removida."
}

if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    Write-Host "Binarios em $InstallRoot removidos."
}

if ($PurgeData -and (Test-Path -LiteralPath $DataRoot)) {
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    Write-Host "Dados em $DataRoot removidos."
}
elseif (Test-Path -LiteralPath $DataRoot) {
    Write-Host "Dados preservados em $DataRoot (use -PurgeData para apagar)."
}

Write-Host 'Desinstalacao concluida.'
