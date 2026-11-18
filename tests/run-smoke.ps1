<#
.SYNOPSIS
    Compila os binarios Rust e executa os testes unitarios, de fumaca do broker e do servidor MCP.

.DESCRIPTION
    O teste sobe um broker em modo console (sem elevacao, sem servico) com um diretorio
    temporario, sobe um servidor HTTP local que ecoa o corpo recebido e valida:
      - o ciclo completo de cadastro, autorizacao, solicitacao e aprovacao
      - a ausencia do valor do segredo em qualquer resposta, log ou estado
      - a recusa de senha incorreta, alvo nao autorizado e segredo literal em template
      - a exigencia do segundo fator TOTP quando habilitada
      - o servidor MCP nativo (svault-mcp.exe) via JSON-RPC sobre stdio
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$CargoToolchain = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $root 'artifacts\broker'

if (-not $CargoToolchain) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $hasVc = [bool]$env:VCToolsInstallDir
    if (-not $hasVc -and (Test-Path -LiteralPath $vswhere)) {
        $vcInstall = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vcInstall) { $hasVc = $true }
    }

    if (-not $hasVc) {
        $CargoToolchain = 'stable-x86_64-pc-windows-gnu'
    }
}

if ($CargoToolchain -match 'gnu' -and (Test-Path -LiteralPath 'C:\msys64\mingw64\bin')) {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
}

$profileDir = if ($Configuration -ieq 'Debug') { 'debug' } else { 'release' }

$buildArgs = @(
    'build',
    '--manifest-path', (Join-Path $root 'Cargo.toml'),
    '-p', 'svault-broker',
    '-p', 'svault-mcp',
    '-p', 'svault-cli',
    '-p', 'svault-smoke'
)
if ($Configuration -ine 'Debug') {
    $buildArgs += '--release'
}
if ($CargoToolchain) {
    $buildArgs = @("+$CargoToolchain") + $buildArgs
}

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & cargo @buildArgs 2>&1 | ForEach-Object { Write-Host "$_" } }
finally { $ErrorActionPreference = $previousPreference }
if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar os binarios Rust do SVault.' }

$binDir = Join-Path $root "target\$profileDir"
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $binDir 'svault-broker.exe') -Destination (Join-Path $artifacts 'svault-broker.exe') -Force
Copy-Item -LiteralPath (Join-Path $binDir 'svault-mcp.exe') -Destination (Join-Path $artifacts 'svault-mcp.exe') -Force
Copy-Item -LiteralPath (Join-Path $binDir 'svaultctl.exe') -Destination (Join-Path $artifacts 'svaultctl.exe') -Force

& (Join-Path $binDir 'svault-smoke.exe') (Join-Path $artifacts 'svault-broker.exe') (Join-Path $artifacts 'svault-mcp.exe')
exit $LASTEXITCODE
