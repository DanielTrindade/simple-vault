[CmdletBinding()]
param(
    [string]$CargoToolchain = '',
    [string]$CargoTarget = '',
    [string]$ReleaseTag = '',
    [string]$IsccPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$manifest = [IO.File]::ReadAllText((Join-Path $repo 'src\svault-manager\Cargo.toml'))
$versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$')
if (-not $versionMatch.Success) { throw 'A versao do SVault precisa seguir X.Y.Z.' }
$version = $versionMatch.Groups[1].Value
if ($ReleaseTag -and $ReleaseTag -cne "v$version") { throw "Tag $ReleaseTag diverge da versao v$version do SVault." }

if (-not (Test-Path -LiteralPath $IsccPath)) { throw 'Instale o Inno Setup 6 ou informe -IsccPath.' }

$publish = Join-Path $repo 'artifacts\publish'
if (Test-Path -LiteralPath $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }

if ($CargoToolchain -match 'gnu' -and (Test-Path -LiteralPath 'C:\msys64\mingw64\bin')) {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
}

$cargoArgs = @(
    'build', '--release', '--locked',
    '--manifest-path', (Join-Path $repo 'Cargo.toml'),
    '-p', 'svault-broker',
    '-p', 'svault-cli',
    '-p', 'svault-mcp',
    '-p', 'svault-manager'
)
if ($CargoTarget) { $cargoArgs += @('--target', $CargoTarget) }
if ($CargoToolchain) { $cargoArgs = @("+$CargoToolchain") + $cargoArgs }

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & cargo @cargoArgs 2>&1 | ForEach-Object { Write-Host "$_" } }
finally { $ErrorActionPreference = $previousPreference }
if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar o workspace Rust do SVault.' }

$targetRoot = Join-Path $repo 'target'
if ($CargoTarget) { $targetRoot = Join-Path $targetRoot $CargoTarget }
$releaseDir = Join-Path $targetRoot 'release'

$binaries = @(
    @{ Sub = 'broker'; Src = 'svault-broker.exe'; Dst = 'svault-broker.exe' },
    @{ Sub = 'cli';    Src = 'svaultctl.exe';     Dst = 'svaultctl.exe' },
    @{ Sub = 'mcp';    Src = 'svault-mcp.exe';    Dst = 'svault-mcp.exe' },
    @{ Sub = 'manager';Src = 'svault-manager.exe';Dst = 'SVaultManager.exe' }
)

foreach ($item in $binaries) {
    $outDir = Join-Path $publish $item.Sub
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $releaseDir $item.Src) -Destination (Join-Path $outDir $item.Dst) -Force
}

& $IsccPath "/DAppVersion=$version" (Join-Path $PSScriptRoot 'SVault.iss')
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar o instalador.' }

$installer = Join-Path $repo "artifacts\installer\SVault-Setup-$version-x64.exe"
$checksum = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$installer.sha256", "$checksum  $([IO.Path]::GetFileName($installer))`n", [Text.Encoding]::ASCII)
