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
if (-not $versionMatch.Success) { throw 'A versao do gerenciador precisa seguir X.Y.Z.' }
$version = $versionMatch.Groups[1].Value
if ($ReleaseTag -and $ReleaseTag -cne "v$version") { throw "Tag $ReleaseTag diverge da versao v$version do gerenciador." }
$publish = Join-Path $repo 'artifacts\publish'
if (-not (Test-Path -LiteralPath $IsccPath)) { throw 'Instale o Inno Setup 6 ou informe -IsccPath.' }
foreach ($project in @(@('SVault.Broker', 'broker'), @('SVault.Cli', 'cli'))) {
    $output = [IO.Path]::GetFullPath((Join-Path $publish $project[1]))
    if (-not $output.StartsWith([IO.Path]::GetFullPath($publish) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Diretorio de publicacao invalido.' }
    if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
    & dotnet publish (Join-Path $repo "src\$($project[0])\$($project[0]).csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o (Join-Path $publish $project[1]) --nologo
    if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar $($project[0])." }
}
$cargoArgs = @('build', '--release', '--locked', '--manifest-path', (Join-Path $repo 'src\svault-manager\Cargo.toml'))
if ($CargoTarget) { $cargoArgs += @('--target', $CargoTarget) }
if ($CargoToolchain) { $cargoArgs = @("+$CargoToolchain") + $cargoArgs }
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & cargo @cargoArgs 2>&1 | ForEach-Object { Write-Host "$_" } }
finally { $ErrorActionPreference = $previousPreference }
if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar o gerenciador.' }
$manager = Join-Path $publish 'manager'
New-Item -ItemType Directory -Path $manager -Force | Out-Null
$targetRoot = Join-Path $repo 'src\svault-manager\target'
if ($CargoTarget) { $targetRoot = Join-Path $targetRoot $CargoTarget }
Copy-Item -LiteralPath (Join-Path $targetRoot 'release\svault-manager.exe') -Destination (Join-Path $manager 'SVaultManager.exe') -Force
& $IsccPath "/DAppVersion=$version" (Join-Path $PSScriptRoot 'SVault.iss')
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar o instalador.' }
$installer = Join-Path $repo "artifacts\installer\SVault-Setup-$version-x64.exe"
$checksum = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$installer.sha256", "$checksum  $([IO.Path]::GetFileName($installer))`n", [Text.Encoding]::ASCII)
