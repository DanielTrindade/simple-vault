$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$package = Join-Path ([IO.Path]::GetTempPath()) ('svault-package-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $package | Out-Null
try {
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo 'install\SVault.iss'))) {
        if ($line -notmatch '^Source: "([^"]+)"; DestDir: "\{tmp\}\\svault-package\\([^"]+)"') { continue }
        $source = Join-Path $repo ('install\' + $Matches[1])
        $destination = Join-Path $package $Matches[2]
        if ($source.Contains('*')) { continue }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    foreach ($relative in @('install\Install-SVault.ps1', 'install\Run-Install.ps1', 'install\SVaultRollback.ps1', 'tests\mcp-smoke.mjs', 'src\svault-mcp\index.mjs', 'src\svault-mcp\package-lock.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $package $relative))) { throw "Dependencia do instalador ausente no pacote: $relative" }
    }
    & node --check (Join-Path $package 'tests\mcp-smoke.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Teste MCP empacotado invalido.' }
    $entry = Join-Path $package 'install\Install-SVault.ps1'
    $log = Join-Path $package 'install-test.log'
    [IO.File]::WriteAllText($entry, "throw 'falha-simulada-atualizacao'", [Text.UTF8Encoding]::new($false))
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'install\Run-Install.ps1') -LogPath $log | Out-Null
    if ($LASTEXITCODE -ne 1 -or -not [IO.File]::ReadAllText($log).Contains('falha-simulada-atualizacao')) { throw 'Falha de instalacao nao foi registrada e propagada.' }
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $tagFailure = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'install\Build-Installer.ps1') -ReleaseTag v999999.0.0 2>&1 | Out-String
        $tagExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    if ($tagExitCode -eq 0 -or -not $tagFailure.Contains('diverge')) { throw 'Tag divergente nao foi recusada antes de compilar.' }
    Write-Output 'Pacote inclui os scripts necessarios para validar a instalacao e a atualizacao.'
    Write-Output 'Falha de atualizacao preserva o diagnostico e retorna codigo de erro.'
    Write-Output 'Tag divergente da versao e recusada antes de compilar.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($package)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Caminho temporario invalido.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
