<#
.SYNOPSIS
    Instala o SVault (100% Rust): Windows Service e arvore de arquivos isolada.

.DESCRIPTION
    Execute em uma sessao elevada (UAC). O script:
      1. compila (ou reutiliza com -SkipBuild) broker, CLI, servidor MCP e gerenciador em Rust
      2. prepara e valida a arvore completa em diretorio temporario antes de tocar no servico
      3. restringe a ACL de C:\SVault e de C:\ProgramData\SVault
      4. registra o servico SVaultBroker executando como LocalSystem
      5. grava broker.json com o SID do usuario interativo autorizado
      6. inicia o servico e executa os testes de saude e protocolo MCP (com rollback automatico)

    Nenhum segredo e lido, escrito ou exibido por este script.
#>
[CmdletBinding()]
param(
    [string]$LegacyServiceAccount = 'svault_svc',
    [string]$ServiceName = 'SVaultBroker',
    [string]$ServiceDisplayName = 'SVault Secret Broker',
    [string]$InstallRoot = 'C:\SVault',
    [string]$DataRoot = 'C:\ProgramData\SVault',
    [string]$SourceRoot = (Join-Path $PSScriptRoot '..\src'),
    [string]$CargoToolchain = '',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'SVaultRollback.ps1')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Este instalador exige uma sessao elevada.'
    }
}

function Publish-RustWorkspace {
    param([string]$RepoRoot, [string]$PublishRoot)

    $binaries = @(
        @{ Sub = 'broker'; Src = 'svault-broker.exe'; Dst = 'svault-broker.exe' },
        @{ Sub = 'cli';    Src = 'svaultctl.exe';     Dst = 'svaultctl.exe' },
        @{ Sub = 'mcp';    Src = 'svault-mcp.exe';    Dst = 'svault-mcp.exe' },
        @{ Sub = 'manager';Src = 'svault-manager.exe';Dst = 'SVaultManager.exe' }
    )

    if ($SkipBuild) {
        foreach ($item in $binaries) {
            $expected = Join-Path (Join-Path $PublishRoot $item.Sub) $item.Dst
            if (-not (Test-Path -LiteralPath $expected -PathType Leaf)) {
                throw "Saida nao encontrada com -SkipBuild: $expected"
            }
        }
        return
    }

    $cargo = (Get-Command cargo -ErrorAction SilentlyContinue).Source
    if (-not $cargo) { throw 'Rust (cargo) e necessario para compilar o SVault a partir dos fontes.' }

    if ($CargoToolchain -match 'gnu' -and (Test-Path -LiteralPath 'C:\msys64\mingw64\bin')) {
        $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
    }

    Write-Host 'Compilando workspace Rust do SVault ...'
    $cargoArgs = @(
        'build', '--release', '--locked',
        '--manifest-path', (Join-Path $RepoRoot 'Cargo.toml'),
        '-p', 'svault-broker',
        '-p', 'svault-cli',
        '-p', 'svault-mcp',
        '-p', 'svault-manager'
    )
    if ($CargoToolchain) { $cargoArgs = @("+$CargoToolchain") + $cargoArgs }

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $cargo @cargoArgs 2>&1 | ForEach-Object { Write-Host "$_" } }
    finally { $ErrorActionPreference = $previousPreference }
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar o workspace Rust do SVault.' }

    $releaseDir = Join-Path $RepoRoot 'target\release'
    foreach ($item in $binaries) {
        $outDir = Join-Path $PublishRoot $item.Sub
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $releaseDir $item.Src) -Destination (Join-Path $outDir $item.Dst) -Force -ErrorAction Stop
    }
}

function Copy-Tree {
    param([string]$Source, [string]$Destination)

    foreach ($file in Get-ChildItem -Path $Source -File -Recurse) {
        $relative = $file.FullName.Substring($Source.Length).TrimStart('\')
        $target = Join-Path $Destination $relative
        $targetDir = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

        Copy-Item -LiteralPath $file.FullName -Destination $target -Force -ErrorAction Stop
    }
}

function Invoke-NativeChecked {
    param([string]$File, [string[]]$Arguments)

    $output = & $File @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Falha em $File (codigo $LASTEXITCODE): $output" }
}

function Remove-UnexpectedAces {
    param([string]$Root, [string[]]$AllowedSids)

    $paths = @((Get-Item -LiteralPath $Root)) + @(Get-ChildItem -LiteralPath $Root -Force -Recurse)
    foreach ($item in $paths) {
        $acl = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
        $changed = $false
        foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            if ($rule.IdentityReference.Value -notin $AllowedSids) {
                Write-Host "Removendo permissao nao prevista de $($rule.IdentityReference.Value) em $($item.FullName)"
                [void]$acl.RemoveAccessRuleSpecific($rule)
                $changed = $true
            }
        }
        if ($changed) { $item.SetAccessControl($acl) }
    }
}

function Assert-RestrictedAcl {
    param([string]$Root, [hashtable]$AllowedRights)

    $paths = @((Get-Item -LiteralPath $Root)) + @(Get-ChildItem -LiteralPath $Root -Force -Recurse)
    foreach ($item in $paths) {
        $acl = Get-Acl -LiteralPath $item.FullName
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if (-not $AllowedRights.ContainsKey($sid) -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
                throw "ACL inesperada em $($item.FullName): $sid"
            }
            $rights = [Security.AccessControl.FileSystemRights]$rule.FileSystemRights
            if (($rights -band $AllowedRights[$sid]) -ne $rights) { throw "Permissao ACL excessiva em $($item.FullName): $sid" }
        }
    }
}

Assert-Administrator

$repoRoot = Split-Path -Parent $PSScriptRoot
$mcpSmokePath = Join-Path $repoRoot 'tests\Mcp.SmokeTest.ps1'
if (-not (Test-Path -LiteralPath $mcpSmokePath -PathType Leaf)) {
    throw 'Pacote incompleto: tests\Mcp.SmokeTest.ps1 nao encontrado. Nenhuma alteracao foi aplicada.'
}

$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Write-Host "Usuario autorizado: $userSid"
Write-Host "Instalacao        : $InstallRoot"
Write-Host "Dados             : $DataRoot"

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
    $serviceDetails = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    $servicePath = [regex]::Match($serviceDetails.PathName, '^\s*(?:"([^"]+)"|(\S+))').Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($servicePath)) { $servicePath = [regex]::Match($serviceDetails.PathName, '^\s*(\S+)').Groups[1].Value }
    $expectedServicePath = [IO.Path]::GetFullPath((Join-Path $InstallRoot 'svault-broker.exe'))
    if (-not [string]::Equals([IO.Path]::GetFullPath($servicePath), $expectedServicePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "O servico $ServiceName aponta para outro broker: $servicePath"
    }
    if ($serviceDetails.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw "O servico $ServiceName nao esta configurado para LocalSystem."
    }
}

# 1. Publicacao dos binarios Rust
$publishRoot = Join-Path $repoRoot 'artifacts\publish'
if (-not $SkipBuild -and (Test-Path -LiteralPath $publishRoot)) { Remove-Item -LiteralPath $publishRoot -Recurse -Force }
Publish-RustWorkspace -RepoRoot $repoRoot -PublishRoot $publishRoot

# 2. Prepara e valida uma release completa antes de alterar o servico
$installParent = Split-Path -Parent ([IO.Path]::GetFullPath($InstallRoot))
if (-not (Test-Path -LiteralPath $installParent)) { New-Item -ItemType Directory -Path $installParent -Force | Out-Null }
$releaseStage = Join-Path $installParent ('.SVault-stage-' + [guid]::NewGuid().ToString('N'))
$releaseBackup = Join-Path $installParent ('.SVault-backup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $releaseStage -Force | Out-Null

foreach ($component in @('broker', 'cli', 'mcp', 'manager')) {
    Copy-Tree -Source (Join-Path $publishRoot $component) -Destination $releaseStage
}

$mcpCompatStage = Join-Path $releaseStage 'mcp'
New-Item -ItemType Directory -Path $mcpCompatStage -Force | Out-Null
$shimSource = Join-Path $SourceRoot 'svault-mcp\index.mjs'
if (Test-Path -LiteralPath $shimSource -PathType Leaf) {
    Copy-Item -LiteralPath $shimSource -Destination (Join-Path $mcpCompatStage 'index.mjs') -Force -ErrorAction Stop
}

$mcpLauncherStage = Join-Path $releaseStage 'svault-mcp.cmd'
@(
    '@echo off',
    'rem Servidor MCP nativo do cofre SVault (Rust). Nao contem segredos: apenas encaminha comandos ao broker.',
    '"%~dp0svault-mcp.exe" %*'
) | Set-Content -LiteralPath $mcpLauncherStage -Encoding ASCII

foreach ($required in @('svault-broker.exe', 'svaultctl.exe', 'svault-mcp.exe', 'SVaultManager.exe', 'svault-mcp.cmd')) {
    if (-not (Test-Path -LiteralPath (Join-Path $releaseStage $required) -PathType Leaf)) {
        throw "Arquivo obrigatorio ausente na release: $required"
    }
}

$hadInstallRoot = Test-Path -LiteralPath $InstallRoot
$oldMovedToBackup = $false
$installActivated = $false
$wasServiceRunning = $null -ne $existingService -and $existingService.Status -eq 'Running'
$serviceCreated = $false
$brokerConfigPath = Join-Path $DataRoot 'broker.json'
$hadBrokerConfig = Test-Path -LiteralPath $brokerConfigPath
$originalBrokerConfig = if ($hadBrokerConfig) { [IO.File]::ReadAllBytes($brokerConfigPath) } else { $null }
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$serviceEnvironment = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
$hadServiceEnvironment = $null -ne $serviceEnvironment
$originalServiceEnvironment = if ($hadServiceEnvironment) { @($serviceEnvironment.Environment) } else { @() }
$originalDataAcls = @()
if (Test-Path -LiteralPath $DataRoot) {
    $dataPaths = @((Get-Item -LiteralPath $DataRoot)) + @(Get-ChildItem -LiteralPath $DataRoot -Force -Recurse)
    foreach ($path in $dataPaths) { $originalDataAcls += [pscustomobject]@{ Path = $path.FullName; Acl = Get-Acl -LiteralPath $path.FullName } }
}

try {
    if ($wasServiceRunning) {
        Write-Host "Parando o servico $ServiceName para ativar a release validada ..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    if ($hadInstallRoot) {
        Move-Item -LiteralPath $InstallRoot -Destination $releaseBackup -ErrorAction Stop
        $oldMovedToBackup = $true
    }
    Move-Item -LiteralPath $releaseStage -Destination $InstallRoot -ErrorAction Stop
    $installActivated = $true

    # Arvore de dados
    if (-not (Test-Path -LiteralPath $DataRoot)) { New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null }
    foreach ($sub in @('state', 'logs')) {
        $path = Join-Path $DataRoot $sub
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    }

    # ACLs
    Write-Host 'Aplicando ACLs ...'
    Invoke-NativeChecked -File 'icacls.exe' -Arguments @($InstallRoot, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')
    Invoke-NativeChecked -File 'icacls.exe' -Arguments @($DataRoot, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "*$userSid`:(OI)(CI)RX")
    Remove-UnexpectedAces -Root $InstallRoot -AllowedSids @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')
    Remove-UnexpectedAces -Root $DataRoot -AllowedSids @('S-1-5-18', 'S-1-5-32-544', $userSid)
    $readRights = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize -bor [Security.AccessControl.FileSystemRights]::ReadAttributes -bor [Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::ListDirectory
    $fullRights = [Security.AccessControl.FileSystemRights]::FullControl
    Assert-RestrictedAcl -Root $InstallRoot -AllowedRights @{ 'S-1-5-18' = $fullRights; 'S-1-5-32-544' = $fullRights; 'S-1-5-32-545' = $readRights }
    Assert-RestrictedAcl -Root $DataRoot -AllowedRights @{ 'S-1-5-18' = $fullRights; 'S-1-5-32-544' = $fullRights; $userSid = $readRights }

    # Configuracao do broker
    $brokerConfig = @{
        version            = '1.0.0'
        allowedClientSids  = @($userSid)
        approvalTtlSeconds = 180
        unlockTtlSeconds   = 300
    } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText((Join-Path $DataRoot 'broker.json'), $brokerConfig, [Text.UTF8Encoding]::new($false))

    # Servico Windows
    $binPath = "$InstallRoot\svault-broker.exe"
    if ($null -eq $existingService) {
        Write-Host "Registrando o servico $ServiceName ..."
        Write-Host "  binPath: $binPath"
        $scOutput = & sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "$ServiceDisplayName" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Falha ao criar o servico: $scOutput"
        }
        $serviceCreated = $true
    }

    New-ItemProperty -Path $serviceKey -Name 'Environment' -PropertyType MultiString -Value @("SVAULT_HOME=$DataRoot") -Force | Out-Null

    if ($serviceCreated) {
        Invoke-NativeChecked -File 'sc.exe' -Arguments @('description', $ServiceName, 'Broker de credenciais isolado do SVault (Rust). Executa como LocalSystem; os valores ficam cifrados pela senha do cofre.')
        Invoke-NativeChecked -File 'sc.exe' -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/60000')
        Invoke-NativeChecked -File 'sc.exe' -Arguments @('failureflag', $ServiceName, '1')
    }
    Start-Sleep -Seconds 1

    # Inicializacao e verificacao
    Write-Host 'Iniciando o servico ...'
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne 'Running') {
        throw "O servico nao ficou em execucao. Estado: $($service.Status). Consulte $DataRoot\logs\svault-broker.log"
    }

    & (Join-Path $InstallRoot 'svaultctl.exe') health
    if ($LASTEXITCODE -ne 0) { throw 'A verificacao do protocolo broker health falhou.' }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $mcpSmokePath `
        -BrokerExe (Join-Path $InstallRoot 'svault-broker.exe') `
        -McpExe (Join-Path $InstallRoot 'svault-mcp.exe')
    if ($LASTEXITCODE -ne 0) { throw 'O smoke MCP isolado falhou.' }
}
catch {
    $failure = $_
    $rollback = Invoke-SVaultRollback `
        -HadPreviousRelease $hadInstallRoot `
        -OldMovedToBackup $oldMovedToBackup `
        -NewActivated $installActivated `
        -WasServiceRunning $wasServiceRunning `
        -StopNewService {
            if ($serviceCreated) {
                $stopFailure = $null
                try { Invoke-NativeChecked -File 'sc.exe' -Arguments @('stop', $ServiceName) } catch { $stopFailure = $_ }
                try { Invoke-NativeChecked -File 'sc.exe' -Arguments @('delete', $ServiceName) }
                catch { if ($null -eq $stopFailure) { throw } }
                if ($null -ne $stopFailure) { throw $stopFailure }
            }
            else { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
        } `
        -RestoreBrokerConfig {
            if ($hadBrokerConfig) { [IO.File]::WriteAllBytes($brokerConfigPath, $originalBrokerConfig) }
            elseif (Test-Path -LiteralPath $brokerConfigPath) { Remove-Item -LiteralPath $brokerConfigPath -Force -ErrorAction Stop }
        } `
        -RestoreServiceEnvironment {
            if (-not $serviceCreated) {
                if ($hadServiceEnvironment) { New-ItemProperty -Path $serviceKey -Name 'Environment' -PropertyType MultiString -Value $originalServiceEnvironment -Force | Out-Null }
                else { Remove-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction Stop }
            }
        } `
        -RestoreDataAcls {
            $aclFailures = [System.Collections.Generic.List[string]]::new()
            foreach ($snapshot in $originalDataAcls) {
                try { if (Test-Path -LiteralPath $snapshot.Path) { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } }
                catch { $aclFailures.Add($_.Exception.GetType().Name) }
            }
            if ($aclFailures.Count -gt 0) { throw 'Falha em uma ou mais restauracoes de ACL.' }
        } `
        -RemoveActivatedRelease {
            if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop }
        } `
        -TestInstallRoot { Test-Path -LiteralPath $InstallRoot } `
        -RestorePreviousRelease {
            if (-not (Test-Path -LiteralPath $releaseBackup)) { throw 'Backup da release anterior ausente.' }
            Move-Item -LiteralPath $releaseBackup -Destination $InstallRoot -ErrorAction Stop
        } `
        -StartPreviousService { Start-Service -Name $ServiceName -ErrorAction Stop }
    foreach ($stepFailure in $rollback.Failures) {
        try { Write-Warning "Falha durante recuperacao ($stepFailure)." } catch { }
    }
    throw $failure
}

if (Test-Path -LiteralPath $releaseBackup) {
    try { Remove-Item -LiteralPath $releaseBackup -Recurse -Force }
    catch { Write-Warning "A release anterior foi mantida em $releaseBackup porque nao pode ser removida." }
}

# Skill e conta legada sao tratadas somente depois de validar a release ativa
$skillSource = Join-Path $repoRoot 'skills\svault\SKILL.md'
if (Test-Path -LiteralPath $skillSource) {
    $skillTargets = @(
        (Join-Path $env:USERPROFILE '.claude\skills\svault\SKILL.md'),
        (Join-Path $env:USERPROFILE '.config\opencode\skills\svault\SKILL.md'),
        (Join-Path $env:USERPROFILE '.codex\skills\svault\SKILL.md')
    )

    foreach ($target in $skillTargets) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $skillSource -Destination $target -Force -ErrorAction Stop
    }
}

$existingUser = Get-LocalUser -Name $LegacyServiceAccount -ErrorAction SilentlyContinue
if ($null -ne $existingUser) { Remove-LocalUser -Name $LegacyServiceAccount -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host 'Instalacao concluida.'
Write-Host "  Servico    : $ServiceName ($($service.Status))"
Write-Host "  Identidade : LocalSystem"
Write-Host "  Pipe       : \\.\pipe\svault.broker.v1"
Write-Host "  Permitido  : $userSid"
Write-Host "  Instalacao : $InstallRoot"
Write-Host "  Dados      : $DataRoot"
Write-Host ''
Write-Host 'Proximos passos:'
Write-Host ('  1. Inicialize o cofre:    & "{0}\svaultctl.exe" init --totp' -f $InstallRoot)
Write-Host ('  2. Cadastre um segredo:   & "{0}\svaultctl.exe" add --id CPF_PESSOAL --kind cpf --target https://servico.exemplo.com' -f $InstallRoot)
Write-Host ('  3. Abra o gerenciador:    & "{0}\SVaultManager.exe"' -f $InstallRoot)
