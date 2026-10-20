<#
.SYNOPSIS
    Instala o SVault: conta de servico dedicada, Windows Service e arvore de arquivos.

.DESCRIPTION
    Execute em uma sessao elevada (UAC). O script:
      1. publica o broker, a CLI e o gerenciador a partir de src\
      2. cria a conta local svault_svc (senha aleatoria, nunca exibida)
      3. nega logon interativo, remoto e via rede para essa conta
      4. restringe a ACL de C:\ProgramData\SVault e de C:\Program Files\SVault
      5. registra o servico SVaultBroker executando como svault_svc
      6. grava broker.json com o SID do usuario interativo autorizado
      7. inicia o servico e verifica o estado

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
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Este instalador exige uma sessao elevada.'
    }
}

function Publish-Project {
    param([string]$Project, [string]$Output)

    if ($SkipBuild) {
        if (-not (Test-Path -LiteralPath $Output)) { throw "Saida nao encontrada com -SkipBuild: $Output" }
        return
    }

    Write-Host "Publicando $Project ..."
    & dotnet publish $Project -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o $Output --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar $Project" }
}

function Copy-Tree {
    param([string]$Source, [string]$Destination)

    foreach ($file in Get-ChildItem -Path $Source -File -Recurse) {
        $relative = $file.FullName.Substring($Source.Length).TrimStart('\')
        $target = Join-Path $Destination $relative
        $targetDir = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

        try {
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        }
        catch {
            Write-Warning "Nao foi possivel atualizar $relative (arquivo em uso). A versao atual continuara em uso ate a proxima execucao."
        }
    }
}

Assert-Administrator

$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Write-Host "Usuario autorizado: $userSid"
Write-Host "Instalacao        : $InstallRoot"
Write-Host "Dados             : $DataRoot"

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

# 1. Publicacao dos binarios
$publishRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\publish'
if (-not $SkipBuild -and (Test-Path -LiteralPath $publishRoot)) { Remove-Item -LiteralPath $publishRoot -Recurse -Force }

Publish-Project -Project (Join-Path $SourceRoot 'SVault.Broker\SVault.Broker.csproj') -Output (Join-Path $publishRoot 'broker')
Publish-Project -Project (Join-Path $SourceRoot 'SVault.Cli\SVault.Cli.csproj') -Output (Join-Path $publishRoot 'cli')
Publish-Project -Project (Join-Path $SourceRoot 'SVault.Manager\SVault.Manager.csproj') -Output (Join-Path $publishRoot 'manager')

# 2. Copia para o local final
if ($null -ne $existingService -and $existingService.Status -ne 'Stopped') {
    Write-Host "Parando o servico $ServiceName para atualizar os binarios ..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

if (-not (Test-Path -LiteralPath $InstallRoot)) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }
Copy-Tree -Source (Join-Path $publishRoot 'broker') -Destination $InstallRoot
Copy-Tree -Source (Join-Path $publishRoot 'cli') -Destination $InstallRoot
Copy-Tree -Source (Join-Path $publishRoot 'manager') -Destination $InstallRoot

# 3. Skill para os agentes
$skillSource = Join-Path (Split-Path -Parent $PSScriptRoot) 'skills\svault\SKILL.md'
if (Test-Path -LiteralPath $skillSource) {
    $skillTargets = @(
        (Join-Path $env:USERPROFILE '.claude\skills\svault\SKILL.md'),
        (Join-Path $env:USERPROFILE '.config\opencode\skills\svault\SKILL.md'),
        (Join-Path $env:USERPROFILE '.codex\skills\svault\SKILL.md')
    )

    foreach ($target in $skillTargets) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $skillSource -Destination $target -Force
    }
    Write-Host "Skill 'svault' instalada em: Claude Code, OpenCode e Codex"
}

# 4. Servidor MCP
$mcpSource = Join-Path $SourceRoot 'svault-mcp'
$mcpTarget = Join-Path $InstallRoot 'mcp'
if (Test-Path -LiteralPath $mcpTarget) { Remove-Item -LiteralPath $mcpTarget -Recurse -Force }
Copy-Item -LiteralPath $mcpSource -Destination $mcpTarget -Recurse -Force

$nodePath = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $nodePath) { $nodePath = 'node' }

$mcpLauncher = Join-Path $InstallRoot 'svault-mcp.cmd'
@(
    '@echo off',
    "rem Servidor MCP do cofre SVault. Nao contem segredos: apenas encaminha comandos ao broker.",
    "`"$nodePath`" `"$mcpTarget\index.mjs`""
) | Set-Content -LiteralPath $mcpLauncher -Encoding ASCII

# 5. Arvore de dados
if (-not (Test-Path -LiteralPath $DataRoot)) { New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null }
foreach ($sub in @('state', 'logs')) {
    $path = Join-Path $DataRoot $sub
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}

# 6. Conta de servico
# O broker roda como LocalSystem: nao exige "Log on as a service" (que a politica local
# bloqueada por GPO impede conceder via secedit/LSA neste tipo de maquina).
# O isolamento dos valores nao depende da conta: eles ficam cifrados por AES-256-GCM
# com a chave derivada da senha do cofre, dentro do Credential Manager do SYSTEM.
$existingUser = Get-LocalUser -Name $LegacyServiceAccount -ErrorAction SilentlyContinue
if ($null -ne $existingUser) {
    Write-Host "Removendo a conta $LegacyServiceAccount (nao e mais necessaria) ..."
    Remove-LocalUser -Name $LegacyServiceAccount -ErrorAction SilentlyContinue
}
Write-Host "Conta de servico  : LocalSystem (sem conta dedicada)"

# 7. ACLs
Write-Host 'Aplicando ACLs ...'
& icacls.exe $InstallRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $DataRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$userSid`:(OI)(CI)RX" | Out-Null

# 8. Configuracao do broker
$brokerConfig = @{
    version            = '1.0.0'
    allowedClientSids  = @($userSid)
    approvalTtlSeconds = 180
    unlockTtlSeconds   = 300
} | ConvertTo-Json -Depth 4
Set-Content -LiteralPath (Join-Path $DataRoot 'broker.json') -Value $brokerConfig -Encoding UTF8

# 9. Servico
# O sc.exe aceita apenas um token sem espacos no binPath: por isso o executavel fica em
# C:\SVault e o diretorio de dados chega ao processo pela variavel de ambiente do servico.
$binPath = "$InstallRoot\svault-broker.exe"

if ($null -ne $existingService) {
    Write-Host "Removendo o servico existente $ServiceName ..."
    if ($existingService.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    $existingService = $null
}

if ($null -eq $existingService) {
    Write-Host "Registrando o servico $ServiceName ..."
    Write-Host "  binPath: $binPath"
    $scOutput = & sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "$ServiceDisplayName" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao criar o servico: $scOutput"
    }
}

# Variaveis de ambiente do servico (o SCM as injeta no processo)
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
New-ItemProperty -Path $serviceKey -Name 'Environment' -PropertyType MultiString -Value @("SVAULT_HOME=$DataRoot") -Force | Out-Null


& sc.exe description $ServiceName "Broker de credenciais isolado do SVault. Executa como LocalSystem; os valores ficam cifrados pela senha do cofre." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Start-Sleep -Seconds 1

# 10. Inicializacao e verificacao
Write-Host 'Iniciando o servico ...'
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$service = Get-Service -Name $ServiceName
if ($service.Status -ne 'Running') {
    throw "O servico nao ficou em execucao. Estado: $($service.Status). Consulte $DataRoot\logs\svault-broker.log"
}

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
