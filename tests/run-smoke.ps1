<#
.SYNOPSIS
    Publica o broker e executa o teste de fumaça com dados fictícios.

.DESCRIPTION
    O teste sobe um broker em modo console (sem elevação, sem serviço) com um diretório
    temporário, sobe um servidor HTTP local que ecoa o corpo recebido e valida:
      - o ciclo completo de cadastro, autorização, solicitação e aprovação
      - a ausência do valor do segredo em qualquer resposta, log ou estado
      - a recusa de senha incorreta, alvo não autorizado e segredo literal em template
      - a exigência do segundo fator TOTP quando habilitada
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $root 'artifacts'

& dotnet publish (Join-Path $root 'src\SVault.Broker\SVault.Broker.csproj') `
    -c $Configuration -r win-x64 --self-contained false -p:PublishSingleFile=true `
    -o (Join-Path $artifacts 'broker') --nologo -v q
if ($LASTEXITCODE -ne 0) { throw 'Falha ao publicar o broker.' }

& dotnet run --project (Join-Path $root 'tests\SVault.SmokeTest\SVault.SmokeTest.csproj') `
    -c $Configuration --no-launch-profile -- (Join-Path $artifacts 'broker\svault-broker.exe')
exit $LASTEXITCODE
