[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BrokerExe,
    [Parameter(Mandatory)] [string]$McpExe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $BrokerExe -PathType Leaf)) {
    throw "Executavel do broker nao encontrado: $BrokerExe"
}
if (-not (Test-Path -LiteralPath $McpExe -PathType Leaf)) {
    throw "Executavel do servidor MCP nao encontrado: $McpExe"
}

$homeDir = Join-Path ([IO.Path]::GetTempPath()) ('svault-mcp-' + [guid]::NewGuid().ToString('N'))
$pipeName = 'svault.mcp.' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $homeDir -Force | Out-Null

$passed = 0
$failed = 0

function Check([string]$Name, [bool]$Condition, [string]$Detail = '') {
    if ($Condition) {
        $script:passed++
        Write-Host "  [ok]   $Name"
    }
    else {
        $script:failed++
        $suffix = if ($Detail) { ": $Detail" } else { '' }
        Write-Host "  [FALHA] $Name$suffix"
    }
}

$brokerInfo = [Diagnostics.ProcessStartInfo]::new()
$brokerInfo.FileName = [IO.Path]::GetFullPath($BrokerExe)
$brokerInfo.Arguments = "--console --in-memory-credentials --home `"$homeDir`" --pipe $pipeName"
$brokerInfo.UseShellExecute = $false
$brokerInfo.RedirectStandardOutput = $true
$brokerInfo.RedirectStandardError = $true
$brokerInfo.CreateNoWindow = $true
$broker = [Diagnostics.Process]::Start($brokerInfo)

$utf8NoBom = [Text.UTF8Encoding]::new($false)
$mcpInfo = [Diagnostics.ProcessStartInfo]::new()
$mcpInfo.FileName = [IO.Path]::GetFullPath($McpExe)
$mcpInfo.UseShellExecute = $false
$mcpInfo.RedirectStandardInput = $true
$mcpInfo.RedirectStandardOutput = $true
$mcpInfo.RedirectStandardError = $true
$mcpInfo.CreateNoWindow = $true
$mcpInfo.StandardOutputEncoding = $utf8NoBom
$mcpInfo.EnvironmentVariables['SVAULT_PIPE'] = $pipeName
$mcp = $null

try {
    Start-Sleep -Milliseconds 800

    $mcp = [Diagnostics.Process]::Start($mcpInfo)
    $nextId = 1

    function Write-McpLine([string]$Line) {
        $bytes = $utf8NoBom.GetBytes($Line + "`n")
        $mcp.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $mcp.StandardInput.BaseStream.Flush()
    }

    function Send-Rpc([string]$Method, [hashtable]$Params) {
        $id = $script:nextId++
        $payload = @{
            jsonrpc = '2.0'
            id      = $id
            method  = $Method
            params  = $Params
        } | ConvertTo-Json -Compress -Depth 8
        Write-McpLine $payload

        $readTask = $mcp.StandardOutput.ReadLineAsync()
        if (-not $readTask.Wait(20000)) {
            throw "Timeout aguardando resposta MCP em $Method"
        }
        $line = $readTask.Result
        if ([string]::IsNullOrWhiteSpace($line)) {
            throw "Resposta vazia do servidor MCP em $Method"
        }
        $parsed = $line | ConvertFrom-Json
        if (-not $parsed.PSObject.Properties['result']) {
            throw "Erro JSON-RPC em ${Method}: $line"
        }
        return $parsed
    }

    $init = Send-Rpc 'initialize' @{
        protocolVersion = '2024-11-05'
        capabilities    = @{}
        clientInfo      = @{ name = 'svault-smoke'; version = '1.0.0' }
    }
    Check 'initialize responde' ($init.result.serverInfo.name -eq 'svault-mcp')

    $notify = @{ jsonrpc = '2.0'; method = 'notifications/initialized'; params = @{} } | ConvertTo-Json -Compress
    Write-McpLine $notify

    $toolsResp = Send-Rpc 'tools/list' @{}
    $names = @($toolsResp.result.tools | ForEach-Object { $_.name } | Sort-Object)
    $expected = @('vault_health', 'vault_list_entries', 'vault_list_operations', 'vault_operation_status', 'vault_request_operation')
    Check 'ferramentas expostas sao apenas as seguras' (($names -join ',') -eq ($expected -join ',')) ($names -join ',')

    $forbidden = @($names | Where-Object { $_ -match 'get_secret|read_password|reveal|export|decrypt' })
    Check 'nenhuma ferramenta devolve segredo' ($forbidden.Count -eq 0)

    $health = Send-Rpc 'tools/call' @{ name = 'vault_health'; arguments = @{} }
    $healthErr = ($health.result.PSObject.Properties['isError'] -and $health.result.isError -eq $true)
    Check 'vault_health responde' (-not $healthErr)

    $entries = Send-Rpc 'tools/call' @{ name = 'vault_list_entries'; arguments = @{} }
    $entriesErr = ($entries.result.PSObject.Properties['isError'] -and $entries.result.isError -eq $true)
    $entriesText = [string]$entries.result.content[0].text
    Check 'vault_list_entries responde' (-not $entriesErr)
    Check 'vault_list_entries nao contem segredo' ($entriesText -notmatch 'value|senha|secret|password')

    $ops = Send-Rpc 'tools/call' @{ name = 'vault_list_operations'; arguments = @{} }
    $opsErr = ($ops.result.PSObject.Properties['isError'] -and $ops.result.isError -eq $true)
    Check 'vault_list_operations responde' (-not $opsErr)

    $req = Send-Rpc 'tools/call' @{ name = 'vault_request_operation'; arguments = @{ operationId = 'inexistente' } }
    $reqText = [string]$req.result.content[0].text
    Check 'vault_request_operation sinaliza erro de forma controlada' ($req.result.isError -eq $true -and $reqText.Contains('not_found')) $reqText

    $status = Send-Rpc 'tools/call' @{ name = 'vault_operation_status'; arguments = @{ requestId = 'inexistente' } }
    Check 'vault_operation_status sinaliza erro de forma controlada' ($status.result.isError -eq $true)
}
catch {
    $failed++
    Write-Host "  [FALHA] execucao do teste MCP: $($_.Exception.Message) | $($_.InvocationInfo.PositionMessage)"
}
finally {
    if ($null -ne $mcp -and -not $mcp.HasExited) {
        try { $mcp.Kill() } catch {}
    }
    if ($null -ne $broker -and -not $broker.HasExited) {
        try { $broker.Kill() } catch {}
    }
    Start-Sleep -Milliseconds 200
    if (Test-Path -LiteralPath $homeDir) {
        Remove-Item -LiteralPath $homeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host "resultado: $passed aprovado(s), $failed falha(s)"
if ($failed -eq 0) { exit 0 } else { exit 1 }
