. (Join-Path $PSScriptRoot '..\install\SVaultRollback.ps1')

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}

function Invoke-RollbackScenario([string]$failureStep, [bool]$oldMoved, [bool]$newActivated, [bool]$failRemove, [bool]$failMove) {
    $state = [pscustomobject]@{
        InstallRoot = if ($oldMoved -or $newActivated) { 'new-release' } else { 'old-release' }
        Backup = if ($oldMoved) { 'old-release' } else { $null }
        Service = 'stopped'
        Calls = [System.Collections.Generic.List[string]]::new()
    }
    $result = Invoke-SVaultRollback `
        -HadPreviousRelease $true `
        -OldMovedToBackup $oldMoved `
        -NewActivated $newActivated `
        -WasServiceRunning $true `
        -StopNewService { $state.Calls.Add('stop') } `
        -RestoreBrokerConfig {
            $state.Calls.Add('config')
            if ($failureStep -eq 'config') { throw 'synthetic' }
        } `
        -RestoreServiceEnvironment {
            $state.Calls.Add('environment')
            if ($failureStep -eq 'environment') { throw 'synthetic' }
        } `
        -RestoreDataAcls {
            $state.Calls.Add('acl')
            if ($failureStep -eq 'acl') { throw 'synthetic' }
        } `
        -RemoveActivatedRelease {
            $state.Calls.Add('remove-new')
            if ($failRemove) { throw 'synthetic' }
            $state.InstallRoot = $null
        } `
        -TestInstallRoot { $null -ne $state.InstallRoot } `
        -RestorePreviousRelease {
            $state.Calls.Add('restore-release')
            if ($failMove) { throw 'synthetic' }
            if ($null -ne $state.InstallRoot) { throw 'occupied' }
            $state.InstallRoot = $state.Backup
            $state.Backup = $null
        } `
        -StartPreviousService {
            $state.Calls.Add('start-old')
            $state.Service = 'running'
        }
    [pscustomobject]@{ State = $state; Result = $result }
}

foreach ($failure in @('config', 'environment', 'acl')) {
    $scenario = Invoke-RollbackScenario $failure $true $true $false $false
    Assert-True ($scenario.State.InstallRoot -eq 'old-release') "A falha em $failure impediu restaurar os binarios anteriores."
    Assert-True ($scenario.State.Service -eq 'running') "A falha em $failure impediu tentar reiniciar o servico anterior."
    Assert-True ($scenario.State.Backup -eq $null) "O backup nao foi restaurado apos falha em $failure."
    Assert-True ($scenario.Result.Failures.Count -eq 1) "A falha em $failure nao foi registrada isoladamente."
    Assert-True ($scenario.State.Calls.Contains('config') -and $scenario.State.Calls.Contains('environment') -and $scenario.State.Calls.Contains('acl')) "Uma restauracao foi pulada apos falha em $failure."
    Write-Output "rollback falha em ${failure}: release e servico anteriores restaurados; falha reportada"
}

$beforeRename = Invoke-RollbackScenario 'none' $false $false $false $false
Assert-True ($beforeRename.State.InstallRoot -eq 'old-release') 'Falha antes do rename alterou a instalacao existente.'
Assert-True ($beforeRename.State.Service -eq 'running') 'Falha antes do rename nao tentou reiniciar o servico existente.'
Assert-True (-not $beforeRename.State.Calls.Contains('remove-new')) 'Falha antes do rename tentou remover a instalacao original.'
Write-Output 'rollback falha pre-rename: release original preservada e servico retomado'

$removeFailure = Invoke-RollbackScenario 'none' $true $true $true $false
Assert-True ($removeFailure.State.InstallRoot -eq 'new-release') 'Falha de remocao deveria manter a release nova visivel para diagnostico.'
Assert-True ($removeFailure.State.Backup -eq 'old-release') 'Falha de remocao perdeu o backup anterior.'
Assert-True ($removeFailure.State.Service -eq 'stopped') 'Rollback tentou iniciar servico sem restaurar binarios anteriores.'
Assert-True ($removeFailure.Result.Failures -contains 'remover-release-nova:RuntimeException') 'Falha ao remover release nao foi reportada.'
Write-Output 'rollback falha ao remover release: backup preservado e servico anterior nao inicia sobre release nova'

$moveFailure = Invoke-RollbackScenario 'none' $true $true $false $true
Assert-True ($moveFailure.State.InstallRoot -eq $null) 'Falha de restore nao deveria ativar uma release incompleta.'
Assert-True ($moveFailure.State.Backup -eq 'old-release') 'Falha ao mover backup perdeu os binarios anteriores.'
Assert-True ($moveFailure.State.Service -eq 'stopped') 'Rollback tentou iniciar servico sem restaurar binarios anteriores.'
Assert-True ($moveFailure.Result.Failures -contains 'restaurar-release-anterior:RuntimeException') 'Falha ao restaurar release nao foi reportada.'
Write-Output 'rollback falha ao mover backup: release anterior preservada e servico nao iniciado'

Write-Output 'resultado: 6 cenarios aprovados, 0 falhas'
