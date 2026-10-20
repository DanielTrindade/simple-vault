function Invoke-SVaultRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [bool]$HadPreviousRelease,
        [Parameter(Mandatory)] [bool]$OldMovedToBackup,
        [Parameter(Mandatory)] [bool]$NewActivated,
        [Parameter(Mandatory)] [bool]$WasServiceRunning,
        [Parameter(Mandatory)] [scriptblock]$StopNewService,
        [Parameter(Mandatory)] [scriptblock]$RestoreBrokerConfig,
        [Parameter(Mandatory)] [scriptblock]$RestoreServiceEnvironment,
        [Parameter(Mandatory)] [scriptblock]$RestoreDataAcls,
        [Parameter(Mandatory)] [scriptblock]$RemoveActivatedRelease,
        [Parameter(Mandatory)] [scriptblock]$TestInstallRoot,
        [Parameter(Mandatory)] [scriptblock]$RestorePreviousRelease,
        [Parameter(Mandatory)] [scriptblock]$StartPreviousService
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    $steps = @(
        @{ Name = 'parar-servico-novo'; Action = $StopNewService },
        @{ Name = 'restaurar-broker-config'; Action = $RestoreBrokerConfig },
        @{ Name = 'restaurar-environment'; Action = $RestoreServiceEnvironment },
        @{ Name = 'restaurar-acls'; Action = $RestoreDataAcls }
    )

    foreach ($step in $steps) {
        try { & $step.Action }
        catch { $failures.Add("$($step.Name):$($_.Exception.GetType().Name)") }
    }

    $previousReleaseRestored = -not $HadPreviousRelease -or -not $OldMovedToBackup
    if ($NewActivated) {
        try { & $RemoveActivatedRelease }
        catch { $failures.Add("remover-release-nova:$($_.Exception.GetType().Name)") }
    }

    if ($OldMovedToBackup) {
        $installRootExists = $true
        try { $installRootExists = [bool](& $TestInstallRoot) }
        catch { $failures.Add("verificar-install-root:$($_.Exception.GetType().Name)") }

        if ($installRootExists) {
            $failures.Add('restaurar-release-anterior:install-root-ocupado')
            $previousReleaseRestored = $false
        }
        else {
            try {
                & $RestorePreviousRelease
                $previousReleaseRestored = $true
            }
            catch {
                $failures.Add("restaurar-release-anterior:$($_.Exception.GetType().Name)")
                $previousReleaseRestored = $false
            }
        }
    }

    $serviceStarted = $false
    if ($WasServiceRunning -and $previousReleaseRestored)
    {
        try {
            & $StartPreviousService
            $serviceStarted = $true
        }
        catch { $failures.Add("iniciar-servico-anterior:$($_.Exception.GetType().Name)") }
    }

    [pscustomobject]@{
        PreviousReleaseRestored = $previousReleaseRestored
        ServiceStarted = $serviceStarted
        Failures = $failures.ToArray()
    }
}
