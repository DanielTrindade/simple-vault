@echo off
title Instalacao do SVault (execute como administrador)
set LOG=%TEMP%\svault-install.log
echo [%DATE% %TIME%] === instalacao do SVault === > "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { try { & '%~dp0Install-SVault.ps1' *>&1 | Tee-Object -FilePath '%TEMP%\svault-install.log' -Append } catch { ($_ | Out-String) | Tee-Object -FilePath '%TEMP%\svault-install.log' -Append } }"
echo.
echo Log completo em %LOG%
pause
