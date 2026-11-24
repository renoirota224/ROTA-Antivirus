@echo off
title ROTA Antivirus - Retirer le disque de test
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Disque-Test.ps1" -Action Retirer
echo.
pause
