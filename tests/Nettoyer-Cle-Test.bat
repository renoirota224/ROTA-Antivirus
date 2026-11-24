@echo off
title ROTA Antivirus - Nettoyer la cle de test
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Cle-Test.ps1" -Action Nettoyer
echo.
pause
