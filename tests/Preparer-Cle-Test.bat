@echo off
title ROTA Antivirus - Preparer la cle de test
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Cle-Test.ps1" -Action Preparer
echo.
pause
