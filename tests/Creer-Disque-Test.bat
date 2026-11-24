@echo off
title ROTA Antivirus - Creer le disque de test
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Disque-Test.ps1" -Action Creer
echo.
pause
