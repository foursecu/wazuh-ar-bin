@echo off
rem ar-sync.cmd - Wazuh active response entry point (Windows agent).
rem Runs ar-sync.ps1 from the same directory. stdin (the JSON message from
rem wazuh-execd) is inherited by PowerShell.
rem
rem Trigger from the manager API:
rem   PUT /active-response?agents_list=<ids>   {"command": "!ar-sync.cmd"}

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0ar-sync.ps1"
exit /b 0
