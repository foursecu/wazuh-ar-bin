@echo off
rem wazuh-ip-block.cmd - Wazuh active response entry point (Windows agent).
rem Runs wazuh-ip-block.ps1 from the same directory. stdin and stdout (the
rem JSON messages with wazuh-execd) are inherited by PowerShell.
rem
rem The Wazuh agent is a 32-bit process; Sysnative reaches the 64-bit
rem PowerShell, so firewall and task cmdlets run without WOW64 redirection.
rem
rem Trigger from the manager API:
rem   PUT /active-response?agents_list=<ids>
rem   {"command": "!wazuh-ip-block.cmd", "arguments": ["block", "203.0.113.7"]}

setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0wazuh-ip-block.ps1"
exit /b %ERRORLEVEL%
