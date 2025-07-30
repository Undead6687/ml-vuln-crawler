@echo off
REM This script starts the ZAP daemon in the background
cd /d "C:\Program Files\ZAP\Zed Attack Proxy\"
start zap.bat -daemon -host localhost -port 8080 -config api.key=oclr1pjo9dpeslpgu3pd676p97
exit
