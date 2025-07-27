@echo off
echo Starting ZAP in daemon mode...
echo This will start ZAP without the GUI for API access only
echo.
echo To start ZAP daemon:
cd "C:\Program Files\ZAP\Zed Attack Proxy"
zap.bat -daemon -host localhost -port 8080 -config api.disablekey=true
echo.
echo ZAP daemon should now be running on http://localhost:8080
echo You can test it by opening: http://localhost:8080 in your browser
echo.
pause
