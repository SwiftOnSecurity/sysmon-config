@echo off
cd %temp%
echo [+] Downloading Graylog Sidecar to: %temp%\Sidecar.exe...
@powershell (new-object System.Net.WebClient).DownloadFile('https://github.com/Graylog2/collector-sidecar/releases/download/0.1.0-rc.1/collector_sidecar_installer_0.1.0-rc.1.exe','%temp%\Sidecar.exe')"
start /wait Sidecar.exe /S -SERVERURL=https://YOURSERVERIPHERE:443/api -TAGS="windows"
echo [+] Executing Script to edit content of sidecar configuration...
@powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/ion-storm/39d1e70fde966c6e69e57bcb989c5c8d/raw/e3bf0a7b589a340cc557c14bc0f619372cae8752/sidecar.ps1')"
cd "C:\Program Files\graylog\collector-sidecar\"
echo [+] Installing Graylog Services...
graylog-collector-sidecar.exe -service install
graylog-collector-sidecar.exe -service start
echo [+] Checking Services...
@powershell get-service collector-sidecar
echo [+] Graylog Sidecar Successfully Installed and Configured!
timeout /t 10
exit