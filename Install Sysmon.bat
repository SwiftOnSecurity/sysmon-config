@echo off
cd %temp%
echo [+] Downloading Sysmon...
@powershell (new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon.exe','%temp%\sysmon.exe')"
echo [+] Downloading Sysmon config...
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml','%temp%\sysmonconfig-export.xml')"
sysmon.exe -accepteula -i sysmonconfig-export.xml
echo [+] Sysmon Successfully Installed!
timeout /t 10
exit