@echo off
setlocal
set hour=%time:~0,2%
set minute=%time:~3,2%
set /A minute+=2
if %minute% GTR 59 (
 set /A minute-=60
 set /A hour+=1
)
if %hour%==24 set hour=00
if "%hour:~0,1%"==" " set hour=0%hour:~1,1%
if "%hour:~1,1%"=="" set hour=0%hour%
if "%minute:~1,1%"=="" set minute=0%minute%
set tasktime=%hour%:%minute%
mkdir C:\ProgramData\sysmon
pushd "C:\ProgramData\sysmon\"
echo [+] Downloading Sysmon...
@powershell (new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon64.exe','C:\ProgramData\sysmon\sysmon64.exe')"
echo [+] Downloading Sysmon config...
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/threathunting/sysmon-config/master/sysmonconfig-export.xml','C:\ProgramData\sysmon\sysmonconfig-export.xml')"
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/threathunting/sysmon-config/master/Auto_update.bat','C:\ProgramData\sysmon\Auto_Update.bat')"
sysmon64.exe -accepteula -i sysmonconfig-export.xml
attrib +s +h +r c:\ProgramData\sysmon
cacls c:\ProgramData\Sysmon /e /p everyone:n
cacls c:\ProgramData\Sysmon /p system:f
cacls c:\ProgramData\Sysmon /p Administrators:f
sc failure Sysmon actions= restart/10000/restart/10000// reset= 120
echo [+] Sysmon Successfully Installed!
echo [+] Creating Auto Update Task set to Hourly..
SchTasks /Create /RU SYSTEM /RL HIGHEST /SC HOURLY /TN Update_Sysmon_Rules /TR C:\ProgramData\sysmon\Auto_Update.bat /F /ST %tasktime%
timeout /t 10
exit
