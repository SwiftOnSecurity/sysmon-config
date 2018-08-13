@echo on
cd C:\ProgramData\sysmon\
@powershell (new-object System.Net.WebClient).DownloadFile('https://smartsync.omegapa.com/1/files/share/44/dev/omega-sysmon/sysmonconfig-export.xml/a0e2616fc58e1c','C:\ProgramData\sysmon\sysmonconfig-export.xml')"
sysmon64 -c sysmonconfig-export.xml
exit
