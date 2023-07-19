# Sysmon Configuration

## Configuration Overview
---
### [Event ID 1 - ProcessCreate](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation)
The configuration uses exclusion-based filtering for ProcessCreate events.

All process creations are monitored except for those defined within the `<ProcessCreate onmatch="exclude">` block.

---
### [Event ID 2 - FileCreateTime](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-2-a-process-changed-a-file-creation-time)
The configuration uses both inclusion-based and exclusion-based filtering.

Events that meet the criteria defined in the `<FileCreateTime onmatch="include">` block will be recorded unless the event also meets criteria defined in the `<FileCreateTime onmatch="exclude">` block.

The __include__ rules for this event capture the following:
- Changes made by images under:
    - `C:\Users\`
    - `\Device\HarddiskVolumeShadowCopy`
- Changes made to any `.exe` file

The __exclude__ rules for this event define the following exclusions:
- Changes made by `OneDrive.exe`
- Changes made by `C:\Windows\system32\backgroundTaskHost.exe`
- Changes made by process image paths containing:
    - `setup`
    - `install`
    - `Update\`
- Changes made by process image paths ending in `redist.exe`
- Changes made by `msiexec.exe`
- Changes made by `TrustedInstaller.exe`
- Changes to files containing `\NVIDIA\NvBackend\ApplicationOntology\` in path

---
### [Event ID 3 - NetworkConnect](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-3-network-connection)
The configuration uses both inclusion-based and exclusion-based filtering.

Events that meet the criteria defined in the `<NetworkConnect onmatch="include">` block will be recorded unless the event also meets criteria defined in the `<NetworkConnect onmatch="exclude">` block.

The __include__ rules for this event capture the following:
- Connections made by processes where the image path begins with:
    - `C:\Users`
    - `C:\ProgramData`
    - `C:\Recycle`
    - `C:\Windows\Temp`
    - `\`
    - `C:\perflogs`
    - `C:\intel`
    - `C:\Windows\fonts`
    - `C:\Windows\system32\config`
- Connections made by the process images:
    - `at.exe`
    - `certutil.exe`
    - `cmd.exe`
    - `cmstp.exe`
    - `cscript.exe`
    - `driverquery.exe`
    - `dsquery.exe`
    - `hh.exe`
    - `infDefaultInstall.exe`
    - `java.exe`
    - `javaw.exe`
    - `javaws.exe`
    - `mmc.exe`
    - `msbuild.exe`
    - `mshta.exe`
    - `msiexec.exe`
    - `nbtstat.exe`
    - `net.exe`
    - `net1.exe`
    - `notepad.exe`
    - `nslookup.exe`
    - `powershell.exe`
    - `powershell_ise.exe`
    - `qprocess.exe`
    - `qwinsta.exe`
    - `reg.exe`
    - `regsvcs.exe`
    - `regsvr32.exe`
    - `rundll32.exe`
    - `rwinsta.exe`
    - `sc.exe`
    - `schtasks.exe`
    - `taskkill.exe`
    - `tasklist.exe`
    - `wmic.exe`
    - `wscript.exe`
    - `bitsadmin.exe`
    - `esentutl.exe`
    - `expand.exe`
    - `extrac32.exe`
    - `findstr.exe`
    - `GfxDownloadWrapper.exe`
    - `ieexec.exe`
    - `makecab.exe`
    - `replace.exe`
    - `Excel.exe`
    - `Powerpnt.exe`
    - `Winword.exe`
    - `squirrel.exe`
    - `nc.exe`
    - `ncat.exe`
    - `psexec.exe`
    - `psexesvc.exe`
    - `tor.exe`
    - `vnc.exe`
    - `vncservice.exe`
    - `vncviewer.exe`
    - `winexesvc.exe`
    - `nmap.exe`
    - `psinfo.exe`
- Connections to the ports:
    - `22` (SSH)
    - `23` (Telnet)
    - `25` (SMTP)
    - `143` (IMAP)
    - `3389` (RDP)
    - `5800` (VNC)
    - `5900` (VNC)
    - `4444` (Metasploit)
    - `1080` (Proxy)
    - `3128` (Proxy)
    - `8080` (Proxy)
    - `1723` (Tor)
    - `9001` (Tor)
    - `9030` (Tor)

The __exclude__ rules for this event define the following exclusions:
- Connections by processes where the image path begins with `C:\ProgramData\Microsoft\Windows Defender\Platform\`
- Connections by processes where the image path ends with `AppData\Local\Microsoft\Teams\current\Teams.exe`
- Connections where the destination hostname ends with:
    - `.microsoft.com`
    - `microsoft.com.akadns.net`
    - `microsoft.com.nsatc.net`
- Connections where the destination IP address is:
    - `23.4.43.27`
    - `72.21.91.29`
    - `127.0.0.1`
- Connections where the destination IP address begins with `fe80:0:0:0`

---
## [Event ID 5 - ProcessTerminate](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-5-process-terminated)
The configuration uses inclusion-based filtering.

The __include__ rules for this event capture the following:
- Processes where the image path begins with:
    - `C:\Users`
    - `\`

---
## [Event ID 6 - DriverLoad](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-6-driver-loaded)
The configuration uses exclusion-based filtering.

The __exclude__ rules for this event define the following exclusions:
- Signed binaries where the signature contains:
    - `microsoft`
    - `windows`
- Signed binaries where the signature begins with `Intel `

---
## [Event ID 8 - CreateRemoteThread](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread)
The configuration uses exclusion-based filtering.

The __exclude__ rules define the following exclusions:
- Remote thread creations where the source image is:
    - `C:\Windows\system32\wbem\WmiPrvSE.exe`
    - `C:\Windows\system32\svchost.exe`
    - `C:\Windows\system32\wininit.exe`
    - `C:\Windows\system32\csrss.exe`
    - `C:\Windows\system32\services.exe`
    - `C:\Windows\system32\winlogon.exe`
    - `C:\Windows\system32\audiodg.exe`
- Remote thread creations where the StartModule is `C:\Windows\system32\kernel32.dll`
- Remote thread creations where the target image is `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
