## Configuration Overview
---
### [Event ID 1 - ProcessCreate](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation)
The configuration uses exclusion-based filtering for ProcessCreate events.

All process creations are monitored except for those defined within the `<ProcessCreate onmatch="exclude">` block.

---
### [Event ID 2 - FileCreateTime (A process changed a file creation time)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-2-a-process-changed-a-file-creation-time)
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
### [Event ID 5 - ProcessTerminate](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-5-process-terminated)
The configuration uses inclusion-based filtering.

The __include__ rules for this event capture the following:
- Processes where the image path begins with:
    - `C:\Users`
    - `\`

---
### [Event ID 6 - DriverLoad](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-6-driver-loaded)
The configuration uses exclusion-based filtering.

The __exclude__ rules for this event define the following exclusions:
- Signed binaries where the signature contains:
    - `microsoft`
    - `windows`
- Signed binaries where the signature begins with `Intel `

---
### [Event ID 8 - CreateRemoteThread](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread)
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

---
### [Event ID 10 - ProcessAccess](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess)
The configuration defines a `<ProcessAccess onmatch="include">` block with no rules.

Using "include" with no rules means nothing in this section will be logged.

---
### [Event ID 11 - File Create](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate)
The configuration uses both inclusion-based and exclusion-based filtering.

The __include__ rules for this event capture the following:
- File creations where the TargetFileName contains:
    - `\Start Menu`
    - `\Startup\`
    - `\Content.Outlook\`
    - `\Downloads\`
    - `VirtualStore`
- File creations where the TargetFileName ends with:
    - `.application`
    - `.appref-ms`
    - `.bat`
    - `.chm`
    - `.cmd`
    - `.cmdline`
    - `.crx`
    - `.dmp`
    - `.docm`
    - `.dll`
    - `.exe`
    - `.exe.log`
    - `.jar`
    - `.jnlp`
    - `.jse`
    - `.hta`
    - `.job`
    - `.pptm`
    - `.ps1`
    - `.sct`
    - `.sys`
    - `.scr`
    - `.vbe`
    - `.vbs`
    - `.wsc`
    - `.wsf`
    - `.xlsm`
    - `.ocx`
    - `proj`
    - `.sln`
    - `.xls`
    - `.ppt`
    - `.rtf`
- File creations where the TargetFileName begins with:
    - `C:\Users\Default`
    - `C:\Windows\system32\Drivers`
    - `C:\Windows\SysWOW64\Drivers`
    - `C:\Windows\system32\GroupPolicy\Machine\Scripts`
    - `C:\Windows\system32\GroupPolicy\User\Scripts`
    - `C:\Windows\system32\Wbem`
    - `C:\Windows\SysWOW64\Wbem`
    - `C:\Windows\system32\WindowsPowerShell`
    - `C:\Windows\SysWOW64\WindowsPowerShell`
    - `C:\Windows\Tasks\`
    - `C:\Windows\system32\Tasks`
    - `C:\Windows\SysWOW64\Tasks`
    - `\Device\HarddiskVolumeShadowCopy`
    - `C:\Windows\AppPatch\Custom`

The __exclude__ rules define the following exclusions:
- File creations by the process image:
    - `C:\Program Files (x86)\EMET 5.5\EMET_Service.exe`
    - `C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe`
    - `C:\Windows\system32\smss.exe`
    - `C:\Windows\system32\CompatTelRunner.exe`
    - `\\?\C:\Windows\system32\wbem\WMIADAP.EXE`
    - `C:\Windows\system32\mobsync.exe`
- File creations where the process image begins with `C:\Windows\winsxs\amd64_microsoft-windows`
- File creations where the TargetFileName begins with:
    - `C:\Windows\system32\DriverStore\Temp\`
    - `C:\Windows\system32\wbem\Performance\`
    - `C:\Windows\Installer\`
    - `C:\$WINDOWS.~BT\Sources\`

---
### [Event ID 12 - RegistryEvent (Object create and delete)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-12-registryevent-object-create-and-delete)
### [Event ID 13 - RegistryEvent (Value set)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-13-registryevent-value-set)
### [Event ID 14 - RegistryEvent (Key and Value Rename)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-14-registryevent-key-and-value-rename)
The `<RegistryEvent>` blocks define the rules for the generation of event IDs 12, 13, and 14.

The configuration uses both inclusion-based and exclusion-based filtering.

The __include__ rules capture the following:
- Registry changes where the TargetObject contains:
    - `CurrentVersion\Run`
    - `Policies\Explorer\Run`
    - `Group Policy\Scripts`
    - `Windows\System\Scripts`
    - `CurrentVersion\Windows\Load`
    - `CurrentVersion\Windows\Run`
    - `CurrentVersion\Winlogon\Shell`
    - `CurrentVersion\Winlogon\System`
    - `UserInitMprLogonScript`
    - `\command\`
    - `\ddeexec\`
    - `{86C86720-42A0-1069-A2E8-08002B30309D}`
    - `exefile`
    - `Classes\*\`
    - `Classes\AllFilesystemObjects\`
    - `Classes\Directory\`
    - `Classes\Drive\`
    - `Classes\Folder\`
    - `Classes\PROTOCOLS\`
    - `ContextMenuHandlers\`
    - `CurrentVersion\Shell`
    - `Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable`
    - `Microsoft\Office\Outlook\Addins\`
    - `Office Test\`
    - `Security\Trusted Documents\TrustRecords`
    - `Internet Explorer\Toolbar\`
    - `Internet Explorer\Extensions\`
    - `Browser Helper Objects\`
    - `\Keyboard Layout\Preload`
    - `\Keyboard Layout\Substitutes`
    - `Compatibility Assistant\Store\`
- Registry changes where the TargetObject begins with:
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
    - `HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellServiceObjectDelayLoad`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellIconOverlayIdentifiers`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\`
    - `HKLM\SYSTEM\CurrentControlSet\Services\WinSock`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\`
    - `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders`
    - `HKLM\Software\Microsoft\Netsh`
    - `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order\`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
    - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List`
    - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\`
    - `HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls\`
    - `HKLM\Software\Classes\CLSID\{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}\`
    - `HKLM\Software\Classes\WOW6432Node\CLSID\{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}\`
    - `HKLM\Software\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\`
    - `HKLM\Software\Classes\WOW6432Node\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\`
    - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Winlogon\`
    - `HKLM\Software\Microsoft\Tracing\RASAPI32`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\`
- Registry changes where the TargetObject ends with:
    - `user shell folders\startup`
    - `\ServiceDll`
    - `\ServiceManifest`
    - `\ImagePath`
    - `\Start`
    - `Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`
    - `Control\Terminal Server\fSingleSessionPerUser`
    - `fDenyTSConnections`
    - `LastLoggedOnUser`
    - `RDP-tcp\PortNumber`
    - `Services\PortProxy\v4tov4`
    - `\InprocServer32\(Default)`
    - `\Hidden`
    - `\ShowSuperHidden`
    - `\HideFileExt`
    - `\ProxyServer`
    - `\EnableFirewall`
    - `\DoNotAllowExceptions`
    - `\EnableBHO`
    - `\DisableSecuritySettingsCheck`
    - `\3\1206`
    - `\3\2500`
    - `\3\1809`
    - `\UrlUpdateInfo`
    - `\InstallSource`
    - `\EulaAccepted`
    - `\DisableAntiSpyware`
    - `\DisableAntiVirus`
    - `\SpynetReporting`
    - `DisableRealtimeMonitoring`
    - `\SubmitSamplesConsent`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`
    - `HKLM\Software\Microsoft\Security Center\`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAHealth`
    - `\FriendlyName`
    - `\LowerCaseLongPath`
    - `\Publisher`
    - `\BinProductVersion`
    - `\DriverVersion`
    - `\DriverVerVersion`
    - `\LinkDate`
- Registry changes where the TargetObject is `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\InProgress\(Default)`
- Registry changes by process image ending with `regedit.exe`
- Registry changes by process image beginning with `\`

The __exclude__ rules define the following exclusions:
- Registry changes where the TargetObject contains:
    - `\{CAFEEFAC-`
    - `\Control\WMI\Autologger\`
    - `_Classes\AppX`
    - `VirtualStore\MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\`
- Registry changes where the TargetObject begins with:
    - `HKLM\COMPONENTS`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\`
    - `HKLM\SOFTWARE\Microsoft\Office\ClickToRun\`
    - `HKCR\VLC.`
    - `HKCR\iTunes.`
- Registry changes where the TargetObject ends with:
    - `Toolbar\WebBrowser`
    - `Browser\ITBar7Height`
    - `Browser\ITBar7Layout`
    - `Internet Explorer\Toolbar\Locked`
    - `Toolbar\WebBrowser\{47833539-D0C5-4125-9FA8-0819E2EAAC93}`
    - `}\PreviousPolicyAreas`
    - `HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc\Start`
    - `\Lsa\OfflineJoin\CurrentValue`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaPid`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SspiCache`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains`
    - `\Services\BITS\Start`
    - `\services\clr_optimization_v2.0.50727_32\Start`
    - `\services\clr_optimization_v2.0.50727_64\Start`
    - `\services\clr_optimization_v4.0.30319_32\Start`
    - `\services\clr_optimization_v4.0.30319_64\Start`
    - `\services\deviceAssociationService\Start`
    - `\services\fhsvc\Start`
    - `\services\nal\Start`
    - `\services\trustedInstaller\Start`
    - `\services\tunnel\Start`
    - `\services\usoSvc\Start`
    - `\UserChoice\ProgId`
    - `\UserChoice\Hash`
    - `\OpenWithList\MRUList`
    - `HKLM\System\CurrentControlSet\Control\Lsa\Audit\SpecialGroups`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\PSScriptOrder`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\SOM-ID`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\GPO-ID`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0\IsPowershell`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0\ExecTime`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\PSScriptOrder`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\SOM-ID`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\GPO-ID`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\0\IsPowershell`
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\0\ExecTime`
- Registry changes where the TargetObject is `HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{945a8954-c147-4acd-923f-40c45405a658}`
- Registry changes where the EventType is `CreateKey`
- Registry changes where the process image is `C:\Program Files\WIDCOMM\Bluetooth Software\btwdins.exe`

---
### [Event ID 15 - FileCreateStreamHash](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-15-filecreatestreamhash)
The configuration uses inclusion-based filtering.

The __include__ rules capture the following:
- File streams created where the TargetFileName contains:
    - `Downloads`
    - `Temp\7z`
    - `Startup`
- File streams created where the TargetFileName ends with:
    - `.bat`
    - `.cmd`
    - `.doc`
    - `.hta`
    - `.jse`
    - `.lnk`
    - `.ppt`
    - `.ps1`
    - `.ps2`
    - `.reg`
    - `.sct`
    - `.vb`
    - `.vbe`
    - `.vbs`
    - `.wsc`
    - `.wsf`

---
### [Event ID 17 - PipeEvent (Pipe Created)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-17-pipeevent-pipe-created)
### [Event ID 18 - PipeEvent (Pipe Connected)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-18-pipeevent-pipe-connected)
The `<PipeEvent>` blocks define the rules for the generation of event IDs 17 and 18.

The configuration uses inclusion-based filtering.

The __include__ rules capture the following:
- Pipe events where the PipeName contains:
    - `paexec`
    - `remcom`
    - `csexec`
    - `\lsadump`
    - `\cachedump`
    - `\wceservicepipe`
    - `\isapi_http`
    - `\isapi_dg`
    - `\isapi_dg2`
    - `\sdlrpc`
    - `\ahexec`
    - `\winsession`
    - `\lsassw`
    - `\46a676ab7f179e511e30dd2dc41bd388`
    - `\9f81f59bc58452127884ce513865ed20`
    - `\e710f28d59aa529d6792ca6ff0ca1b34`
    - `\rpchlp_3`
    - `\NamePipe_MoreWindows`
    - `\pcheap_reuse`
    - `\gruntsvc`
    - `\583da945-62af-10e8-4902-a8f205c72b2e`
    - `\bizkaz`
    - `\svcctl`
    - `\Posh`
    - `\jaccdpqnvbrrxlaf`
    - `\csexecsvc`
    - `MSSE-` and `-server`
- Pipe events where the PipeName begins with:
    - `\postex_`
    - `\postex_ssh_`
    - `\status_`
    - `\msagent_`

---
### [Event ID 19 - WmiEvent (WmiEventFilter activity detected)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-19-wmievent-wmieventfilter-activity-detected)
### [Event ID 20 - WmiEvent (WmiEventConsumer activity detected)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-20-wmievent-wmieventconsumer-activity-detected)
### [Event ID 21 - WmiEvent (WmiEventConsumerToFilter activity detected)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-21-wmievent-wmieventconsumertofilter-activity-detected)
The `<WmiEvent>` blocks define the rules for the generation of event IDs 19, 20, and 21.

The configuration defines a `<WmiEvent onmatch="exclude">` block with no rules.

Using exclude with no rules means everything will be logged.

---
### [Event ID 22 - DNSEvent (DNS query)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query)
The configuration uses exclusion-based filtering.

The __exclude__ rules define the following exclusions:
- Queries by process image beginning with `C:\ProgramData\Microsoft\Windows Defender\Platform\`
- Queries where the QueryName is:
    - `..localmachine`
    - `localhost`
    - `login.windows.net`
    - `acdc-direct.office.com`
    - `atm-fp-direct.office.com`
    - `loki.delve.office.com`
    - `management.azure.com`
    - `messaging.office.com`
    - `outlook.office365.com`
    - `portal.azure.com`
    - `protection.outlook.com`
    - `substrate.office.com`
    - `clients1.google.com`
    - `clients2.google.com`
    - `clients3.google.com`
    - `clients4.google.com`
    - `clients5.google.com`
    - `clients6.google.com`
    - `safebrowsing.googleapis.com`
    - `ajax.googleapis.com`
    - `cdnjs.cloudflare.com`
    - `play.google.com`
    - `content-autofill.googleapis.com`
    - `disqus.com`
    - `1rx.io`
    - `adservice.google.com`
    - `ampcid.google.com`
    - `clientservices.googleapis.com`
    - `googleadapis.l.google.com`
    - `imasdk.googleapis.com`
    - `l.google.com`
    - `ml314.com`
    - `mtalk.google.com`
    - `update.googleapis.com`
    - `www.googletagservices.com`
    - `msocsp.com`
    - `ocsp.comodoca.com` (Duplicate entry on line 1134)
    - `ocsp.entrust.net` (Duplicate entry on line 1136)
    - `ocsp.godaddy.com` (Duplicate entry on line 1129)
    - `ocsp.int-x3.letsencrypt.org` (Duplicate entry on line 1140)
    - `ocsp.msocsp.com`
    - `ocsp.sectigo.com`
    - `pki-goog.l.google.com`
    - `ocsp.verisign.com`
    - `status.rapidssl.com`
    - `status.thawte.com`
- Queries where the QueryName ends with:
    - `.arpa.`
    - `.arpa`
    - `.msftncsi.com`
    - `-pushp.svc.ms`
    - `.b-msedge.net`
    - `.bing.com`
    - `.hotmail.com`
    - `.live.com`
    - `.live.net`
    - `.s-microsoft.com`
    - `.microsoft.com`
    - `.microsoftonline.com`
    - `.microsoftstore.com`
    - `.ms-acdc.office.com`
    - `.msedge.net`
    - `.msn.com`
    - `.msocdn.com`
    - `.skype.com`
    - `.skype.net`
    - `.windows.com`
    - `.windows.net.nsatc.net`
    - `.windowsupdate.com`
    - `.xboxlive.com`
    - `.activedirectory.windowsazure.com`
    - `.aria.microsoft.com`
    - `.msauth.net`
    - `.msftauth.net`
    - `.office.net`
    - `.opinsights.azure.com`
    - `.res.office365.com`
    - `.adobe.com`
    - `.adobe.io`
    - `.mozaws.net`
    - `.mozilla.com`
    - `.mozilla.net`
    - `.mozilla.org`
    - `.spotify.com`
    - `.spotify.map.fastly.net`
    - `.wbx2.com`
    - `.webex.com`
    - `.akadns.net`
    - `.netflix.com`
    - `aspnetcdn.com`
    - `.typekit.net`
    - `.stackassets.com`
    - `.steamcontent.com`
    - `.disqus.com`
    - `.fontawesome.com`
    - `.1rx.io`
    - `.2mdn.net`
    - `.3lift.com`
    - `.adadvisor.net`
    - `.adap.tv`
    - `.addthis.com`
    - `.adform.net`
    - `.adnxs.com`
    - `.adroll.com`
    - `.adrta.com`
    - `.adsafeprotected.com`
    - `.adsrvr.org`
    - `.adsymptotic.com`
    - `.advertising.com`
    - `.agkn.com`
    - `.amazon-adsystem.com` (Duplicate entry on line 1022)
    - `.analytics.yahoo.com`
    - `.aol.com`
    - `.betrad.com`
    - `.bidswitch.net`
    - `.casalemedia.com`
    - `.chartbeat.net`
    - `.cnn.com`
    - `.convertro.com`
    - `.criteo.com`
    - `.criteo.net`
    - `.crwdcntrl.net`
    - `.demdex.net`
    - `.domdex.com`
    - `.dotomi.com`
    - `.doubleclick.net`
    - `.doubleverify.com`
    - `.emxdgt.com`
    - `.everesttech.net`
    - `.exelator.com`
    - `.google-analytics.com`
    - `.googleadservices.com`
    - `.googlesyndication.com`
    - `.googletagmanager.com`
    - `.googlevideo.com`
    - `.gstatic.com`
    - `.gvt1.com`
    - `.gvt2.com`
    - `.ib-ibi.com`
    - `.jivox.com`
    - `.krxd.net`
    - `.lijit.com`
    - `.mathtag.com`
    - `.moatads.com`
    - `.moatpixel.com`
    - `.mookie1.com`
    - `.myvisualiq.net`
    - `.netmng.com`
    - `.nexac.com`
    - `.openx.net`
    - `.optimizely.com`
    - `.outbrain.com`
    - `.pardot.com`
    - `.phx.gbl`
    - `.pinterest.com`
    - `.pubmatic.com`
    - `.quantcount.com`
    - `.quantserve.com`
    - `.revsci.net`
    - `.rfihub.net`
    - `.rlcdn.com`
    - `.rubiconproject.com`
    - `.scdn.co`
    - `.scorecardresearch.com`
    - `.serving-sys.com`
    - `.sharethrough.com`
    - `.simpli.fi`
    - `.sitescout.com`
    - `.smartadserver.com`
    - `.snapads.com`
    - `.spotxchange.com`
    - `.taboola.com`
    - `.taboola.map.fastly.net`
    - `.tapad.com`
    - `.tidaltv.com`
    - `.trafficmanager.net`
    - `.tremorhub.com`
    - `.tribalfusion.com`
    - `.turn.com`
    - `.twimg.com`
    - `.tynt.com`
    - `.w55c.net`
    - `.ytimg.com`
    - `.zorosrv.com`
    - `.pscp.tv`
    - `.amazontrust.com` (Duplicate entry on line 1130)
    - `.digicert.com`
    - `.globalsign.com`
    - `.globalsign.net`
    - `.intel.com`
    - `.symcb.com`
    - `.symcd.com`
    - `.thawte.com`
    - `.usertrust.com` (Duplicate entry on line 1133)
    - `.verisign.com`
    - `ocsp.identrust.com` (Duplicate entry on line 1137)
    - `pki.goog` (Duplicate entry on line 1128)
