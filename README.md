# sysmon-config 

Credits to SwiftOnSecurity and ion-storm for providing the base fork of this config. Incremental changes have been made to meet my specific needs. Feel free to use or send a pull request.

## Use ##

### Auto-Install with Auto Update Script:###
Run with administrator rights
~~~~
install_sysmon.bat
~~~~

### Uninstall ###
Run with administrator rights
~~~~
sysmon.exe -u
~~~~

### Event Log Location ###
All sysmon events are written to
~~~~
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
~~~~
