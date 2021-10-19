# sysmon-config | A ransomware focused Sysmon configuration file #

This is a Microsoft Sysinternals Sysmon configuration file template with
default high-quality event tracing. This is a fork of
[SwiftOnSecurity](https://twitter.com/SwiftOnSecurity/)'s awesome
[sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), with an
additional focus on ransomware artifacts.

## Reasoning ##

Ransomware commonly encrypt documents and other files, often renaming them with
deterministic file names and extensions in the process. In addition, they
create instructions in the forms of text files, images or executables detailing
how to restore these files (often in the form of payment). Monitoring for files
that match these ransomware artifacts may provide security teams with early
warnings of a ransomware outbreak.

It is strongly suggested that you configure your SIEM or alerting system when
there is a large number of Sysmon Event Code 11 (File Creation or Overwrites)
events that match file names or extensions commonly associated with ransomware.

**N.B.** There are some ransomware variants that do not rename file extensions,
or use completely random extensions, which will not be detected by this
Sysmon configuration. Use your judgment, apply appropriate Anti-Virus and
other controls, practice defense-in-depth.

## Use ##
### Install ###
Run with administrator rights
~~~~
sysmon.exe -accepteula -i sysmonconfig-export.xml
~~~~

### Update existing configuration ###
Run with administrator rights
~~~~
sysmon.exe -c sysmonconfig-export.xml
~~~~

### Uninstall ###
Run with administrator rights
~~~~
sysmon.exe -u
~~~~

## Thanks ##

Thanks to [SwiftOnSecurity](https://twitter.com/SwiftOnSecurity/) for their well
documented Sysmon configuration, and mark Russinovich and Thomas Garnier for
developing Sysmon.
