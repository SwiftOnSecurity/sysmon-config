# sysmon-config | A Sysmon configuration file for everybody to fork #

This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.

The file provided should function as a great starting point for system monitoring in a self-contained package. This configuration and results should give you a good idea of what's possible for Sysmon.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)**

Because virtually every line is commented and sections are marked with explanations, it should also function as a tutorial for Sysmon and a guide to critical monitoring areas in Windows systems.

Pull requests and issue tickets are welcome, and new additions will be credited in-line or on Git.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[See active forks of this configuration](https://github.com/SwiftOnSecurity/sysmon-config/network)**

Note: Exact syntax and filtering choices are deliberate to catch appropriate entries and to have as little performance impact as possible. Sysmon's filtering abilities are different than the built-in Windows auditing features, so often a different approach is taken than the normal static listing of every possible important area.

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
