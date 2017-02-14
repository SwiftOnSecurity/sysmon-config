# sysmon-config | A Sysmon configuration file for everybody #

This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.

Should serve as a great starting point to tune Sysmon for your environment - implement it on test systems and add entries to screen out uninteresting events. Should give you an idea of what's possible for Sysmon. It demonstrates a lot of what I wish I knew when I began in 2014.

Because virtually every line is commented and sections are marked with explanations, it should also function as a tutorial for Sysmon and a guide to critical monitoring areas in Windows systems.

Pull requests are welcome, new additions will be credited in-line or on Git.

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
