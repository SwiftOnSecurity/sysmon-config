# sysmon-config #

A Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.

Should serve as a great starting point to tune Sysmon for your environment - implement it on test systems and add entries to screen out uninteresting events. Should give you an idea of what's possible for Sysmon.

Pull requests are welcome, new additions will be credited in-line.

Note: Exact syntax and filtering choices are highly deliberate to catch appropriate entries and to have as little performance impact as possible. Sysmon's abilities are different than some built-in Windows auditing features, so some compromises have been made.

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
