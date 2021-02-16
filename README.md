# sysmon-config | A Sysmon configuration file for everybody to fork #

This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.

The file should function as a great starting point for system change monitoring in a self-contained and accessible package. This configuration and results should give you a good idea of what's possible for Sysmon. Note that this does not track things like authentication and other Windows events that are also vital for incident investigation.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)**

Because virtually every line is commented and sections are marked with explanations, it should also function as a tutorial for Sysmon and a guide to critical monitoring areas in Windows systems.

- For a far more exhaustive and detailed approach to Sysmon configuration from a different approach, see also **[sysmon-modular](https://github.com/olafhartong/sysmon-modular)** by [@olafhartong](https://twitter.com/olafhartong), which can act as a superset of sysmon-config.

- Sysmon is a compliment to native Windows logging abilities, not a replacement for it. For valuable advice on these configurations, see **[MalwareArchaeology Logging Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)** by [@HackerHurricane](https://twitter.com/hackerhurricane).

Note: Exact syntax and filtering choices in the configuration are highly deliberate in what they target, and to have as little performance impact as possible. Sysmon's filtering abilities are different than the built-in Windows auditing features, so often a different approach is taken than the normal static listing of paths. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[See other forks of this configuration](https://github.com/SwiftOnSecurity/sysmon-config/network)**

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

## Required actions ##

### Prerequisites ###
Highly recommend using [Notepad++](https://notepad-plus-plus.org/) to edit this configuration. It understands UNIX newline format and does XML syntax highlighting, which makes this very understandable. I do not recommend using the built-in Notepad.exe.

### Customization ###
You will need to install and observe the results of the configuration in your own environment before deploying it widely. For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

The configuration is highly commented and designed to be self-explanatory to assist you in this customization to your environment.

### Design notes ###
This configuration expects software to be installed system-wide and NOT in the C:\Users folder. Various pieces of software install themselves in User directories, which are subject to extra monitoring. Where possible, you should install the system-wide version of these pieces of software, like Chrome. See the configuration file for more instructions.
