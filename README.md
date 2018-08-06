# sysmon-config-cryptomining #

This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing modified to specifically track XMR mining software.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[config-cryptocurrency.xml](https://github.com/ryanku98/sysmon-configs/blob/master/config-cryptocurrency.xml)**

Pull requests and issue tickets are welcome, and new additions will be credited in-line or on Git.

Note: Exact syntax and filtering choices are deliberate to catch appropriate entries and to have as little performance impact as possible. Sysmon's filtering abilities are different than the built-in Windows auditing features, so often a different approach is taken than the normal static listing of every possible important area.

## Use ##
### Install ###
Run with administrator rights
~~~~
sysmon -accepteula -i
~~~~

### Update existing configuration ###
Run with administrator rights
~~~~
sysmon -c C:\[Path]\[To]\[File]\config-cryptocurrency.xml
~~~~

### Uninstall ###
Run with administrator rights
~~~~
sysmon -u
~~~~

## Required actions ##
### Customization ###
You will need to install and observe the results of the configuration in your own environment before deploying it widely. For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

### Design notes ###
This configuration expects software to be installed system-wide and NOT in the C:\Users folder.

If your users install Chrome themselves, you should deploy the [Chrome MSI](https://enterprise.google.com/chrome/chrome-browser/), which will automatically change the shortcuts to the machine-level installation. Your users will not even notice anything different.
