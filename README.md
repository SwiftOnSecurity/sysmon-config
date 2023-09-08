# Sysmon ATT&CK Configuration #
The file provided should function as a great starting point for system monitoring in a self-contained package. This configuration and results should give you a good idea of what's possible for Sysmon. Please beware that you may need to fine tune and add exclusions depending on your environment. High CPU usage may be seen if exclusions are not added and one or more rules are firing off multiple times every second. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[sysmonconfig-export.xml](https://github.com/NerbalOne/sysmon-config/blob/master/sysmonconfig-export.xml)**

Pull requests and issue tickets are welcomed. Any new additions will be credited in-line or on Git. Tag your name with Author=YourName within the rulename field.

This Sysmon ATT&CK Configuration is designed "Explicitly" to enrich your SIEM for threat intelligence, forensics, and UEBA use cases. You'll want to create a key-value parser for the
rulename field to create field names per event within your SIEM.  
Ideally this is best used with an Alerting Repository/Index where the "Alert=" field is marked and a non-alerting visibility index/repository where threat hunting and investigations can be done 
that contains added context and story line information of user behavior and activity leading up to an attack. Non-Alerting visibility rules are tagged with "Desc=" and "Forensic=" and are
meant to provide contextual information for analysts to build cases and identify what is happening with SIEM enrichments. Some of these non-alerting visibility rules can be graduated 
to the Alerting rules or can be used with correlation rules within a SIEM/SOAR/XDR.  

The goal with this configuration is a "Control" configuration that provides ultimate visibility that should be ran in conjunction with an EDR.  
As we know, allot of EDR's today provide little contextual information, forensic information that is tagged, categorized, risk rated, and some alerts EDR vendors choose to not alert
on due to the differences between each environment and how hard it is to baseline some detections. There is many use cases where EDR's fall short. They are not the greatest at 
identifying suspicious activity that may fall short of being labeled as malicious. The goal here is to detect all common user activity that would lead to exfiltration, infiltration, 
malware, malicious activity, and questionable activity. If a user is poking around the registry, sending data to cloud storage, downloading and executing random attachments and files, and/or
copying files, we want to know. We also want to leave an audit trail by monitoring the registry, artifact locations, and provide our forensic analysts as much detail as possible.

If you have forensic registry keys, file locations, artifacts, behavior detections, and anything that may be beneficial here, feel free to put in a pull request.  
The goal here is as much visibility as possible with accurate alerts that are not noisy.  


This now has an Auto Updater script to update to the latest Sysmon config hourly.  This is great for mass deployments without having to manually update thousands of systems.

## Use ##

### Auto-Install with Auto Update Script:###
The two below PowerShell scripts that are contained in this repo will download and install Sysmon and the config along with creating a scheduled task to run hourly to update the config.
~~~~
Sysmon Install.ps1
SysmonUpdateConfig.ps1
~~~~

### Install ###
Run with administrator rights.
~~~~
sysmon.exe -accepteula -i sysmonconfig-export.xml
~~~~

### Update Existing Configuration ###
Run with administrator rights.
~~~~
sysmon.exe -c sysmonconfig-export.xml
~~~~

### Uninstall ###
Run with administrator rights.
~~~~
sysmon.exe -u
~~~~

## Hide Sysmon from services.msc ##
~~~~
Hide:
sc sdset Sysmon D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
Restore:
sc sdset Sysmon D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
