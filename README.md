# sysmon-config | A Sysmon configuration file

This is a forked and modified version of @SwiftOnSecurity's [sysmon config](https://github.com/SwiftOnSecurity/sysmon-config).

Currently it is simply a copy with most of the 30+ open pull requests of the original repository merged. Thus we have fixed many of the issues that are still present in the original version and extended the coverage by important new extensions that have been provided over the last year.

## Testing

This configuration is focused on detection coverage. We have only one rather small testing environment to avoid problematic expressions that trigger too often. It is recommended to test the downloaded configuration on a small set of systems in your environment in any case. 

## Feedback

Since we don't have more than one environment to test the config ourselves, we rely on feedback from the community.

Please report:

1. Expressions that cause a high volume of events
2. Broken configuration elements (typos, wrong conditions)
3. Missing coverage (preferrably as a pull request)

## Usage

### Install

Run with administrator rights

```batch
sysmon.exe -accepteula -i sysmonconfig-export.xml
```

### Update existing configuration

Run with administrator rights

```batch
sysmon.exe -c sysmonconfig-export.xml
```

### Uninstall

Run with administrator rights

```batch
sysmon.exe -u
```
