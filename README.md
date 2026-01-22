# sysmon-config | A Sysmon configuration file

This is a forked and modified version of @SwiftOnSecurity's [sysmon config](https://github.com/SwiftOnSecurity/sysmon-config).

It started as a is simply copy of the original repository. We merged most of the 30+ open pull requests. Thus we have fixed many of the issues that are still present in the original version and extended the coverage with important new extensions.

## Maintainers of this Fork

- Florian Roth @Neo23x0
- Tobias Michalski @humpalum
- Christian Burkard @phantinuss
- Nasreddine Bencherchali @nas_bench

## Additional coverage includes

- Cobalt Strike named pipes
- PrinterNightmare
- HiveNightmare

## Configs in this Repository

This repo includes the original and two additional configurations

- `sysmonconfig-export.xml` the original config provided by @SwiftOnSecurity
- `sysmonconfig-export-block.xml` the original config provided by @SwiftOnSecurity with some basic blocking rules usable since Sysmon v14 (WARNING: use it with care!)
- `sysmonconfig-trace.xml` a config by @Cyb3rWard0g that logs just everything with a few examples for debugging or threat research purposes

## Other Sysmon Configs

- Olaf Hartong's [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) - modular Sysmon config for easier maintenance and generation of specific configs

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

## Credits

Since we wanted to be able to receive new pull requests this repository, we had to squash all open(!) pull requests of the original reposiory into a single commit on this one.

We've pull the following requests:

Registry key to detect definitions of Windows Defender Exclusions\
155 opened 12 days ago by @phantinuss

Outlook Webview URL changes\
154 opened on 14 Jun by @humpalum

Event id 26\
153 opened on 14 Jun by @Richman711

Important and relevant NamedPipe names\
151 opened on 27 May by @Neo23x0

Added named pipe used by @Cobalt Strike\
150 opened on 26 May by @WojciechLesicki

Fix FileDelete example.\
149 opened on 26 May by @sigalpes

Add exclusion for WUDFHost.exe to Event 11\
148 opened on 19 Apr by @lord-garmadon

Corrected event name for Event ID 23\
147 opened on 16 Apr by @lord-garmadon

Monitor for .js files for Microsoft JScript\
146 opened on 7 Apr by @KevinDeNotariis

Added WinRM ports and Service names\
145 opened on 16 Mar by @tobor88

Add ASP files for webshells\
144 opened on 8 Mar by @GossiTheDog

Update NetworkConnect rule to fix Metasploit default port\
143 opened on 6 Mar by @brokenvhs

Ransomware artifacts added to File Creation config\
140 opened on 18 Feb by @sduff

MiniNT registry key check\
130 opened on 9 Sep 2020 by @ThisIsNotTheUserYouAreLookingFor

Added detection for CVE-2017-0199 and CVE-2017-8759.\
118 opened on 21 May 2020 by @d4rk-d4nph3

Printer port changes as used in CVE-2020-1048\
115 opened on 15 May 2020 by @Neo23x0

Update sysmonconfig-export.xml\
108 opened on 1 Mar 2020 by @harmonkc

Changed the bypassable DNS hostname checks\
107 opened on 5 Feb 2020 by @MaxNad

Added most of the missing LOLBAS for downloading executables\
106 opened on 5 Feb 2020 by @MaxNad

Change Metasploit Alert port from 444 to 4444\
105 opened on 5 Feb 2020 by @ION28

Add exclusion for Azure MMA agent | Add exclusion for IPAM GP PS script | Add exclusion for MonitorKnowledgeDiscovery\
104 opened on 29 Jan 2020 by @adrwh

Fixed wdigest registry path\
102 opened on 13 Dec 2019 by @qz8xTD

unnecessary shout out to Alpha version for DNS logging\
100 opened on 10 Dec 2019 by @itpropaul

Add scripting filename targets\
98 opened on 14 Nov 2019 by @bartblaze

Included some of the entries from PR to sysmonconfig-export.xml\
97 opened on 6 Nov 2019 by @cudeso

Keyboard Layout Load\
92 opened on 13 Oct 2019 by @Neo23x0

Fixed IMAP port\
71 opened on 12 Jan 2019 by @esecrpm
66 opened on 21 Aug 2018 by @martboo
59 opened on 25 May 2018 by @paalbra

Micro-improvements to monitored scenarios\
53 opened on 6 Mar 2018 by @threathunting

Corrected typo for RTF extension\
50 opened on 24 Jan 2018 by @kronflux

Add Windows Trust registry keys to log\
40 opened on 4 Oct 2017 by @mdunten
