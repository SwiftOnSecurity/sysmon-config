#Author: NerbalOne
#This PowerShell script will first download the latest Sysmon config. Then it will apply this config to Sysmon.

# Define Sysmon Path
$sysmonPath = "C:\ProgramData\Sysmon\sysmon.exe"
$sysmonConfigPath = "C:\ProgramData\Sysmon\sysmonconfig-export.xml"

# Define Sysmon Config URL
$sysmonConfigURL = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml"

# Download the Latest Sysmon Config
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sysmonConfigURL -OutFile $sysmonConfigPath

# Run sysmon.exe with Config
& $sysmonPath -c $sysmonConfigPath

# Check the Exit Code of the Previous Command
if ($LASTEXITCODE -eq 0) {
    Write-Output "Sysmon executed successfully."
} else {
    Write-Output "Sysmon execution failed."
}

