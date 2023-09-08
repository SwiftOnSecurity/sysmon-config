#Author: NerbalOne
#This PowerShell script will first create the Sysmon folder if it does not exist. It will then download Sysmon.exe, which supports both 32 bit and 64 bit, along with the Sysmon config and Sysmon Update script. It will then install Sysmon with the config and create a Scheduled Task to run hourly to update the Sysmon config.

# Define Sysmon URLs
$sysmonURL = "https://live.sysinternals.com/sysmon.exe"
$sysmonConfigURL = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml"
$sysmonUpdateConfig = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/SysmonUpdateConfig.ps1"

# Define Local Path for Sysmon File and Sysmon Config
$sysmonPath = "C:\Programdata\Sysmon\sysmon.exe"
$sysmonConfigPath = "C:\Programdata\Sysmon\sysmonconfig-export.xml"
$sysmonUpdatePath = "C:\Programdata\Sysmon\SysmonUpdateConfig.ps1"
$sysmonFolderPath = "C:\ProgramData\Sysmon\"

# Create Sysmon Folder if it Doesn't Exist
if (-not (Test-Path $sysmonFolderPath)) {
    # Create the Folder
    try {
        New-Item -ItemType Directory -Path $sysmonFolderPath -Force
        Write-Host "Folder created successfully at $folderPath"
    }
    catch {
        Write-Host "Error creating the folder: $_"
    }
}
else {
    Write-Host "The folder already exists at $folderPath"
}

# Download Sysmon, Config, and Update Script
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sysmonURL -OutFile $sysmonPath
Invoke-WebRequest -Uri $sysmonConfigURL -OutFile $sysmonConfigPath
Invoke-WebRequest -Uri $sysmonUpdateConfig -OutFile $sysmonUpdatePath

# Install Sysmon with Config
Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i $sysmonConfigPath" -NoNewWindow -Wait

# Create a New Scheduled Task
Start-Process schtasks.exe -ArgumentList '/Create /RU SYSTEM /RL HIGHEST /SC HOURLY /TN Update_Sysmon_Rules /TR "powershell.exe -ExecutionPolicy Bypass -File "C:\Programdata\Sysmon\SysmonUpdateConfig.ps1"" /f' -Wait -WindowStyle Hidden
Start-Process schtasks.exe -ArgumentList '/Run /TN Update_Sysmon_Rules' -Wait -WindowStyle Hidden

# Define Sysmon service Name
$sysmonServiceName = "Sysmon"

# Check if Sysmon Service Exists
try {
    $service = Get-Service -Name $sysmonServiceName -ErrorAction Stop
    Write-Output "Sysmon service exists"
} catch {
    Throw "Sysmon service does not exist"
}

# Check if Scheduled Task is Created Successfully
try {
    $task = Get-ScheduledTask -TaskName "Update_Sysmon_Rules" -ErrorAction Stop
    Write-Output "Scheduled task created successfully"
} catch {
    Throw "Scheduled task creation failed"
}
