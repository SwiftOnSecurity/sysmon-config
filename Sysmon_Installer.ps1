#Author: NerbalOne
#This PowerShell script will first create the Sysmon folder if it does not exist. It will then identify which OS architecture the endpoint is running and download the appropriate Sysmon version along with the Sysmon config and Sysmon Update script. It will then install Sysmon with the config and create a Scheduled Task to run hourly to update the Sysmon config.
#You may have issues while running this script on Windows Server 2012 R2 servers as it seems this server version only works with the Sysmon.exe and not the Sysmon64.exe with the newer Sysmon versions. 

# Define Sysmon URLs
$sysmon32URL = "https://live.sysinternals.com/sysmon.exe"
$sysmon64URL = "https://live.sysinternals.com/sysmon64.exe"
$sysmonConfigURL = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml"
$sysmonUpdateConfig = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/SysmonUpdateConfig.ps1"

# Define Local Path for Sysmon File and Sysmon Config
$sysmon32Path = "C:\Programdata\Sysmon\sysmon.exe"
$sysmon64Path = "C:\Programdata\Sysmon\sysmon64.exe"
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

# Check OS Architecture
$OSArchitecture = (Get-WmiObject -Query "Select * from Win32_OperatingSystem").OSArchitecture

# Download Sysmon Update Script
Invoke-WebRequest -Uri $sysmonUpdateConfig -OutFile $sysmonUpdatePath

# Download Sysmon Config
Invoke-WebRequest -Uri $sysmonConfigURL -OutFile $sysmonConfigPath

# Depending on the OS Architecture, Download and Install Sysmon
if ($OSArchitecture -eq "32-bit") {
    # Download Sysmon 32 bit
    Invoke-WebRequest -Uri $sysmon32URL -OutFile $sysmon32Path

    # Install Sysmon with Config
    Start-Process -FilePath $sysmon32Path -ArgumentList "-accepteula -i $sysmonConfigPath" -NoNewWindow -Wait

} elseif ($OSArchitecture -eq "64-bit") {
    # Download Sysmon 64 bit
    Invoke-WebRequest -Uri $sysmon64URL -OutFile $sysmon64Path

    # Install Sysmon with Config
    Start-Process -FilePath $sysmon64Path -ArgumentList "-accepteula -i $sysmonConfigPath" -NoNewWindow -Wait

} else {
    Write-Output "Unsupported architecture: $OSArchitecture"
}

# Create a New Scheduled Task
Start-Process schtasks.exe -ArgumentList '/Create /RU SYSTEM /RL HIGHEST /SC HOURLY /TN Update_Sysmon_Rules /TR "powershell.exe -ExecutionPolicy Bypass -File "C:\Programdata\Sysmon\SysmonUpdateConfig.ps1"" /f' -Wait -WindowStyle Hidden
Start-Process schtasks.exe -ArgumentList '/Run /TN Update_Sysmon_Rules' -Wait -WindowStyle Hidden

# Define Sysmon service Name Based on OS Architecture
$sysmonServiceName = if ($OSArchitecture -eq "64-bit") { "Sysmon64" } else { "Sysmon" }

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
