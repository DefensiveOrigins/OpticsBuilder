# Optics Builder 23JAN21

############
# DC FIRST #
############

# Some housekeeping, limit progress bar, enable support for TLS in PowerShell

$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


# C:\Labs should exist, start there

cd c:\labs



# Acquire packages

Invoke-WebRequest –URI https://download.sysinternals.com/files/Sysmon.zip -OutFile “Sysmon.zip” 
Invoke-WebRequest –URI https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.10.2-windows-x86_64.zip -OutFile “WinLogBeat.zip” 
Invoke-WebRequest –URI https://github.com/olafhartong/sysmon-modular/archive/master.zip -OutFile “sysmon-modular.zip” 
Invoke-WebRequest –URI https://github.com/palantir/windows-event-forwarding/archive/master.zip -OutFile “palantir.zip”
Invoke-WebRequest –URI https://github.com/DefensiveOrigins/LABPACK/archive/master.zip -OutFile LabPack.zip 
write-host("Downloaded files:")
write-host("Sysmon, WinLogBeat-v7.10.2, latest sysmon-modular, Palantir, and DO-LabPack files, including GPOs")



# Expand .zip archives

Expand-Archive .\Sysmon.zip 
Expand-Archive .\sysmon-modular.zip 
Expand-Archive .\palantir.zip 
Expand-Archive .\WinLogBeat.zip 
Expand-Archive .\LabPack.zip 



# Clean up zips

Remove-Item .\Sysmon.zip
Remove-Item .\sysmon-modular.zip
Remove-Item .\palantir.zip
Remove-Item .\WinLogBeat.zip
Remove-item .\LabPack.zip



# Force the allowance of unsigned scripts and build the modular config for sysmon

Set-ExecutionPolicy bypass -Force
cd C:\labs\sysmon-modular\sysmon-modular-master
Import-Module .\Merge-SysmonXml.ps1 
Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml
Get-Content ".\sysmonconfig.xml " | select -First 10



# Copy sysmon files over to c:\labs\sysmon

cp C:\LABS\sysmon-modular\sysmon-modular-master\sysmonconfig.xml c:\labs\sysmon\sysmonconfig.xml



# Install Sysmon on the DC

cd \\dc01\labs\sysmon\
./sysmon.exe -accepteula -i sysmonconfig.xml



# Check on the sysmon event logs location

Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational



# Next up, import the GPOs necessary for auditing, transcription, WinRM and RDP, event collection and forwarding

Import-GPO -Path "\\dc01\LABS\LabPack\LABPACK-master\Lab-GPOs\CMD-PS-Logging\" -BackupGpoName "CMD-PS-Logging" -CreateIfNeeded -TargetName "CMD-PS-Logging" -Server DC01
Import-GPO -Path "\\dc01\LABS\LabPack\LABPACK-master\Lab-GPOs\Enhanced-WS-Auditing\" -BackupGpoName "Enhanced WS Auditing" -CreateIfNeeded -TargetName "Enhanced-WS-Auditing" -Server DC01
Import-GPO -Path "\\dc01\LABS\LabPack\LABPACK-master\Lab-GPOs\Enhanced-DC-Auditing\" -BackupGpoName "Enhanced DC Auditing" -CreateIfNeeded -TargetName "Enhanced-DC-Auditing" -Server DC01
Import-GPO -Path "\\dc01\LABS\LabPack\LABPACK-master\Lab-GPOs\Enable-WinRM-and-RDP\" -BackupGpoName "Enable-WinRM-and-RDP" -CreateIfNeeded -TargetName "Enable-WinRM-and-RDP" -Server DC01
Import-GPO -Path “\\dc01\LABS\LabPack\LABPACK-master\Lab-GPOs\Windows Event Forwarding” -BackupGpoName "Windows Event Forwarding” -CreateIfNeeded -TargetName "Windows Event Forwarding" -Server DC01



# Link those GPOs to various containers in AD structure

New-GPLink -Name "CMD-PS-Logging" -Target "dc=labs,dc=local" -LinkEnabled Yes
New-GPLink -Name "Enhanced-WS-Auditing" -Target "dc=labs,dc=local" -LinkEnabled Yes
New-GPLink -Name "Enhanced-DC-Auditing" -Target "ou=Domain Controllers,dc=labs,dc=local" -LinkEnabled Yes
New-GPLink -Name "Enable-WinRM-and-RDP” -Target "dc=labs,dc=local" -LinkEnabled Yes
New-GPLink -Name "Windows Event Forwarding” -Target "dc=labs,dc=local" -LinkEnabled Yes



# Enable windows event collection with wecutil

wecutil qc /q



# copy the CustomEventChannels directory contents over to System32, then import the custom channels manifest

cp C:\LABS\LabPack\LABPACK-master\Lab-WEF-Palantir\windows-event-channels\CustomEventChannels.* C:\windows\System32\
wevtutil im C:\windows\system32\CustomEventChannels.man



# start the windows event collector service

net start wecsvc



# install the event subscriptions with a for loop

cd C:\LABS\LabPack\LABPACK-master\Lab-WEF-Palantir\wef-subscriptions
foreach ($file in (Get-ChildItem *.xml)) {wecutil cs $file}


# increase the size of all custom channels

foreach ($subscription in (wevtutil el | select-string -pattern "WEC")) {wevtutil sl $subscription /ms:4194304}
wevtutil gl WEC3-PRINT


#####################################
# REMOTE POWERSHELL SESSION TO WS01 #
#####################################

# Fire up a powershell-remoting session to the WS

Enter-PSSession ws01



# CD to labs\sysmon file share and install sysmon

cd \\dc01\labs\sysmon\
./sysmon.exe -accepteula -i sysmonconfig.xml

Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational



# Update policies and reboot remote system
# Remote PS session will disconnect, and remote desktop will disconnect, DC will finish up local configuration and boot too

gpupdate /force
Restart-Computer -Force




#############################
# FINALIZE DC CONFIGURATION #
#############################

# WinLogBeat config file handling

mv C:\labs\WinLogBeat\winlogbeat-7.10.2-windows-x86_64\winlogbeat.yml C:\labs\WinLogBeat\winlogbeat-7.10.2-windows-x86_64\winlogbeat.yml.old
cp C:\labs\LabPack\LABPACK-master\Lab-WinLogBeat\winlogbeat.yml C:\labs\WinLogBeat\winlogbeat-7.10.2-windows-x86_64\winlogbeat.yml



# CD to winlogbeat dir and install as a service

cd c:\labs\WinLogBeat\winlogbeat-7.10.2-windows-x86_64\
powershell -Exec bypass -File .\install-service-winlogbeat.ps1



# Configure service parameters and start

Set-Service -Name "winlogbeat" -StartupType automatic
Start-Service -Name "winlogbeat"
Get-Service winlogbeat



# Finally, run gpupdate and reboot the DC

gpupdate /force
Restart-Computer
