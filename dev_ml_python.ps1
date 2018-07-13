# Description: Boxstarter Script
# Author: Microsoft
# Install boxstarter:
# 	. { iwr -useb http://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force
#
# You might need to set: Set-ExecutionPolicy RemoteSigned (Set-ExecutionPolicy Restricted to set to default) 
# Also might need: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, as per:
# https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel

# Run this boxstarter by calling the following from an **elevated** command-prompt, and RAW gist (meaning raw file)
# 	start http://boxstarter.org/package/nr/url?<URL-TO-RAW-GIST>
# OR
# 	Install-BoxstarterPackage -PackageName <URL-TO-RAW-GIST> -DisableReboots
#
# Learn more: http://boxstarter.org/Learn/WebLauncher

# Common dev settings for machine learning

Disable-UAC

#First install antivirus 
#choco install -y avastfreeantivirus

#Chrome web browser
choco install -y googlechrome

# --- HARDWARE ---
choco install -y geforce-game-ready-driver
#choco install -y geforce-experience
choco install -y DellCommandUpdate

#--- Windows Features ---
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions

#Taskbar options
Set-TaskbarOptions -Size Small -Dock Top -Combine Full -Lock
Set-TaskbarOptions -Size Small -Dock Top -Combine Full -AlwaysShowIconsOn

#--- File Explorer Settings ---
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

#--- Map caps lock to escape ---
$hexified = "00,00,00,00,00,00,00,00,02,00,00,00,01,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"};
$kbLayout = 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout';
IF(!(Test-Path $kbLayout)){
	New-ItemProperty -Path $kbLayout -Name "Scancode Map" -PropertyType Binary -Value ([byte[]]$hexified);
}
ELSE {
	New-ItemProperty -Path $kbLayout -Name "Scancode Map" -PropertyType Binary -Force -Value ([byte[]]$hexified);
}

#Screensaver 
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d C:\Windows\system32\Bubbles.scr /f
#Enable lock screen with screensaver
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 600 /f

#--- Git ---
choco install -y git -params '"/GitAndUnixToolsOnPath /WindowsTerminal"'

#--- Windows Subsystems/Features ---
choco install -y Microsoft-Hyper-V-All -source windowsFeatures
choco install -y Microsoft-Windows-Subsystem-Linux -source windowsfeatures

#--- Ubuntu ---
# Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-1604 -OutFile ~/Ubuntu.appx -UseBasicParsing
# Add-AppxPackage -Path ~/Ubuntu.appx

#--- Fonts ---
choco install -y inconsolata
# choco install -y ubuntu.font

#--- Tools ---
#choco install -y docker-for-windows
choco install -y python
choco install -y 7zip.install
choco install -y conemu
#choco install sharex

#--- System Tools ---
choco install -y sysinternals

#--- Uninstall unecessary applications that come with Windows out of the box ---

# 3D Builder
Get-AppxPackage Microsoft.3DBuilder | Remove-AppxPackage

# Alarms
Get-AppxPackage Microsoft.WindowsAlarms | Remove-AppxPackage

# Autodesk
Get-AppxPackage *Autodesk* | Remove-AppxPackage

# Bing Weather, News, Sports, and Finance (Money):
Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage

# BubbleWitch
Get-AppxPackage *BubbleWitch* | Remove-AppxPackage

# Candy Crush
Get-AppxPackage king.com.CandyCrush* | Remove-AppxPackage

# Comms Phone
Get-AppxPackage Microsoft.CommsPhone | Remove-AppxPackage

# Dell
Get-AppxPackage *Dell* | Remove-AppxPackage

# Dropbox
Get-AppxPackage *Dropbox* | Remove-AppxPackage

# Facebook
Get-AppxPackage *Facebook* | Remove-AppxPackage

# Feedback Hub
Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage

# Get Started
Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage

# Keeper
Get-AppxPackage *Keeper* | Remove-AppxPackage

# Mail & Calendar
Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage

# Maps
Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage

# March of Empires
Get-AppxPackage *MarchofEmpires* | Remove-AppxPackage

# McAfee Security
Get-AppxPackage *McAfee* | Remove-AppxPackage

# Uninstall McAfee Security App
$mcafee = gci "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | foreach { gp $_.PSPath } | ? { $_ -match "McAfee Security" } | select UninstallString
if ($mcafee) {
	$mcafee = $mcafee.UninstallString -Replace "C:\Program Files\McAfee\MSC\mcuihost.exe",""
	Write "Uninstalling McAfee..."
	start-process "C:\Program Files\McAfee\MSC\mcuihost.exe" -arg "$mcafee" -Wait
}

# Messaging
Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage

# Minecraft
Get-AppxPackage *Minecraft* | Remove-AppxPackage

# Netflix
Get-AppxPackage *Netflix* | Remove-AppxPackage

# Office Hub
Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

# One Connect
Get-AppxPackage Microsoft.OneConnect | Remove-AppxPackage

# OneNote
Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage

# People
Get-AppxPackage Microsoft.People | Remove-AppxPackage

# Phone
Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage

# Photos
Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage

# Plex
Get-AppxPackage *Plex* | Remove-AppxPackage

# Skype (Metro version)
Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage

# Sound Recorder
Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage

# Solitaire
Get-AppxPackage *Solitaire* | Remove-AppxPackage

# Sticky Notes
Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage

# Sway
Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage

# Twitter
Get-AppxPackage *Twitter* | Remove-AppxPackage

# Xbox
Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage

# Zune Music, Movies & TV
Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage
Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage

#--- Windows Settings ---
# Some from: @NickCraver's gist https://gist.github.com/NickCraver/7ebf9efbfd0c3eab72e9

# Privacy: Let apps use my advertising ID: Disable
If (-Not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0

# WiFi Sense: HotSpot Sharing: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
# To Restore (Enabled):
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 1

# Disable Telemetry (requires a reboot to take effect)
# Note this may break Insider builds for your organization
# Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
# Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# Change Explorer home screen back to "This PC"
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
# Change it back to "Quick Access" (Windows 10 default)
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2

# Better File Explorer
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0
# Disable Quick Access: Frequent Folders
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0
# To Restore:
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 1
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 1

# Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) {
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
# To Restore:
# Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1

#Disable sleep on lid close both battery (dc) and direct (ac) power
# DOES NOT WORK
#https://www.tenforums.com/tutorials/69762-change-lid-close-default-action-windows-10-a.html
#powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
#powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
# DOES WORK -  scheme_min is high performance, set to current scheme
powercfg /s scheme_min
#plugged in
powercfg /setacvalueindex scheme_min sub_buttons lidaction 0
#dc is battery power
powercfg /setdcvalueindex scheme_min sub_buttons lidaction 0

# Lock screen (not sleep) on lid close
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name AwayModeEnabled -Type DWord -Value 1
# To Restore:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name AwayModeEnabled -Type DWord -Value 0

#Set night shift schedule on (mirror circadian rhythm)
#https://github.com/jaapbrasser/SharedScripts/blob/master/Set-BlueLight/Set-BlueLight.ps1
$BlueLightOption = @{
	Off          = [byte[]](2,0,0,0,147,250,216,91,185,109,210,1,0,0,0,0,67,66,1,0,208,10,2,198,20,202,236,227,222,149,183,155,233,1,0)
	On           = [byte[]](2,0,0,0,128,208,150,171,186,109,210,1,0,0,0,0,67,66,1,0,16,0,208,10,2,198,20,221,137,219,220,170,183,155,233,1,0)
	AutoOn       = [byte[]](2,0,0,0,89,63,239,213,232,109,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,188,62,202,50,14,16,46,54,0,202,60,14,8,46,46,0,0)
	AutoOff      = [byte[]](2,0,0,0,175,164,252,55,235,109,210,1,0,0,0,0,67,66,1,0,202,20,14,21,0,202,30,14,7,0,207,40,188,62,202,50,14,16,46,54,0,202,60,14,8,46,46,0,0)
	NoShift      = [byte[]](2,0,0,0,255,124,43,3,82,107,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,168,70,202,50,14,16,46,49,0,202,60,14,8,46,47,0,0)
	MinimumShift = [byte[]](2,0,0,0,224,193,179,114,82,107,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,236,57,202,50,14,16,46,49,0,202,60,14,8,46,47,0,0)
	MediumShift  = [byte[]](2,0,0,0,49,229,185,33,82,107,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,200,42,202,50,14,16,46,49,0,202,60,14,8,46,47,0,0)
	LargeShift   = [byte[]](2,0,0,0,22,255,5,128,82,107,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,138,27,202,50,14,16,46,49,0,202,60,14,8,46,47,0,0)
	MaximumShift = [byte[]](2,0,0,0,199,91,231,198,81,107,210,1,0,0,0,0,67,66,1,0,2,1,202,20,14,21,0,202,30,14,7,0,207,40,208,15,202,50,14,16,46,49,0,202,60,14,8,46,47,0,0)
}
$SetRegistrySplat = @{
	Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\{0}\Current'
	Force = $true
	Name  = 'Data'
}
function Set-RegistryValue {
	if (-not (Test-Path -Path $SetRegistrySplat.Path)) {
			New-Item -Path $SetRegistrySplat.Path -Force
	} else {
		Set-ItemProperty @SetRegistrySplat
	}
}
$SetRegistrySplat.Path  = $SetRegistrySplat.Path -f '$$windows.data.bluelightreduction.settings'
$SetRegistrySplat.Value = $BlueLightOption.AutoOn
Set-RegistryValue
				
# Use the Windows 7-8.1 Style Volume Mixer
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name MTCUVC | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name EnableMtcUvc -Type DWord -Value 0
# To Restore (Windows 10 Style Volume Control):
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name EnableMtcUvc -Type DWord -Value 1

# Disable Xbox Gamebar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWord -Value 0

# Turn off People in Taskbar
If (-Not (Test-Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People | Out-Null
}
Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name PeopleBand -Type DWord -Value 0

# TODO: install additional ML tools

#--- VS Code ---
choco install -y vscode

#--- VS Code extensions ---
choco install -y vscode-docker

#--- Visual Studio ---
choco install -y visualstudio2017community

#--- Unity ---
choco install -y unity

#--- Java ---
choco install -y jdk8

#--- Intellij ---
choco install -y intellijidea-ultimate

#--- Android Studio ---
choco install -y androidstudio

#---- Python + extensions ---
choco install -y python
choco install -y pip
pip install lxml
pip install bs4

#---- Hosts file -----
# $hostsDir = "~/Documents/Software/Github/Public";
# $hostsGitHubURL = "https://github.com/StevenBlack/hosts";
# If (-Not (Test-Path $hostsDir)) {
# 	mkdir $hostsDir
# 	git clone $hostsGitHubURL $hostsDir/StevenBlackHosts
# 	#cd $hostsDir
# 	#updateHostsWindows.bat
# 	#cd ~
# }


#RESTART COMPUTER AFTER 
#--- Rename the Computer ---
# Requires restart, or add the -Restart flag
$computername = "RenamedPC"
if ($env:computername -ne $computername) {
	Rename-Computer -NewName $computername
}

#Turn on bitlocker
#https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-basic-deployment
manage-bde -on C:

#-------------------------------------------------
Enable-UAC
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula
#-------------------------------------------------


