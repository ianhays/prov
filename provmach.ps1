# Adapted From: https://community.spiceworks.com/scripts/show/4378-windows-10-decrapifier-1803

#------ VARIABLES ------

#------ END VARIABLES ------

#------ COMMAND LINE ARGUMENTS ------

#
#***Command Line Args / Switches***
# 
#Switch         Function
#---------------------------
#-FreshInstall  Treats the computer as a brand new install, and will destructively set it up.
#-Superuser     Whether the owner and primary user of this machine will be an admin/superuser or a standard user i.e. is this my computer, or my kids computer?


[cmdletbinding(DefaultParameterSetName="provmach")]
param 
(
    [Parameter(ParameterSetName="FreshInstall")]
    [switch]$FreshInstall,
    [switch]$Superuser
)
#------ END COMMAND LINE ARGUMENTS ------

#------ Functions - Helpers------

### Function: loaddefaulthive
Function loaddefaulthive
{
	#Registry change functions
	#Load default user hive
	$defaultuser = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' Default).Default
	reg load "$reglocation" $defaultuser\ntuser.dat
}

### Function: unloaddefaulthive
Function unloaddefaulthive
{
	[gc]::collect()
	reg unload "$reglocation"
}

### Function: EnableSystemRestore
Function EnableSystemRestore
{
	Write-Host -ForegroundColor Blue "----- Function: EnableSystemRestore: Turns on System Restore on the C drive and creates a restore point before doing anything else."
	
	#Set Percentage for System Protection
	Write-Host -ForegroundColor Green "Setting size for system restore"
	vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

	# Enable system restore on C:\
	Write-Host -ForegroundColor Green "Enabling system restore..."
	Enable-ComputerRestore -Drive "$env:SystemDrive"

	#Force Restore point to not skip
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

	#Disable sleep timers and create a restore point just in case
	Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

	# All done!
	Write-Host -ForegroundColor Blue "----- Function: EnableSystemRestore: ACTION COMPLETED!"
}

#------ END Functions - Helpers------

#------ Functions - Universal------

### Function: DisableTasks
Function DisableTasks
{
	Write-Host -ForegroundColor Blue "----- Function: DisableTasks: Shut down unneeded tasks and set them to disabled"

	# Disables scheduled tasks
	# Tasks: Various CEIP and information gathering/sending tasks.
	Get-Scheduledtask "Microsoft Compatibility Appraiser", "ProgramDataUpdater", "Consolidator", "KernelCeipTask", "UsbCeip", "Microsoft-Windows-DiskDiagnosticDataCollector", "GatherNetworkInfo", "QueueReporting" -erroraction silentlycontinue | Disable-scheduledtask 
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null    
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" -ErrorAction SilentlyContinue | Out-Null

	# All done!
	Write-Host -ForegroundColor Blue "----- Function: DisableTasks: ACTION COMPLETED!"
}

### Function: DisableServices
Function DisableServices
{
	Write-Host -ForegroundColor Blue "----- Function: DisableServices: Shut down unneeded services and set them to startup manual or disabled"
	
	$ManualServices = @(
		"HomeGroupProvider"                            
		"HomeGroupListener"
		#"dmwappushservice"                             # WAP Push Message Routing Service NOTE Sysprep w/ Generalize WILL FAIL if you disable the DmwApPushService. Commented out by default.
		"WbioSrvc"                                     # Windows Biometric Service (required for Fingerprint reader / facial detection)
		#"wscsvc"                                       # Windows Security Center Service
		#"WSearch"                                      # Windows Search
		"XblAuthManager"                               # Xbox Live Auth Manager
		"XblGameSave"                                  # Xbox Live Game Save Service
		"XboxNetApiSvc"                                # Xbox Live Networking Service
		"XboxGipSvc"                                   #Disables Xbox Accessory Management Service
		#"NetTcpPortSharing"                            # Net.Tcp Port Sharing Service
		"SharedAccess"                                 # Internet Connection Sharing (ICS)
		"PcaSvc"                                       #Disables Program Compatibility Assistant Service
		"LicenseManager"                               #Disable LicenseManager(Windows store may not work properly)
		#"SysMain"                                      #Disables sysmain
		#"lmhosts"                                      #Disables TCP/IP NetBIOS Helper
		#"FontCache"                                    #Disables Windows font cache
		#"ALG"                                          # Disables Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
		#"BFE"                                         #Disables Base Filtering Engine (BFE) (is a service that manages firewall and Internet Protocol security)
		#"BrokerInfrastructure"                         #Disables Windows infrastructure service that controls which background tasks can run on the system.
		"SCardSvr"                                      #Disables Windows smart card
		#"BthAvctpSvc"                                   #Disables AVCTP service (if you use  Bluetooth Audio Device or Wireless Headphones. then don't disable this)
		#"FrameServer"                                   #Disables Windows Camera Frame Server(this allows multiple clients to access video frames from camera devices.)
		#"BthAvctpSvc"                                   #AVCTP service (This is Audio Video Control Transport Protocol service.)
		#"BDESVC"                                        #Disables bitlocker
		#"PNRPsvc"                                      # Disables peer Name Resolution Protocol ( some peer-to-peer and collaborative applications, such as Remote Assistance, may not function, Discord will still work)
		#"p2psvc"                                       # Disbales Peer Name Resolution Protocol(nables multi-party communication using Peer-to-Peer Grouping.  If disabled, some applications, such as HomeGroup, may not function. Discord will still work)
		#"p2pimsvc"                                     # Disables Peer Networking Identity Manager (Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly.Discord will still work)
		#"PerfHost"                                      #Disables  remote users and 64-bit processes to query performance .
		"BcastDVRUserService_48486de"                   #Disables GameDVR and Broadcast   is used for Game Recordings and Live Broadcasts
		#"CaptureService_48486de"                        #Disables optional screen capture functionality for applications that call the Windows.Graphics.Capture API.  
		#"cbdhsvc_48486de"                               #Disables   cbdhsvc_48486de (clipboard service it disables)
		#"BluetoothUserService_48486de"                  #disbales BluetoothUserService_48486de (The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session.)
		#"StorSvc"                                       #Disables StorSvc (usb external hard drive will not be reconised by windows)
		#"RtkBtManServ"                                  #Disables Realtek Bluetooth Device Manager Service
		#"QWAVE"                                         #Disables Quality Windows Audio Video Experience (audio and video might sound worse)
		#Hp services
		"HPAppHelperCap"
		"HPDiagsCap"
		"HPNetworkCap"
		"HPSysInfoCap"
		"HpTouchpointAnalyticsService"
	)
	
    $DisabledServices = @(
		"diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service
		"DiagTrack"                                    # Diagnostics Tracking Service
		"lfsvc"                                        # Geolocation Service
		"MapsBroker"                                   # Downloaded Maps Manager
		"TrkWks"                                       # Distributed Link Tracking Client
		"WMPNetworkSvc"                                # Windows Media Player Network Sharing Service
		"WerSvc"                                       #disables windows error reporting
		"Fax"                                          #Disables fax
		"fhsvc"                                        #Disables fax histroy
		"gupdate"                                      #Disables google update
		"gupdatem"                                     #Disable another google update
		"stisvc"                                       #Disables Windows Image Acquisition (WIA)
		"AJRouter"                                     #Disables (needed for AllJoyn Router Service)
		"MSDTC"                                        # Disables Distributed Transaction Coordinator
		"WpcMonSvc"                                    #Disables Parental Controls
		"PhoneSvc"                                     #Disables Phone Service(Manages the telephony state on the device)
		"WPDBusEnum"                                   #Disables Portable Device Enumerator Service
		"wisvc"                                        #Disables Windows Insider program(Windows Insider will not work)
		"RetailDemo"                                   #Disables RetailDemo whic is often used when showing your device
		#"EntAppSvc"                                     #Disables enterprise application management.
		"edgeupdate"                                    # Disables one of edge update service  
		"MicrosoftEdgeElevationService"                 # Disables one of edge  service 
		"edgeupdatem"                                   # disbales another one of update service (disables edgeupdatem)                          
		"SEMgrSvc"                                      #Disables Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
		"WpnService"                                    #Disables WpnService (Push Notifications may not work )
		#hyper-v services
		"HvHost"                          
		"vmickvpexchange"
		"vmicguestinterface"
		"vmicshutdown"
		"vmicheartbeat"
		"vmicvmsession"
		"vmicrdv"
		"vmictimesync" 
	)
	
	foreach ($service in $ManualServices) 
	{
		#-ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist
		Write-Host  -ForegroundColor Green "Setting $service StartupType to Manual"
		Get-Service -Name $service -ErrorAction SilentlyContinue | stop-service -passthru | set-service -startuptype Manual
	}

	foreach ($service in $DisabledServices) 
	{
		#-ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist
		Write-Host  -ForegroundColor Green "Setting $service StartupType to Disabled"
		Get-Service -Name $service -ErrorAction SilentlyContinue | stop-service -passthru | set-service -startuptype disabled
	}
	Write-Host -ForegroundColor Blue "----- Function: DisableServices: ACTION COMPLETED!"
}

### Function RemoveBloatware - Uninstalls apps no one would ever want in any circumstance
Function RemoveBloatware
{
	Write-Host -ForegroundColor Blue "----- Function: Function RemoveBloatware: Uninstalls apps no one would ever want in any circumstance"

	$Bloatware = @(
		#Unnecessary Windows 10 AppX Apps
		#"Microsoft.3DBuilder"
		#"Microsoft.Microsoft3DViewer"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.BingWeather"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingTravel"
		#"Microsoft.MinecraftUWP"
		#"Microsoft.GamingServices"
		"Microsoft.WindowsReadingList"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.Messaging"
		#"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.News"
		"Microsoft.Office.Lens"
		"Microsoft.Office.Sway"
		#"Microsoft.Office.OneNote"
		#"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		"Microsoft.SkypeApp"
		"Microsoft.Wallet"
		"Microsoft.Whiteboard"
		#"Microsoft.WindowsAlarms"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		#"Microsoft.WindowsSoundRecorder"
		#"Microsoft.XboxApp"
		#"Microsoft.ConnectivityStore"
		"Microsoft.CommsPhone"
		#"Microsoft.ScreenSketch"
		#"Microsoft.Xbox.TCUI"
		#"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.MixedReality.Portal"
		#"Microsoft.XboxIdentityProvider"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"Microsoft.YourPhone"
		"Microsoft.Getstarted"
		#"Microsoft.MicrosoftOfficeHub"
		"Adobe Express"
		"Spotify"
		"Disney+"
		#"Xbox"
		"Clipchamp"
		"Prime Video"
		"TicTok"
		"Instagram"
		"Facebook"
		#Sponsored Windows 10 AppX Apps
		#Add sponsored/featured apps to remove in the "*AppName*" format
		"*EclipseManager*"
		"*ActiproSoftwareLLC*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*Duolingo-LearnLanguagesforFree*"
		"*PandoraMediaInc*"
		"*CandyCrush*"
		"*BubbleWitch3Saga*"
		"*Wunderlist*"
		"*Flipboard*"
		"*Twitter*"
		"*Facebook*"
		"*Royal Revolt*"
		"*Sway*"
		"*Speed Test*"
		"*Dolby*"
		"*Viber*"
		"*ACGMediaPlayer*"
		"*Netflix*"
		"*OneCalendar*"
		"*LinkedInforWindows*"
		"*HiddenCityMysteryofShadows*"
		"*Hulu*"
		"*HiddenCity*"
		"*AdobePhotoshopExpress*"
		"*HotspotShieldFreeVPN*"

		#Optional: Typically not removed but you can if you need to for some reason
		"*Microsoft.Advertising.Xaml*"
		#"*Microsoft.MSPaint*"
		#"*Microsoft.MicrosoftStickyNotes*"
		#"*Microsoft.Windows.Photos*"
		#"*Microsoft.WindowsCalculator*"
		#"*Microsoft.WindowsStore*"
	)

    foreach ($Bloat in $Bloatware) 
	{
        Write-Host  -ForegroundColor Green "Trying to remove $Bloat."
        Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online
    }

	Write-Host -ForegroundColor Blue "----- Function: RemoveBloatware: ACTION COMPLETED!"
}

### Function WindowsFeatures
Function WindowsFeatures
{
	Write-Host -ForegroundColor Blue "----- Function: WindowsFeatures: Enabling/Disabling Windows Features and Capabilities"
	Write-Host -ForegroundColor Green "Installing .NET Framework..."
	Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null

	Write-Host  -ForegroundColor Green "Installing Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

	Write-Host  -ForegroundColor Green "Installing Windows MediaPlayback..."
	Enable-WindowsOptionalFeature -Online -FeatureName "MediaPlayback" -NoRestart -WarningAction SilentlyContinue | Out-Null
			
	Write-Host  -ForegroundColor Green "Installing Windows MediaFeaturePack..."
	dism /online /Add-Capability /CapabilityName:Media.MediaFeaturePack~~~~0.0.1.0

	# Disabling WordPad
	Write-Host  -ForegroundColor Green "Disabling WordPad. Will show a small message with an error 87 if the program is already deleted. No worries."
	dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.WordPad~~~~0.0.1.0
	
	# Disabling Notepad
	Write-Host  -ForegroundColor Green "Disabling Notepad. Will show a small message with an error 87 if the program is already deleted. No worries."
	dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.Notepad.System~~~~0.0.1.0
	Write-Host -ForegroundColor Blue "----- Function: WindowsFeatures: ACTION COMPLETE!"
}

### Function: RegChange - Applies all registry settings that we always want to use, calling both RegSetUser and RegSetMachine
Function RegChange
{
	Write-Host -ForegroundColor Blue "----- Function: RegChange: Applying all registry settings"
	#Cycle registry locations - 1st pass HKCU, 2nd pass default NTUSER.dat
	$reglocation = "HKCU"
	regsetuser
	$reglocation = "HKLM\AllProfile"
	Write-Host "***Applying registry items to default NTUSER.DAT...***"
	loaddefaulthive; regsetuser; unloaddefaulthive
	$reglocation = $null
	regsetmachine
	Write-Host -ForegroundColor Blue "----- Function: RegChange: ACTION COMPLETE!"
}

### Function: RegSetUser - Applies user-specific registry settings that we always want to use.
Function RegSetUser
{
	Write-Host -ForegroundColor Blue "----- Function: RegSetUser: Setting $reglocation registry entries"

	#Start menu suggestions
	Write-Host "Modifying Registry Entries for: Start menu suggestions"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
	#Show suggested content in settings
	Write-Host "Modifying Registry Entries for: Show suggested content in settings"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-338393Enabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-353694Enabled" /D 0 /F
	#Show suggestions occasionally
	Write-Host "Modifying Registry Entries for: Show suggestions occasionally"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-338388Enabled" /D 0 /F
	#Multitasking - Show suggestions in timeline
	Write-Host "Modifying Registry Entries for: Multitasking - Show suggestions in timeline"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-353698Enabled" /D 0 /F
	#Lockscreen suggestions, rotating pictures
	Write-Host "Modifying Registry Entries for: Lockscreen suggestions, rotating pictures"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "RotatingLockScreenEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "RotatingLockScreenOverlayEnabled" /D 0 /F
	#Preinstalled apps, Minecraft Twitter etc all that - still need a clean default start menu to fully eliminate
	Write-Host "Modifying Registry Entries for: Preinstalled apps, Minecraft Twitter etc all that"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEverEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "OEMPreInstalledAppsEnabled" /D 0 /F
	#MS shoehorning apps quietly into your profile
	Write-Host "Modifying Registry Entries for: MS shoehorning apps quietly into your profile"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SilentInstalledAppsEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "ContentDeliveryAllowed" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContentEnabled" /D 0 /F
	#Ads in File Explorer
	Write-Host "Modifying Registry Entries for: Ads in File Explorer"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F
	#Show me the Windows welcome experience after updates and occasionally
	Write-Host "Modifying Registry Entries for: Windows welcome experience"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-310093Enabled" /D 0 /F
	#Get tips, tricks, suggestions as you use Windows 
	Write-Host "Modifying Registry Entries for: Get tips, tricks, suggestions as you use Windows "
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-338389Enabled" /D 0 /F

	#Privacy Settings
	#Let websites provide local content by accessing language list - appears to reset during OOBE.
	Write-Host "Modifying Registry Entries for: Let websites provide local content by accessing language list"
	Reg Add "$reglocation\Control Panel\International\User Profile" /T REG_DWORD /V "HttpAcceptLanguageOptOut" /D 1 /F
	#Ask for feedback
	Write-Host "Modifying Registry Entries for: Ask for feedback"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Siuf\Rules" /T REG_DWORD /V "NumberOfSIUFInPeriod" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Siuf\Rules" /T REG_DWORD /V "PeriodInNanoSeconds" /D 0 /F
	#Let apps use advertising ID
	Write-Host "Modifying Registry Entries for: Let apps use advertising ID"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T REG_DWORD /V "Enabled" /D 0 /F
	#Let Windows track app launches to improve start and search results - includes run history
	Write-Host "Modifying Registry Entries for: Let Windows track app launches"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "Start_TrackProgs" /D 0 /F
	#Tailored experiences - Diagnostics & Feedback settings
	Write-Host "Modifying Registry Entries for: Tailored experiences"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /T REG_DWORD /V "TailoredExperiencesWithDiagnosticDataEnabled" /D 0 /F
	#Improve inking & typing recognition
	Write-Host "Modifying Registry Entries for: Improve inking & typing recognition"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Input\TIPC" /T REG_DWORD /V "Enabled" /D 0 /F
	#Pen & Windows Ink - Show recommended app suggestions
	Write-Host "Modifying Registry Entries for: Pen & Windows Ink - Show recommended app suggestions"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /T REG_DWORD /V "PenWorkspaceAppSuggestionsEnabled" /D 0 /F
	
	#People + Feeds
	#Show My People notifications
	Write-Host "Modifying Registry Entries for: Show My People notifications"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" /T REG_DWORD /V "ShoulderTap" /D 0 /F
	#Show My People app suggestions
	Write-Host "Modifying Registry Entries for: Show My People app suggestions"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContent-314563Enabled" /D 0 /F
	#People on Taskbar
	Write-Host "Modifying Registry Entries for: People on Taskbar"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /T REG_DWORD /V "PeopleBand" /D 0 /F
	#News/Feeds taskbar item
	Write-Host "Modifying Registry Entries for: News/Feeds taskbar item"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /T REG_DWORD /V "ShellFeedsTaskbarViewMode" /D 2 /F
		
	#Other Settings
	#Do not track - Edge
	Write-Host "Modifying Registry Entries for: Do not track - Edge"
	Reg Add "$reglocation\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /T REG_DWORD /V "DoNotTrack" /D 1 /F
	#Do not track - IE
	Write-Host "Modifying Registry Entries for: Do not track - IE"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Internet Explorer\Main" /T REG_DWORD /V "DoNotTrack" /D 1 /F
	
	### App permissions user settings, these are all available from the settings menu
	Write-Host "Modifying Registry Entries for: App Permission Settings"
	#Deny App access to Camera
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Microphone
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Notifications - doesn't appear to work in 1803, setting hasn't been moved as of 1803 like most of the others
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Account Info
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Contacts
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /T REG_SZ /V "Value" /D Deny /F	
	#Deny App access to Calendar
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Call history
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Email
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Tasks
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to TXT/MMS
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Radios - doesn't appear to work in 1803, setting hasn't been moved as of 1803 like most of the others
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Other Devices - reset during OOBE
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Cellular Data
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to Allow apps to run in background global setting - seems to reset during OOBE
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /T REG_DWORD /V "GlobalUserDisabled" /D 1 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "BackgroundAppGlobalToggle" /D 0 /F	
	#Deny App access to App Diagnostics - doesn't appear to work in 1803, setting hasn't been moved as of 1803 like most of the others
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to My Documents
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to My Pictures
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to My Videos
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to File System
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /T REG_SZ /V "Value" /D Deny /F
	#Deny App access to location and sensors
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /T REG_DWORD /V "SensorPermissionState" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /T REG_SZ /V "Value" /D Deny /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /T REG_SZ /V "Value" /D Deny /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /T REG_SZ /V "Value" /D Deny /F

	#Disable Cortana and Bing search user settings
	Write-Host "Modifying Registry Entries for: Cortana and Bing search Settings"
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "CortanaEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "CanCortanaBeEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "DeviceHistoryEnabled" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "CortanaConsent" /D 0 /F
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "CortanaInAmbientMode" /D 0 /F
	#Disable Bing search from start menu/search bar
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "BingSearchEnabled" /D 0 /F
	#Disable Cortana on lock screen
	Reg Add "$reglocation\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /T REG_DWORD /V "VoiceActivationEnableAboveLockscreen" /D 0 /F
	#Disable Cortana search history
	Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "HistoryViewEnabled" /D 0 /F

    # Disable Tailored Experiences
	Write-Host "Modifying Registry Entries for: Tailored Experiences"
	Reg Add "$reglocation\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableTailoredExperiencesWithDiagnosticData" /D 1 /F

    # Remove "News and Interest" from taskbar
	Write-Host "Modifying Registry Entries for: Remove News and Interest from taskbar"
	Reg Add "$reglocation\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /T REG_DWORD /V "EnableFeeds" /D 0 /F
	Reg Add "$reglocation\Software\Microsoft\Windows\CurrentVersion\Feeds" /T REG_DWORD /V "ShellFeedsTaskbarViewMode" /D 2 /F
    
	#Disable "Meet Now" taskbar button
	Write-Host "Modifying Registry Entries for: Meet Now taskbar button"
	Reg Add	"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /T REG_DWORD /V "HideSCAMeetNow" /D 1 /F
	Write-Host -ForegroundColor Blue "----- Function: RegSetUser: ACTION COMPLETE!"
}

### Function: RegSetMachine - Applies machine-level registry settings that we always want to use.
Function RegSetMachine
{
	#Set local machine settings and local group policies    
	Write-Host -ForegroundColor Blue "----- Function RegSetMachine: Setting HKLM registry entries"

	### Application Compatibility
	#Turn off Application Telemetry			
	Write-Host "Modifying Registry Entries for: Turn off Application Telemetry"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "AITEnable" /D 0 /F			
	#Turn off inventory collector			
	Write-Host "Modifying Registry Entries for: Turn off inventory collector		"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "DisableInventory" /D 1 /F

	# Disable app history tracking
	Write-Host "Modifying Registry Entries for: Disabling Activity History"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    
	### Cloud Content			
	#Turn off Consumer Experiences	- Enterprise only (for Pro, HKCU settings and start menu cleanup achieve same result)		
	Write-Host "Modifying Registry Entries for: Turn off Consumer Experiences"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableWindowsConsumerFeatures" /D 1 /F
	#Turn off all spotlight features	
	Write-Host "Modifying Registry Entries for: Turn off all spotlight features	"
	Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableWindowsSpotlightFeatures" /D 1 /F  

	### Data Collection and Preview Builds			
	#Set Telemetry to off (switches to 1:basic for W10Pro and lower)			
	Write-Host "Modifying Registry Entries for: Set Telemetry to off "
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F
	#Disable pre-release features and settings			
	Write-Host "Modifying Registry Entries for: Disable pre-release features and settings		"
	Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /T REG_DWORD /V "EnableConfigFlighting" /D 0 /F
	#Do not show feedback notifications			
	Write-Host "Modifying Registry Entries for: Do not show feedback notifications		"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "DoNotShowFeedbackNotifications" /D 1 /F

	# Disable Windows Error Reporting
	Write-Host "Modifying Registry Entries for: Disable Windows Error Reporting"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	
	#Disallow web search from desktop search			
	Write-Host "Modifying Registry Entries for: Disallow web search from desktop search	"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "DisableWebSearch" /D 1 /F
	#Don't search the web or display web results in search			
	Write-Host "Modifying Registry Entries for: Don't search the web or display web results in search	"
	Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "ConnectedSearchUseWeb" /D 0 /F
	#Don't allow search to use location
	Write-Host "Modifying Registry Entries for: Don't allow search to use location"
	Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "AllowSearchToUseLocation" /D 0 /F

	#--Non Local GP Settings--		
	#Delivery Optimization settings - sets to 1 for LAN only, change to 0 for off
	Write-Host "Modifying Registry Entries for: Delivery Optimization settings"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /T REG_DWORD /V "DownloadMode" /D 1 /F
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /T REG_DWORD /V "DODownloadMode" /D 1 /F
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /T REG_DWORD /V "DownloadMode" /D 1 /F
	
	#Disabling advertising info and device metadata collection for this machine
	Write-Host "Modifying Registry Entries for: Disabling advertising info and device metadata collection for this machine"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T REG_DWORD /V "Enabled" /D 0 /F
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /V "PreventDeviceMetadataFromNetwork" /T REG_DWORD /D 1 /F
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

	#Disable Customer Experience Improvement Program. GP setting at: Computer Config\Admin Templates\System\Internet Communication Managemen\Internet Communication settings
	Write-Host "Modifying Registry Entries for: Disable Customer Experience Improvement Program"
	Reg Add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /T REG_DWORD /V "CEIPEnable" /D 0 /F
	
	#Prevent using sign-in info to automatically finish setting up after an update
	Write-Host "Modifying Registry Entries for: revent using sign-in info to automatically finish setting up after an update"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /T REG_DWORD /V "ARSOUserConsent" /D 0 /F
	
	#Prevent apps on other devices from opening apps on this one - disables phone pairing
	Write-Host "Modifying Registry Entries for: Prevent apps on other devices from opening apps on this one - disables phone pairing"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /T REG_DWORD /V "UserAuthPolicy" /D 0 /F

	# Disable Remote Assistance
	Write-Host "Modifying Registry Entries for: Disable Remote Assistance"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    
	#Enable diagnostic data viewer
	Write-Host "Modifying Registry Entries for: Enable diagnostic data viewer"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /T REG_DWORD /V "EnableEventTranscript" /D 1 /F
	
	#Disable Edge desktop shortcut
	Write-Host "Modifying Registry Entries for: Disable Edge desktop shortcut"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /T REG_DWORD /V "DisableEdgeDesktopShortcutCreation" /D 1 /F

	#Disable Cortana
	Write-Host "Modifying Registry Entries for: Disable Cortana"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "AllowCortana" /D 0 /F
	#Disallow Cortana on lock screen - seems pointless with above setting, may be deprecated, covered by HKCU anyways		
	Write-Host "Modifying Registry Entries for: Disallow Cortana on lock screen"
	Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "AllowCortanaAboveLock" /D 0 /F

	#Turn off location - global
	Write-Host "Modifying Registry Entries for: Turn off location - global"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /T REG_SZ /V "Value" /D Deny /F

	# All done!
	Write-Host -ForegroundColor Blue "----- Function: RegSetMachine: ACTION COMPLETE!"
}      

### Function: EnableRDP
Function EnableRDP
{
	Write-Host -ForegroundColor Blue "----- Function EnableRDP: Setting up Remote Desktop access to this computer"	

	Write-Host "Enabling optional Windows Feature RDC"
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-RemoteDesktopConnection" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
	Write-Host "Modifying Registry Entries for: fDenyTSConnections"
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0

	Write-Host "Adding firewall rules for remote desktop"
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

	# All done!
	Write-Host -ForegroundColor Blue "----- Function EnableRDP: ACTION COMPLETE!"
}

### Function InstallPrograms - Installs all basic programs needed by every computer
Function InstallPrograms
{
	Write-Host -ForegroundColor Blue "----- Function InstallPrograms: Installs all basic programs needed by every computer"	

	# Install most programs using a prebuilt Ninite installer included in this folder.
	# This Ninite should include:
	#	- Brave Browser
	#	- Git
	#	- Notepad++
	#	- WinSCP
	#	- PuTTY
	#	- Visual Studio Code
	#	- 7-zip
	#	- Discord
	#	- Blender
	#	- Steam
	#	- Epic Games Launcher
	#	- VLC
	#	- Java x64 and x86 - All Versions AdoptOpenJD
	#	- JDK x64 and x86 - All Versions AdoptOpenJD
	#	- .NET All Versions
	#	- .NET Desktop Runtime All Versions
	#	- VC++ Redistributable All Versions
	#	- Python All Versions
	Invoke-Expression -Command ".\NiniteInstaller.exe"

	# Install winget package manager
	Write-Host "Installing WinGet PowerShell module from PSGallery..."
	Install-PackageProvider -Name NuGet -Force | Out-Null
	Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
	Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."
	Repair-WinGetPackageManager
	Write-Host "Done Installing Winget."

	# Install any other programs that aren't available through Ninite but are available through winget
	#	- Steelseries GG - Software to control SteelSeries mouse
	#	- PowerToys
	#		- PowerToys.AdvancedPaste
	#		- PowerToys.FancyZones
	#		- PowerToys.FileLocksmith
	#		- PowerToys.KeyboardManager
	#	- Hardware fan monitors and such
	winget install --id SteelSeries.GG --source winget
	winget install --id Microsoft.PowerToys --source winget
	winget install --id CPUID.HWMonitor --source winget
	winget install --id calibre.calibre --source winget
	winget install --id OpenWhisperSystems.Signal --source winget
	
	# Install SuperUser programs that aren't in Ninite
	#	- LightBurn - Software to control Laser Cutters of all types and brands
	#	- BambuStudio - Software to control Bambu branded 3d printers
	#	- AutoHotKey
	if ($SuperUser)
	{
		#winget install --id LightBurnSoftware.LightBurn --source winget #TODO: select specific version my license covers
		winget install --id Bambulab.Bambustudio --source winget
		winget install --id Microsoft.VisualStudio.2022.Community --source winget
		winget install --id AppWork.JDownloader --source winget
		winget install --id AutoHotKey.AutoHotKey --source winget
	}
	
	# Install programs that are in neither Ninite nor winget that we have to bundle installers for
	#	- Lian Li L-Connect 3 - Software for Lian LI Fans and Coolers
	# 	- https://www.fosshub.com/Bulk-Crap-Uninstaller.html
	#	- Windows Snip Tool (removed in Windows 11 by default)
	#	- FanControl


	# All done!
	Write-Host -ForegroundColor Blue "----- Function InstallPrograms: ACTION COMPLETE!"	
}

### Function ConfigureStartupPrograms - Disables/Enables programs that run on startup by default when installed e.g. Discord.
Function ConfigureStartupPrograms
{
	# Windows has a built-in settings menu for this if not doing it programatically - search for "startup programs" and run that, then enable/disable by program. But we want to automatically do it.
	
	Write-Host -ForegroundColor Blue "----- Function ConfigureStartupPrograms: Sets programs that should or should not run at startup by default e.g. Discord and Steam"
	
	# Any programs may be easily added to the startup sequence by moving a shortcut to their .exe into this folder: 
	# -- (for all users) C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
	# -- (for one user)  C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
	
	
	# However, the more common method to add them to startup is by adding a registry entry for them
	# Startup program registry entries are stored in: 
	# -- (for all users) Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	# -- (for one user)  Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	Write-Host "Modifying Registry Entries for: Disable auto-start of SecurityHealth service."
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F
	
	
	Write-Host -ForegroundColor Blue "----- Function ConfigureStartupPrograms: ACTION COMPLETE!"	
}

### Function ConfigureDefender - Sets the settings for the absurdly overbearing Windows Defender Antivirus
Function ConfigureDefender
{
	Write-Host -ForegroundColor Blue "----- Function ConfigureDefender: Sets the settings for the absurdly overbearing Windows Defender Antivirus"	
	
	#TODO Defender
	#TODO User Account Control

	# All Done!
	Write-Host -ForegroundColor Blue "----- Function ConfigureDefender: ACTION COMPLETE!"
}

### Function ConfigureWindowsUpdate - controls how windows update operates and when it is allowed to fuck with you.
Function ConfigureWindowsUpdate
{
	Write-Host -ForegroundColor Blue "----- Function ConfigureWindowsUpdate: Setting up how windows update operates and when it is allowed to fuck with you."	

	# Turn off automatic download/install of store app updates	
	Write-Host "Modifying Registry Entries for: Turn off automatic download/install of store app updates	"
	Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /T REG_DWORD /V "AutoDownload" /D 2 /F	
	
	#Turn off featured SOFTWARE notifications through Windows Update
	Write-Host "Modifying Registry Entries for: Turn off featured SOFTWARE notifications through Windows Update"
	Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /T REG_DWORD /V "EnableFeaturedSoftware" /D 0 /F

	# Driver Updates through Windows Update - requires letting Windows collect your device metadata.
	Write-Host "Modifying Registry Entries for: Disabling driver offering through Windows Update"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	
	# Prevent Windows from searching for Drivers
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
	Write-Host "Modifying Registry Entries for: Prevent Windows from searching for Drivers"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
	
	# Disallow update drivers from "Quality" Updates
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
	Write-Host "Modifying Registry Entries for: Disallow update drivers from Quality Updates"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
	
	# Disabling the absurd auto-restart and forced restart
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
	Write-Host "Modifying Registry Entries for: Disabling the absurd auto-restart and forced restart"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	
	# All done!
	Write-Host -ForegroundColor Blue "----- Function ConfigureWindowsUpdate: ACTION COMPLETE!"
}

### Function DefaultPrograms - Sets the default apps with which to open all file extensions
Function DefaultPrograms
{
	Write-Host -ForegroundColor Blue "----- Function DefaultPrograms: Sets the default apps with which to open all file extensions"	
	#TODO
  # dism /online /Remove-DefaultAppAssociations - Removes the default application associations from a Windows image.
  # /Import-DefaultAppAssociations - Imports a set of default application associations to a Windows image.
  # /Get-DefaultAppAssociations - Displays the list of default application associations from a Windows image.
  # /Export-DefaultAppAssociations - Exports the default application associations from a running operating system.
	Write-Host -ForegroundColor Blue "----- Function DefaultPrograms: ACTION COMPLETE!"
}

#------ END Functions - Universal------

#------ Functions - Optional ------

### Function: ConfigurePowerOptions
Function ConfigurePowerOptions
{
	Write-Host -ForegroundColor Blue "----- Function ConfigurePowerOptions: Setting up Power options and TimeZone"	

	# Set when the computer should go to sleep, timeout, hibernate, etc.
	powercfg.exe -change -monitor-timeout-ac 10 # When plugged in, turn off my screen after: x minutes
	powercfg.exe -change -monitor-timeout-dc 10 
	powercfg.exe -change -disk-timeout-ac 0
	powercfg.exe -change -disk-timeout-dc 0
	powercfg.exe -change -standby-timeout-ac 30 # When plugged in, put my device to sleep after: x minutes
	powercfg.exe -change -standby-timeout-dc 30
	powercfg.exe -change -hibernate-timeout-ac 0 # When plugged in, hibernate my device after: x minutes; hibernation is like deep sleep where RAM is emptied onto the disk. and the computer is otherwise turned off.
	powercfg.exe -change -hibernate-timeout-dc 0
	
	# Set the time zone to CST.
	Write-Host "Setting the time zone to CST."
	Set-TimeZone -Id "Central Standard Time"
	
	# Configure Task to Set the PC to turn off in the middle of the night if its been left on.
	Write-Host "Configure Task to Set the PC to turn off in the middle of the night if its been left on. ONLY when superuser=false."
	$TaskName = "DailySystemShutdown"
	$TaskDescription = "Performs a daily system restart."
	$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "System" -LogonType ServiceAccount

	# Delete the auto-shutdown task we previously created if any exists already
	Write-Host "Deleting any previously created auto-shutdown tasks by this script."
	if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
	{
		Disable-ScheduledTask -TaskName $TaskName
		Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
	}

	# Only enable the shutdown task for a non-superuser setup.
	If (!($SuperUser))
	{
		# Set time for task action
		$RestartTime = "03:00" # Time of day for the restart (e.g., 03:00 for 3 AM)
	
		# Create a task action (the command to execute)
		#$TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "Restart-Computer -Force"
		$TaskAction = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/s /f /t 0'
		
		# Create a daily trigger
		$TaskTrigger = New-ScheduledTaskTrigger -Daily -At $RestartTime	

		# Register the scheduled task
		Write-Host "Registering a task named $TaskName to auto shutdown the PC every day at $RestartTime"
		Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Description $TaskDescription
	}

	# Set account lockout threshold
	# Write-Host -ForegroundColor Green "Setting Account Security Policy:"
	# Write-Host -ForegroundColor Green "Account Lockout Threshold: 5 `nAccount Lockout Duration: 30 minutes `nAccount Lockout Counter Restet: 30 minutes"
	# net accounts /lockoutthreshold:5
	# ##Set account lockout duration
	# net accounts /lockoutduration:30
	# #Reset acccount lockout counter
	# net accounts /lockoutwindow:30
	# Enable screen saver
	# Write-Host -ForegroundColor Green "Further Hardening:"
	# Write-Host -ForegroundColor Green "`nScreen Saver Enabled `nScreen Saver Timeout: 15 minutes `nSpecific Screen Saver Set `nPassword Protected Screen Saver `nSceen Saver Cannot Be Changed"
	# REG DEL "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /f
	# #Set screen saver timeout 900
	# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f
	# #Set specific screensaver scrnsave.scr
	# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d C:\Windows\system32\scrnsave.scr /f
	# #Password protect the screen saver enabled
	# REG ADD "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
	# #Prevent changing the screen saver enabled
	# REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage \t REG_DWORD /d 1 /f

	Write-Host -ForegroundColor Blue "----- Function ConfigurePowerOptions: ACTION COMPLETE!"
}

### Function: CustomizeExplorer - contains all regedits having to do with Explorer
Function CustomizeExplorer
{	
	Write-Host -ForegroundColor Blue "----- Function CustomizeExplorer: Configure all regedits having to do with File Explorer"	
	
	# Disable Explorer Notifactions & Action Center
	Write-Host "Modifying Registry Entries for: Disable Explorer Notifactions & Action Center"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

	# Change Default Explorer View to This PC
	Write-Host "Modifying Registry Entries for: Change Default Explorer View to This PC"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

	# Remove recent docs history from explorer
	Write-Host "Modifying Registry Entries for: Recent Docs History"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1

	# Hide 3D objects Icon from This PC
	# Write-Host "Modifying Registry Entries for: Hiding 3D Objects icon from This PC..."
    # Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
    
    # Hide the Task View button in Explorer    
	Write-Host "Modifying Registry Entries for: Hiding Task View button"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 
    
    # Hide the 'People' Icon
	Write-Host "Modifying Registry Entries for: Hide the 'People' Icon"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
 
	# OPTION: Remove OneDrive from the Explorer Navigation Pane
	# Adapted From: https://www.elevenforum.com/t/add-or-remove-onedrive-in-navigation-pane-of-file-explorer-in-windows-11.2478/
	$Option_RemoveOneDriveFromExplorerNavigationPane = $false
	if ($Option_RemoveOneDriveFromExplorerNavigationPane)
	{
		Write-Host "Modifying Registry Entries for: Remove OneDrive from the Explorer Navigation Pane"
		# @="OneDrive - Personal"
		Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0
		# @="OneDrive - Personal"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "HiddenByDefault" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Type DWord -Value 1
		#OneDrive settings - use -OneDrive switch to leave these on
		#Prevent usage of OneDrive local GP - Computer Config\Admin Templates\Windows Components\OneDrive	
		#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSyncNGSC" /D 1 /F
		#Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSync" /D 1 /F
		#Remove OneDrive from File Explorer
		#Reg Add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /T REG_DWORD /V "System.IsPinnedToNameSpaceTree" /D 0 /F
		#Reg Add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /T REG_DWORD /V "System.IsPinnedToNameSpaceTree" /D 0 /F
		
		#Disable OneDrive startup run user settings
		#Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /T REG_BINARY /V "OneDrive" /D 0300000021B9DEB396D7D001 /F
		#Disable automatic OneDrive desktop setup for new accounts
		#If ($reglocation -ne "HKCU")
		#{
		#	Reg Delete "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "OneDriveSetup" /F
		#}
	}

	# Option: Remove Home from Explorer Navigation Pane
	# Adapted From: https://www.elevenforum.com/t/add-or-remove-home-in-navigation-pane-of-file-explorer-in-windows-11.2449/
	$Option_RemoveHomeFromExplorerNavigationPane = $false
	if ($Option_RemoveHomeFromExplorerNavigationPane)
	{
		Write-Host "Modifying Registry Entries for: Remove Home from Explorer Navigation Pane"
		# @="CLSID_MSGraphHomeFolder"
		Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0
	}

	# Option: Remove Gallery from Explorer Navigation Pane
	# Adapted From: https://www.elevenforum.com/t/add-or-remove-gallery-in-file-explorer-navigation-pane-in-windows-11.14178/
	$Option_RemoveGalleryFromExplorerNavigationPane = $true
	if ($Option_RemoveGalleryFromExplorerNavigationPane)
	{
		Write-Host "Modifying Registry Entries for: Remove Gallery from Explorer Navigation Pane"
		# @="Gallery"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Name "HiddenByDefault" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Type DWord -Value 1
	}
	
	If ($SuperUser)
	{
		# Set Explorer to show file extensions by default
		Write-Host "Modifying Registry Entries for: Set Explorer to show file extensions by default"
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

		# Add "Run as different user" to context menu
		Write-Host "Modifying Registry Entries for: Add Run as different user to context menu"
		Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /T REG_DWORD /V "ShowRunasDifferentuserinStart" /D 1 /F
		
		# Showing File Operation details in Explorer - "Enthusiast Mode"
		If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
			New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
		}
		Write-Host "Modifying Registry Entries for: Explorer Enthusiast Mode - shows file operation status on explorer"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    }
	Write-Host -ForegroundColor Blue "----- Function CustomizeExplorer: ACTION COMPLETE!"
}

### Function: CustomizeMisc - extra misc customization edits available
Function CustomizeMisc
{
	Write-Host -ForegroundColor Blue "----- Function CustomizeMisc: Setting up extra customization edits available"	

	#Taskbar search, personal preference. 0 = no search, 1 = search icon, 2 = search bar
	#Write-Host "Modifying Registry Entries for: Taskbar search bar"
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsAADCloudSearchEnabled" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsMSACloudSearchEnabled" -Type DWord -Value 0
	#Allow search to use location if it's enabled
	Write-Host "Modifying Registry Entries for: Allow search to use location if it's enabled"
	Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "AllowSearchToUseLocation" /D 0 /F

	### Store
	#Disable all apps from store, commented out by default as it will break the store			
	#Write-Host "Modifying Registry Entries for: Disable all apps from store, commented out by default as it will break the store"
	#Reg Add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "DisableStoreApps" /D 1 /F		
	#Turn off Store, left disabled by default			
	#Write-Host "Modifying Registry Entries for: Turn off Store, left disabled by default"
	#Reg Add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "RemoveWindowsStore" /D 1 /F

	### Sync your settings - commented out by default to keep functionality of sync service		
	#Do not sync (anything)			
	#Write-Host "Modifying Registry Entries for: Computer Settings Sync"
	#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /T REG_DWORD /V "DisableSettingSync" /D 2 /F
	#Disallow users to override this
	#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /T REG_DWORD /V "DisableSettingSyncUserOverride" /D 1 /F
	
	#Let apps on other devices open messages and apps on this device - Shared Experiences settings
	Write-Host "Modifying Registry Entries for: Let apps on other devices open messages and apps on this device - Shared Experiences settings"
	Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /T REG_DWORD /V "RomeSdkChannelUserAuthzPolicy" /D 0 /F
	Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /T REG_DWORD /V "CdpSessionUserAuthzPolicy" /D 0 /F
	
	#Speech Inking & Typing - comment out if you use the pen\stylus a lot
	Write-Host "Modifying Registry Entries for: Speech Inking & Typing"
	Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /T REG_DWORD /V "Enabled" /D 0 /F
	Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitTextCollection" /D 1 /F
	Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitInkCollection" /D 1 /F
	Reg Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /T REG_DWORD /V "HarvestContacts" /D 0 /F
	Reg Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /T REG_DWORD /V "AcceptedPrivacyPolicy" /D 0 /F
	
	#Use Autoplay for all media and devices?
	Write-Host "Modifying Registry Entries for: Use Autoplay for all media and devices?"
	Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /T REG_DWORD /V "DisableAutoplay" /D 1 /F

	# All done!
	Write-Host -ForegroundColor Blue "----- Function CustomizeMisc: ACTION COMPLETE!"
}

# Function: CustomizePersonalization - Adjusts window size, snapping, etc. 
Function CustomizePersonalization
{
	Write-Host -ForegroundColor Blue "----- Function CustomizePersonalization: Adjusts window size, snapping, etc. "	
	# TODO: Set window snap behavior
	# TODO: Set alt-tab behavior
	
	# Write-Host  -ForegroundColor Green "Adjusting visual effects for performance..."
    # Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    # Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    # Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    # Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    # Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    # Write-Host  -ForegroundColor Green "Adjusted visual effects for performance"
    # $ResultText.text = "`r`n" +"`r`n" + "Adjusted VFX for performance"
	Write-Host -ForegroundColor Blue "----- Function CustomizePersonalization: ACTION COMPLETE!"
}

#------ END Functions - Optional------

#------ Functions - Fresh Install ------

### Function: SetComputerName
Function SetComputerName
{
	Write-Host -ForegroundColor Blue "----- WARNING: DESTRUCTIVE ACTION - Function SetComputerName: Kicks up a prompt to set this computers name."	
	#Set the Computer name
	while ($confirmInfo -ne 'y')
	{
		$compName = (Read-Host "Enter New Computer Name")

		Write-Output "`n`nComputer Name: $compName`n"
		$confirmInfo = (Read-Host "Is this information correct Y/N")
	}

	#set new PC name
	Write-Host -ForegroundColor Green "`n`nSetting Computer name..."
	Rename-Computer -NewName $compName
	Write-Host -ForegroundColor Blue "----- Function SetComputerName: ACTION COMPLETE!"
}

### Function: RemoveAllApps
Function RemoveAllApps
{
	Write-Host -ForegroundColor Blue "----- WARNING: DESTRUCTIVE ACTION - Function RemoveAllApps: Removing ALL apps from the computer except for a limited selection of decent ones."	
	#Apps to keep. Wildcard is implied so try to be specific enough to not overlap with apps you do want removed. 
	#Make sure not begin or end with a "|". ex: "app|app2" - good. "|app|app2|" - bad.

	$GoodApps =	"calculator|camera|sticky|store|windows.photos|soundrecorder|mspaint|microsoft.paint|windowsnotepad|screensketch"

	# Removes all apps from the computer except for the ones in the good apps list above.
	# SafeApps contains apps that shouldn't be removed, or just can't and cause errors
	$SafeApps = "AAD.brokerplugin|accountscontrol|apprep.chxapp|assignedaccess|asynctext|bioenrollment|capturepicker|cloudexperience|contentdelivery|desktopappinstaller|ecapp|edge|extension|getstarted|immersivecontrolpanel|lockapp|net.native|oobenet|parentalcontrols|PPIProjection|search|sechealth|secureas|shellexperience|startmenuexperience|terminal|vclibs|xaml|XGpuEject|Xbox"
	
	$SafeApps = "$SafeApps|$GoodApps"
	$RemoveApps = Get-AppxPackage -allusers | where-object { $_.name -notmatch $SafeApps }
	$RemovePrApps = Get-AppxProvisionedPackage -online | where-object { $_.displayname -notmatch $SafeApps }
	ForEach ($RemovedApp in $RemoveApps)
	{
		Write-Host "Removing app package: $RemovedApp.name"
		Remove-AppxPackage -package $RemovedApp -erroraction silentlycontinue
	}			
	ForEach ($RemovedPrApp in $RemovePrApps)
	{
		Write-Host "Removing provisioned app $RemovedPrApp.displayname"
		Remove-AppxProvisionedPackage -online -packagename $RemovedPrApp.packagename -erroraction silentlycontinue
	}
	Write-Host -ForegroundColor Blue "----- Function RemoveAllApps: ACTION COMPLETE!"
} 

### Function: CustomizeStartMenu - contains all regedits having to do with start menu
Function CustomizeStartMenu
{
	Write-Host -ForegroundColor Blue "----- WARNING: DESTRUCTIVE ACTION - Function CustomizeStartMenu: Configuring the Start Menu - will remove any pinned apps from start menu"	
	# Customizing Start Menu
	$layoutFile="C:\Windows\StartMenuLayout.xml"
	$START_MENU_LAYOUT = @" 
	<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
	  <LayoutOptions StartTileGroupCellWidth="6" />
	  <DefaultLayoutOverride>
		<StartLayoutCollection>
		  <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
			<start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
			  <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Brave.lnk" />
			  <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk" />
			  <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\File Explorer.lnk" />
			  <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Signal.lnk" />
			  <start:DesktopApplicationTile Size="2x2" Column="0" Row="2" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows System\Control Panel.lnk" />
			  <start:DesktopApplicationTile Size="2x2" Column="0" Row="2" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk" />
			</start:Group>
		  </defaultlayout:StartLayout>
		</StartLayoutCollection>
	  </DefaultLayoutOverride>
	</LayoutModificationTemplate>
"@

    #Delete layout file if it already exists
    If(Test-Path $layoutFile)
    {
        Remove-Item $layoutFile
    }

    #Creates the blank layout file
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @("HKLM", "HKCU")

    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        IF(!(Test-Path -Path $keyPath)) {
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases)
	{
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0

		Write-Host  -ForegroundColor Green "Search and Start Menu Tweaks Complete"
    }
	Write-Host -ForegroundColor Blue "----- Function CustomizeStartMenu: ACTION COMPLETE!"
}

#------ END Functions - Fresh Install------
#------ End Functions ------

#------ BEGIN RUN PROGRAM------

Start-Transcript $ENV:SYSTEMDRIVE\ProvisionMachineLog.txt
Write-Host -ForegroundColor Blue "----- Starting Program! "	
Write-Host -ForegroundColor Blue "----- Argument - FreshInstall: $FreshInstall"	
Write-Host -ForegroundColor Blue "----- Argument - SuperUser: $SuperUser"	

# Backup before we start messing with stuff
EnableSystemRestore

# Functions - Fresh install	Only
If ($FreshInstall)
{
	SetComputerName
	#RemoveAllApps - I don't think this is really necessary, and it wiped all the drivers off my system lol.
	CustomizeStartMenu # Will wipe away any pinned to start menu programs
}

# Functions - Universal
DisableTasks
DisableServices
RemoveBloatware
WindowsFeatures
RegChange
EnableRDP
InstallPrograms
ConfigureStartupPrograms
ConfigureDefender	
ConfigureWindowsUpdate

#Functions - Optional
ConfigurePowerOptions
CustomizeExplorer
CustomizeMisc
CustomizePersonalization 
DefaultPrograms #must be called after all programs are installed e.g. notepad++ and whatnot

# All Done!
Write-Host -ForegroundColor Blue "----- SCRIPT COMPLETE! "	
Write-Host -ForegroundColor Blue "----- Remember to set your execution policy back!  Set-Executionpolicy restricted is the Windows 10 default."
Write-Host -ForegroundColor Blue "----- Reboot your computer now!"     
Stop-Transcript

#------ END RUN PROGRAM------
