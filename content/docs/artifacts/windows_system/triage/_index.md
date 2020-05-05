---
description: Triage artifacts simply collect various files as quickly as possible.
  In recent versions of Velociraptor, many of the triage artifacts have been merged
  into the Windows.KapeFiles.Targets artifact.
linktitle: Triage
title: Triage Artifacts
weight: 60

---
## Windows.Triage.ProcessMemory

Dump process memory and upload to the server


Arg|Default|Description
---|------|-----------
processRegex|notepad|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Triage.ProcessMemory
description: |
  Dump process memory and upload to the server

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: processRegex
    default: notepad

sources:
  - queries:
      - |
        LET processes = SELECT Name as ProcessName, CommandLine, Pid
            FROM pslist()
            WHERE Name =~ processRegex

      - |
        SELECT * FROM foreach(
          row=processes,
          query={
            SELECT ProcessName, CommandLine, Pid, FullPath,
                   upload(file=FullPath) as CrashDump
            FROM proc_dump(pid=Pid)
          })
```
   {{% /expand %}}

## Windows.KapeFiles.Targets


Kape is a popular bulk collector tool for triaging a system
quickly. While KAPE itself is not an opensource tool, the logic it
uses to decide which files to collect is encoded in YAML files
hosted on the KapeFiles project
(https://github.com/EricZimmerman/KapeFiles) and released under an
MIT license.

This artifact is automatically generated from these YAML files,
contributed and maintained by the community. This artifact only
encapsulates the KAPE "Targets" - basically a bunch of glob
expressions used for collecting files on the endpoint. We do not
do any post processing these files - we just collect them.

We recommend that timeouts and upload limits be used
conservatively with this artifact because we can upload really
vast quantities of data very quickly.


Arg|Default|Description
---|------|-----------
_BasicCollection||Basic Collection (by Phill Moore): Thumbcache DB, at .job, at SchedLgU.txt, XML, Amcache, Amcache transaction files, $SDS, WindowsIndexSearch, $LogFile, $Boot, ntuser.dat registry hive XP, ntuser.dat  ...
_Boot||$Boot (by Eric Zimmerman): $Boot
_J||$J (by Eric Zimmerman): $J, $Max
_LogFile||$LogFile (by Eric Zimmerman): $LogFile
_MFT||$MFT (by Eric Zimmerman): $MFT
_SDS||$SDS (by Eric Zimmerman): $SDS
_T||$T (by Eric Zimmerman): $T
Amcache||Amcache.hve (by Eric Zimmerman): Amcache, Amcache transaction files
Ammyy||Ammyy Data (by Drew Ervin): Ammyy Program Data
ApacheAccessLog||Apache Access Log (by Hadar Yudovich): Apache Access Log
AppData||AppData (by Phill Moore): AppData
ApplicationEvents||Windows Application Event Log (by Drew Ervin): Application Event Log XP, Application Event Log Win7+
Avast||Avast Antivirus Data (by Drew Ervin): Avast AV User Logs, Avast AV Index, Avast AV Logs (XP), Avast AV Logs
AviraAVLogs||Avira Logs (by Fabian Murer): Avira Activity Logs
BCD||Boot Configuration Files (by Troy Larson): BCD, BCD Logs
Bitdefender||Bitdefender Antivirus Data (by Drew Ervin): Bitdefender Endpoint Security Logs
BoxDrive||Box Cloud Storage Files and Metadata (by Chad Tilbury): Box User Files, Box Drive Application Metadata, Box Sync Application Metadata
Chrome||Chrome (by Eric Zimmerman): Chrome Preferences, Chrome Shortcuts, Chrome Top Sites, Chrome bookmarks, Chrome Visited Links, Chrome Web Data, Chrome bookmarks XP, Chrome Cookies XP, Chrome Current Sess ...
ChromeExtensions||Chrome Extension Files (by piesecurity): Chrome Extension Files, Chrome Extension Files XP
CiscoJabber||Jabber (by Andrew Bannon): Cisco Jabber Database
CloudStorage||Cloud Storage Contents and Metadata (by Chad Tilbury): Google File Stream Metadata, OneDrive User Files, OneDrive Metadata Logs, OneDrive Metadata Settings, Box User Files, Box Drive Application Metad ...
CombinedLogs||Collect Event logs, Trace logs, Windows Firewall and PowerShell console (by Mike Cary): Windows Firewall Logs, WDI Trace Logs 1, WDI Trace Logs 2, WMI Trace Logs, SleepStudy Trace Logs, Energy-NTKL Tr ...
ComboFix||ComboFix Antivirus Data (by Drew Ervin): ComboFix
ConfluenceLogs||Confluence Log Files (by Eric Capuano): Confluence Wiki Log Files, Confluence Wiki Log Files
DirectoryTraversalWildCardExample||Find zip archives (by Eric Zimmerman): Zips
Dropbox||Dropbox Cloud Storage Files and Metadata (by Chad Tilbury): Dropbox User Files, Dropbox Metadata, Dropbox Metadata, Dropbox Metadata, Windows Protect Folder
ESET||ESET Antivirus Data (by Drew Ervin): ESET NOD32 AV Logs (XP), ESET NOD32 AV Logs
Edge||Edge (by Phill Moore): Edge folder, WebcacheV01.dat
EncapsulationLogging||EncapsulationLogging (by Troy Larson): EncapsulationLogging Logs, EncapsulationLogging
EventLogs_RDP||Collect Win7+ RDP related Event logs (by Mark Hallman): Event logs Win7+, Event logs Win7+, Event logs Win7+, Event logs Win7+
EventLogs||Event logs (by Eric Zimmerman): Event logs XP, Event logs Win7+
EventTraceLogs||Event Trace Logs (by Mark Hallman): WDI Trace Logs 1, WDI Trace Logs 2, WMI Trace Logs, SleepStudy Trace Logs, Energy-NTKL Trace Logs
EvidenceOfExecution||Evidence of execution related files (by Eric Zimmerman): RecentFileCache, Prefetch, Amcache transaction files, Syscache transaction files, Amcache, Syscache
Exchange||Exchange Log Files (by Keith Twombley): Exchange TransportRoles log files, Exchange client access log files
ExchangeClientAccess||Exchange Client Access Log Files (by Keith Twombley): Exchange client access log files
ExchangeTransport||Exchange Transport Log Files (by Keith Twombley): Exchange TransportRoles log files
FSecure||F-Secure Antivirus Data (by Drew Ervin): F-Secure Logs, F-Secure User Logs, F-Secure Scheduled Scan Reports
FileSystem||File system metadata (by Eric Zimmerman): $LogFile, $MFT, $Boot, $J, $Max, $T, $SDS
Firefox||Firefox (by Eric Zimmerman): Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, ...
Gigatribe||Gigatribe Files (by Linus Nissi): Gigatribe Files Windows XP, Gigatribe Files Windows XP, Gigatribe Files Windows Vista/7/8/10
GoogleDrive||Google Drive Storage Files and Metadata (by Chad Tilbury): Google File Stream Metadata, Google Drive User Files, Google Drive Metadata
GroupPolicy||Current Group Policy Enforcement (by piesecurity): Local Group Policy INI Files, Local Group Policy Files - Registry Policy Files, Local Group Policy Files - Startup/Shutdown Scripts
HitmanPro||HitmanPro Antivirus Data (by Drew Ervin): HitmanPro Logs, HitmanPro Alert Logs, HitmanPro Database
IISLogFiles||IIS Log Files (by Troy Larson): IIS log files, IIS log files, IIS log files, IIS log files
InternetExplorer||Internet Explorer (by Eric Zimmerman): Roaming Internet Explorer folder, IE 9/10 History, IE 9/10 Cache, IE 9/10 Cookies, IE 9/10 Download History, IE 11 Metadata, IE 11 Cache, IE 11 Cookies, Index.da ...
JavaWebCache||Java WebStart Cache - (IDX Files) (by piesecurity): Java WebStart Cache User Level - Default, Java WebStart Cache User Level - IE Protected Mode, Java WebStart Cache System level, Java WebStart Cache  ...
KapeTriage||Kape Triage collections that will collect most of the files needed for a DFIR Investigation.  This module pulls evidence from File System files, Registry Hives, Event Logs, Scheduled Tasks, Evidence o ...
Kaseya||Kaseya Data (by Drew Ervin): Kaseya Live Connect Logs (XP), Kaseya Live Connect Logs, Kaseya Agent Endpoint Service Logs (XP), Kaseya Agent Endpoint Service Logs, Kaseya Agent Service Log, Kaseya Setu ...
LinuxOnWindowsProfileFiles||Linux on Windows Profile Files (by Troy Larson): .bash_history, .bash_logout, .bashrc, .profile
LiveUserFiles||Live User Files (by Mark Hallman): User Files - Desktop, User Files - Documents, User Files - Downloads, User Files - Dropbox
LnkFilesAndJumpLists||Lnk files and jump lists (by Eric Zimmerman): Lnk files from Recent, Lnk files from Microsoft Office Recent, Lnk files from Recent (XP), Desktop lnk files XP, Desktop lnk files, Restore point lnk file ...
LogFiles||LogFiles (by Fabian Murer): LogFiles
LogMeIn||LogMeIn Data (by Drew Ervin): LogMeIn Application Logs, Application Event Log XP, Application Event Log Win7+, LogMeIn ProgramData Logs
MOF||MOF files (WMI) (by Eric Zimmerman): MOF files
MSSQLErrorLog||MS SQL ErrorLogs (by Troy Larson): MS SQL Errorlog, MS SQL Errorlogs
Malwarebytes||Malwarebytes Data (by Drew Ervin): MalwareBytes Anti-Malware Scan Logs, MalwareBytes Anti-Malware Logs, MalwareBytes Anti-Malware Service Logs
McAfee||McAfee Log Files (by Sam Smoker): McAfee Desktop Protection Logs XP, McAfee Desktop Protection Logs, McAfee Endpoint Security Logs, McAfee Endpoint Security Logs, McAfee VirusScan Logs
McAfee_ePO||McAfee ePO Log Files (by Doug Metz): McAfee ePO Logs
MiniTimelineCollection||MFT, Registry and Event Logs to generate a mini timeline (by Mari DeGrazia): $SDS, $LogFile, $Boot, ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser ...
NGINXLogs||NGINX Log Files (by Eric Capuano): NGINX Log Files
Notepad__||Notepad++ backup (by Banaanhangwagen): Notepad++ backup
OneDrive||Microsoft OneDrive Storage Files and Metadata (by Chad Tilbury): OneDrive User Files, OneDrive Metadata Logs, OneDrive Metadata Settings
OutlookPSTOST||Outlook PST and OST files (by Eric Zimmerman): PST XP, OST XP, PST, OST
PowerShellConsole||PowerShell Console Log File (by Mike Cary): PowerShell Console Log
Prefetch||Prefetch files (by Eric Zimmerman): Prefetch
RDPCache||RDP Cache Files (by Hadar Yudovich): RDP Cache Files, RDP Cache Files
RDPLogs||RDP Logs (by Drew Ervin): LocalSessionManager Event Logs, RDPClient Event Logs, RDPCoreTS Event Logs, RemoteConnectionManager Event Logs
RecentFileCache||Amcache.hve (by Eric Zimmerman): RecentFileCache
Recycle||Recycle Bin (by Mark Hallman): $Recycle.Bin, RECYCLER WinXP
RegistryHives||System and user related Registry hives (by Eric Zimmerman): ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat D ...
RegistryHivesSystem||System level/related Registry hives (by Eric Zimmerman / Mark Hallman): SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transa ...
RegistryHivesUser||User Related Registry hives (by Eric Zimmerman / Mark Hallman): ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.d ...
RemoteAdmin||Composite target for files related to remote administration tools (by Drew Ervin): ScreenConnect Session Database, ScreenConnect Session Database, Application Event Log XP, Application Event Log Win7+ ...
RogueKiller||RogueKiller Anti-Malware (by Adlice Software) (by Drew Ervin): RogueKiller Reports
SDB||Shim SDB FIles (by Troy Larson): SDB Files, SDB Files x64
SRUM||System Resource Usage Monitor (SRUM) Data (by Mark Hallman): SRUM
SUPERAntiSpyware||SUPERAntiSpyware Data (by Drew Ervin): SUPERAntiSpyware Logs
ScheduledTasks||Scheduled tasks (*.job and XML) (by Eric Zimmerman): at .job, at SchedLgU.txt, XML
ScreenConnect||ScreenConnect Data (now known as ConnectWise Control) (by Drew Ervin): Application Event Log XP, Application Event Log Win7+, ScreenConnect Session Database, ScreenConnect Session Database
SignatureCatalog||Obtain detached signature catalog files (by Mike Pilkington): SignatureCatalog
Skype||Skype (by Eric Zimmerman): leveldb (Skype for Desktop +v8), main.db (App <v12), skype.db (App +v12), main.db XP, main.db Win7+, s4l-[username].db (App +v8)
Sophos||Sophos Data (by Drew Ervin): Application Event Log XP, Sophos Logs (XP), Sophos Logs, Application Event Log Win7+
StartupInfo||StartupInfo XML Files (by Hadar Yudovich): StartupInfo XML Files
Symantec_AV_Logs||Symantec AV Logs (by Brian Maloney): Symantec Endpoint Protection Logs (XP), Symantec Endpoint Protection Logs, Symantec Endpoint Protection User Logs, Symantec Event Log Win7+, Application Event Log  ...
Syscache||syscache.hve (by Phill Moore): Syscache transaction files, Syscache
TeamViewerLogs||Team Viewer Logs (by Hadar Yudovich): TeamViewer Connection Logs, TeamViewer Application Logs, TeamViewer Configuration Files
TeraCopy||TeraCopy log history (by Kevin Pagano): TeraCopy
ThumbCache||Thumbcache DB (by Eric Zimmerman): Thumbcache DB
TorrentClients||Torrent Clients (by Banaanhangwagen): TorrentClients - qBittorrent, TorrentClients - qBittorrent, TorrentClients - uTorrent, TorrentClients - BitTorrent
Torrents||Torrent Files (by Tony Knutson): Torrents
TrendMicro||Trend Micro Data (by Drew Ervin): Trend Micro Logs, Trend Micro Security Agent Report Logs, Trend Micro Security Agent Connection Logs
USBDevicesLogs||USB devices log files (by Eric Zimmerman): Setupapi.log XP, Setupapi.log Win7+
VIPRE||VIPRE Data (by Drew Ervin): VIPRE Business User Logs (v5-v6), VIPRE Business User Logs (up to v4), VIPRE Business Agent Logs, VIPRE Business User Logs (v7+)
VNCLogs||VNC Logs (by Phill Moore): Application Event Log XP, Application Event Log Win7+, RealVNC Log
VirtualDisks||Virtual Disks (by Phill Moore): VHD, VHDX, VDI, VMDK
WBEM||Web-Based Enterprise Management (WBEM) (by Mark Hallman): WBEM
WER||Windows Error Reporting (by Troy Larson): WER Files, Crash Dumps, Crash Dumps
WebBrowsers||Web browser history, bookmarks, etc. (by Eric Zimmerman): Chrome Preferences, Chrome Shortcuts, Chrome Top Sites, Chrome bookmarks, Chrome Visited Links, Chrome Web Data, Places, Downloads, Form histo ...
WindowsDefender||Windows Defender Data (by Drew Ervin): Windows Defender Logs, Windows Defender Event Logs
WindowsFirewall||Windows Firewall Logs (by Mike Cary): Windows Firewall Logs
WindowsIndexSearch||Windows Index Search (by Mark Hallman): WindowsIndexSearch
WindowsNotifcationsDB||Windows 10 Notification DB (by Hadar Yudovich): Windows 10 Notification DB, Windows 10 Notification DB
WindowsTimeline||ActivitiesCache.db collector (by Lee Whitfield): ActivitiesCache.db-shm, ActivitiesCache.db-wal, ActivitiesCache.db
XPRestorePoints||XP Restore Points - System Volume Information directory (by Phill Moore): System Volume Information
iTunesBackup||iTunes Backups (by Tony Knutson): iTunes Backup Folder, iTunes Backup Folder
Device|C:|
VSSAnalysis|None|If set we run the collection across all VSS and collect only unique changes.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.KapeFiles.Targets
description: |

    Kape is a popular bulk collector tool for triaging a system
    quickly. While KAPE itself is not an opensource tool, the logic it
    uses to decide which files to collect is encoded in YAML files
    hosted on the KapeFiles project
    (https://github.com/EricZimmerman/KapeFiles) and released under an
    MIT license.

    This artifact is automatically generated from these YAML files,
    contributed and maintained by the community. This artifact only
    encapsulates the KAPE "Targets" - basically a bunch of glob
    expressions used for collecting files on the endpoint. We do not
    do any post processing these files - we just collect them.

    We recommend that timeouts and upload limits be used
    conservatively with this artifact because we can upload really
    vast quantities of data very quickly.

reference:
  - https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape
  - https://github.com/EricZimmerman/KapeFiles

parameters:
  - name: _BasicCollection
    description: "Basic Collection (by Phill Moore): Thumbcache DB, at .job, at SchedLgU.txt, XML, Amcache, Amcache transaction files, $SDS, WindowsIndexSearch, $LogFile, $Boot, ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat DEFAULT transaction files, UsrClass.dat registry hive, UsrClass.dat registry transaction files, Lnk files from Recent, Lnk files from Microsoft Office Recent, Lnk files from Recent (XP), Desktop lnk files XP, Desktop lnk files, Restore point lnk files XP, RecentFileCache, $MFT, SRUM, $J, $Max, Setupapi.log XP, Setupapi.log Win7+, $Recycle.Bin, RECYCLER WinXP, Prefetch, Syscache, Syscache transaction files, Event logs XP, Event logs Win7+, SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transaction files, PowerShell Console Log, SAM registry hive, SECURITY registry hive, SOFTWARE registry hive, SYSTEM registry hive, RegBack registry transaction files, SAM registry hive (RegBack), SECURITY registry hive (RegBack), SOFTWARE registry hive (RegBack), SYSTEM registry hive (RegBack), SYSTEM registry hive (RegBack), System Profile registry hive, System Profile registry transaction files, Local Service registry hive, Local Service registry transaction files, Network Service registry hive, Network Service registry transaction files, System Restore Points Registry Hives (XP), $T"
    type: bool
  - name: _Boot
    description: "$Boot (by Eric Zimmerman): $Boot"
    type: bool
  - name: _J
    description: "$J (by Eric Zimmerman): $J, $Max"
    type: bool
  - name: _LogFile
    description: "$LogFile (by Eric Zimmerman): $LogFile"
    type: bool
  - name: _MFT
    description: "$MFT (by Eric Zimmerman): $MFT"
    type: bool
  - name: _SDS
    description: "$SDS (by Eric Zimmerman): $SDS"
    type: bool
  - name: _T
    description: "$T (by Eric Zimmerman): $T"
    type: bool
  - name: Amcache
    description: "Amcache.hve (by Eric Zimmerman): Amcache, Amcache transaction files"
    type: bool
  - name: Ammyy
    description: "Ammyy Data (by Drew Ervin): Ammyy Program Data"
    type: bool
  - name: ApacheAccessLog
    description: "Apache Access Log (by Hadar Yudovich): Apache Access Log"
    type: bool
  - name: AppData
    description: "AppData (by Phill Moore): AppData"
    type: bool
  - name: ApplicationEvents
    description: "Windows Application Event Log (by Drew Ervin): Application Event Log XP, Application Event Log Win7+"
    type: bool
  - name: Avast
    description: "Avast Antivirus Data (by Drew Ervin): Avast AV User Logs, Avast AV Index, Avast AV Logs (XP), Avast AV Logs"
    type: bool
  - name: AviraAVLogs
    description: "Avira Logs (by Fabian Murer): Avira Activity Logs"
    type: bool
  - name: BCD
    description: "Boot Configuration Files (by Troy Larson): BCD, BCD Logs"
    type: bool
  - name: Bitdefender
    description: "Bitdefender Antivirus Data (by Drew Ervin): Bitdefender Endpoint Security Logs"
    type: bool
  - name: BoxDrive
    description: "Box Cloud Storage Files and Metadata (by Chad Tilbury): Box User Files, Box Drive Application Metadata, Box Sync Application Metadata"
    type: bool
  - name: Chrome
    description: "Chrome (by Eric Zimmerman): Chrome Preferences, Chrome Shortcuts, Chrome Top Sites, Chrome bookmarks, Chrome Visited Links, Chrome Web Data, Chrome bookmarks XP, Chrome Cookies XP, Chrome Current Session XP, Chrome Current Tabs XP, Chrome Favicons XP, Chrome History XP, Chrome Last Session XP, Chrome Last Tabs XP, Chrome Preferences XP, Chrome Shortcuts XP, Chrome Top Sites XP, Chrome bookmarks XP, Chrome Visited Links XP, Chrome Web Data XP, Chrome bookmarks, Chrome Cookies, Chrome Current Session, Chrome Current Tabs, Chrome Favicons, Chrome History, Chrome Last Session, Chrome Last Tabs"
    type: bool
  - name: ChromeExtensions
    description: "Chrome Extension Files (by piesecurity): Chrome Extension Files, Chrome Extension Files XP"
    type: bool
  - name: CiscoJabber
    description: "Jabber (by Andrew Bannon): Cisco Jabber Database"
    type: bool
  - name: CloudStorage
    description: "Cloud Storage Contents and Metadata (by Chad Tilbury): Google File Stream Metadata, OneDrive User Files, OneDrive Metadata Logs, OneDrive Metadata Settings, Box User Files, Box Drive Application Metadata, Box Sync Application Metadata, Dropbox User Files, Dropbox Metadata, Dropbox Metadata, Dropbox Metadata, Windows Protect Folder, Google Drive User Files, Google Drive Metadata"
    type: bool
  - name: CombinedLogs
    description: "Collect Event logs, Trace logs, Windows Firewall and PowerShell console (by Mike Cary): Windows Firewall Logs, WDI Trace Logs 1, WDI Trace Logs 2, WMI Trace Logs, SleepStudy Trace Logs, Energy-NTKL Trace Logs, PowerShell Console Log, Event logs XP, Event logs Win7+"
    type: bool
  - name: ComboFix
    description: "ComboFix Antivirus Data (by Drew Ervin): ComboFix"
    type: bool
  - name: ConfluenceLogs
    description: "Confluence Log Files (by Eric Capuano): Confluence Wiki Log Files, Confluence Wiki Log Files"
    type: bool
  - name: DirectoryTraversalWildCardExample
    description: "Find zip archives (by Eric Zimmerman): Zips"
    type: bool
  - name: Dropbox
    description: "Dropbox Cloud Storage Files and Metadata (by Chad Tilbury): Dropbox User Files, Dropbox Metadata, Dropbox Metadata, Dropbox Metadata, Windows Protect Folder"
    type: bool
  - name: ESET
    description: "ESET Antivirus Data (by Drew Ervin): ESET NOD32 AV Logs (XP), ESET NOD32 AV Logs"
    type: bool
  - name: Edge
    description: "Edge (by Phill Moore): Edge folder, WebcacheV01.dat"
    type: bool
  - name: EncapsulationLogging
    description: "EncapsulationLogging (by Troy Larson): EncapsulationLogging Logs, EncapsulationLogging"
    type: bool
  - name: EventLogs_RDP
    description: "Collect Win7+ RDP related Event logs (by Mark Hallman): Event logs Win7+, Event logs Win7+, Event logs Win7+, Event logs Win7+"
    type: bool
  - name: EventLogs
    description: "Event logs (by Eric Zimmerman): Event logs XP, Event logs Win7+"
    type: bool
  - name: EventTraceLogs
    description: "Event Trace Logs (by Mark Hallman): WDI Trace Logs 1, WDI Trace Logs 2, WMI Trace Logs, SleepStudy Trace Logs, Energy-NTKL Trace Logs"
    type: bool
  - name: EvidenceOfExecution
    description: "Evidence of execution related files (by Eric Zimmerman): RecentFileCache, Prefetch, Amcache transaction files, Syscache transaction files, Amcache, Syscache"
    type: bool
  - name: Exchange
    description: "Exchange Log Files (by Keith Twombley): Exchange TransportRoles log files, Exchange client access log files"
    type: bool
  - name: ExchangeClientAccess
    description: "Exchange Client Access Log Files (by Keith Twombley): Exchange client access log files"
    type: bool
  - name: ExchangeTransport
    description: "Exchange Transport Log Files (by Keith Twombley): Exchange TransportRoles log files"
    type: bool
  - name: FSecure
    description: "F-Secure Antivirus Data (by Drew Ervin): F-Secure Logs, F-Secure User Logs, F-Secure Scheduled Scan Reports"
    type: bool
  - name: FileSystem
    description: "File system metadata (by Eric Zimmerman): $LogFile, $MFT, $Boot, $J, $Max, $T, $SDS"
    type: bool
  - name: Firefox
    description: "Firefox (by Eric Zimmerman): Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search"
    type: bool
  - name: Gigatribe
    description: "Gigatribe Files (by Linus Nissi): Gigatribe Files Windows XP, Gigatribe Files Windows XP, Gigatribe Files Windows Vista/7/8/10"
    type: bool
  - name: GoogleDrive
    description: "Google Drive Storage Files and Metadata (by Chad Tilbury): Google File Stream Metadata, Google Drive User Files, Google Drive Metadata"
    type: bool
  - name: GroupPolicy
    description: "Current Group Policy Enforcement (by piesecurity): Local Group Policy INI Files, Local Group Policy Files - Registry Policy Files, Local Group Policy Files - Startup/Shutdown Scripts"
    type: bool
  - name: HitmanPro
    description: "HitmanPro Antivirus Data (by Drew Ervin): HitmanPro Logs, HitmanPro Alert Logs, HitmanPro Database"
    type: bool
  - name: IISLogFiles
    description: "IIS Log Files (by Troy Larson): IIS log files, IIS log files, IIS log files, IIS log files"
    type: bool
  - name: InternetExplorer
    description: "Internet Explorer (by Eric Zimmerman): Roaming Internet Explorer folder, IE 9/10 History, IE 9/10 Cache, IE 9/10 Cookies, IE 9/10 Download History, IE 11 Metadata, IE 11 Cache, IE 11 Cookies, Index.dat History, Index.dat History subdirectory, Index.dat temp internet files, Index.dat cookies, Index.dat UserData, Index.dat Office XP, Index.dat Office, Local Internet Explorer folder"
    type: bool
  - name: JavaWebCache
    description: "Java WebStart Cache - (IDX Files) (by piesecurity): Java WebStart Cache User Level - Default, Java WebStart Cache User Level - IE Protected Mode, Java WebStart Cache System level, Java WebStart Cache System level - IE Protected Mode, Java WebStart Cache System level (SysWow64), Java WebStart Cache System level (SysWow64) - IE Protected Mode, Java WebStart Cache User Level - XP"
    type: bool
  - name: KapeTriage
    description: "Kape Triage collections that will collect most of the files needed for a DFIR Investigation.  This module pulls evidence from File System files, Registry Hives, Event Logs, Scheduled Tasks, Evidence of Execution, SRUM data, Web Browser data (IE/Edge, Chrome, Mozilla history), LNK Files, Jump Lists, 3rd party remote access software logs, 3rd party antivirus software logs. (by Scott Downie): at .job, at SchedLgU.txt, XML, Amcache, Amcache transaction files, Application Event Log XP, Application Event Log Win7+, $SDS, $LogFile, $Boot, ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat DEFAULT transaction files, UsrClass.dat registry hive, UsrClass.dat registry transaction files, Lnk files from Recent, Lnk files from Microsoft Office Recent, Lnk files from Recent (XP), Desktop lnk files XP, Desktop lnk files, Restore point lnk files XP, RemoteConnectionManager Event Logs, LocalSessionManager Event Logs, RDPClient Event Logs, RDPCoreTS Event Logs, RecentFileCache, $MFT, SRUM, $J, $Max, Prefetch, Syscache, Syscache transaction files, Event logs XP, Event logs Win7+, RDP Cache Files, RDP Cache Files, SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transaction files, SAM registry hive, SECURITY registry hive, SOFTWARE registry hive, SYSTEM registry hive, RegBack registry transaction files, SAM registry hive (RegBack), SECURITY registry hive (RegBack), SOFTWARE registry hive (RegBack), SYSTEM registry hive (RegBack), SYSTEM registry hive (RegBack), System Profile registry hive, System Profile registry transaction files, Local Service registry hive, Local Service registry transaction files, Network Service registry hive, Network Service registry transaction files, System Restore Points Registry Hives (XP), $T, LogMeIn ProgramData Logs, LogMeIn Application Logs, RealVNC Log, ScreenConnect Session Database, ScreenConnect Session Database, TeamViewer Connection Logs, TeamViewer Application Logs, TeamViewer Configuration Files, Kaseya Live Connect Logs (XP), Kaseya Live Connect Logs, Kaseya Agent Endpoint Service Logs (XP), Kaseya Agent Endpoint Service Logs, Kaseya Agent Service Log, Kaseya Setup Log, Kaseya Setup Log, Ammyy, Edge folder, WebcacheV01.dat, Chrome bookmarks XP, Chrome Cookies XP, Chrome Current Session XP, Chrome Current Tabs XP, Chrome Favicons XP, Chrome History XP, Chrome Last Session XP, Chrome Last Tabs XP, Chrome Preferences XP, Chrome Shortcuts XP, Chrome Top Sites XP, Chrome bookmarks XP, Chrome Visited Links XP, Chrome Web Data XP, Chrome bookmarks, Chrome Cookies, Chrome Current Session, Chrome Current Tabs, Chrome Favicons, Chrome History, Chrome Last Session, Chrome Last Tabs, Chrome Preferences, Chrome Shortcuts, Chrome Top Sites, Chrome bookmarks, Chrome Visited Links, Chrome Web Data, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Index.dat History, Index.dat History subdirectory, Index.dat temp internet files, Index.dat cookies, Index.dat UserData, Index.dat Office XP, Index.dat Office, Local Internet Explorer folder, Roaming Internet Explorer folder, IE 9/10 History, IE 9/10 Cache, IE 9/10 Cookies, IE 9/10 Download History, IE 11 Metadata, IE 11 Cache, IE 11 Cookies"
    type: bool
  - name: Kaseya
    description: "Kaseya Data (by Drew Ervin): Kaseya Live Connect Logs (XP), Kaseya Live Connect Logs, Kaseya Agent Endpoint Service Logs (XP), Kaseya Agent Endpoint Service Logs, Kaseya Agent Service Log, Kaseya Setup Log, Kaseya Setup Log"
    type: bool
  - name: LinuxOnWindowsProfileFiles
    description: "Linux on Windows Profile Files (by Troy Larson): .bash_history, .bash_logout, .bashrc, .profile"
    type: bool
  - name: LiveUserFiles
    description: "Live User Files (by Mark Hallman): User Files - Desktop, User Files - Documents, User Files - Downloads, User Files - Dropbox"
    type: bool
  - name: LnkFilesAndJumpLists
    description: "Lnk files and jump lists (by Eric Zimmerman): Lnk files from Recent, Lnk files from Microsoft Office Recent, Lnk files from Recent (XP), Desktop lnk files XP, Desktop lnk files, Restore point lnk files XP"
    type: bool
  - name: LogFiles
    description: "LogFiles (by Fabian Murer): LogFiles"
    type: bool
  - name: LogMeIn
    description: "LogMeIn Data (by Drew Ervin): LogMeIn Application Logs, Application Event Log XP, Application Event Log Win7+, LogMeIn ProgramData Logs"
    type: bool
  - name: MOF
    description: "MOF files (WMI) (by Eric Zimmerman): MOF files"
    type: bool
  - name: MSSQLErrorLog
    description: "MS SQL ErrorLogs (by Troy Larson): MS SQL Errorlog, MS SQL Errorlogs"
    type: bool
  - name: Malwarebytes
    description: "Malwarebytes Data (by Drew Ervin): MalwareBytes Anti-Malware Scan Logs, MalwareBytes Anti-Malware Logs, MalwareBytes Anti-Malware Service Logs"
    type: bool
  - name: McAfee
    description: "McAfee Log Files (by Sam Smoker): McAfee Desktop Protection Logs XP, McAfee Desktop Protection Logs, McAfee Endpoint Security Logs, McAfee Endpoint Security Logs, McAfee VirusScan Logs"
    type: bool
  - name: McAfee_ePO
    description: "McAfee ePO Log Files (by Doug Metz): McAfee ePO Logs"
    type: bool
  - name: MiniTimelineCollection
    description: "MFT, Registry and Event Logs to generate a mini timeline (by Mari DeGrazia): $SDS, $LogFile, $Boot, ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat DEFAULT transaction files, UsrClass.dat registry hive, UsrClass.dat registry transaction files, $MFT, $J, $Max, Event logs XP, Event logs Win7+, SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transaction files, SAM registry hive, SECURITY registry hive, SOFTWARE registry hive, SYSTEM registry hive, RegBack registry transaction files, SAM registry hive (RegBack), SECURITY registry hive (RegBack), SOFTWARE registry hive (RegBack), SYSTEM registry hive (RegBack), SYSTEM registry hive (RegBack), System Profile registry hive, System Profile registry transaction files, Local Service registry hive, Local Service registry transaction files, Network Service registry hive, Network Service registry transaction files, System Restore Points Registry Hives (XP), $T"
    type: bool
  - name: NGINXLogs
    description: "NGINX Log Files (by Eric Capuano): NGINX Log Files"
    type: bool
  - name: Notepad__
    description: "Notepad++ backup (by Banaanhangwagen): Notepad++ backup"
    type: bool
  - name: OneDrive
    description: "Microsoft OneDrive Storage Files and Metadata (by Chad Tilbury): OneDrive User Files, OneDrive Metadata Logs, OneDrive Metadata Settings"
    type: bool
  - name: OutlookPSTOST
    description: "Outlook PST and OST files (by Eric Zimmerman): PST XP, OST XP, PST, OST"
    type: bool
  - name: PowerShellConsole
    description: "PowerShell Console Log File (by Mike Cary): PowerShell Console Log"
    type: bool
  - name: Prefetch
    description: "Prefetch files (by Eric Zimmerman): Prefetch"
    type: bool
  - name: RDPCache
    description: "RDP Cache Files (by Hadar Yudovich): RDP Cache Files, RDP Cache Files"
    type: bool
  - name: RDPLogs
    description: "RDP Logs (by Drew Ervin): LocalSessionManager Event Logs, RDPClient Event Logs, RDPCoreTS Event Logs, RemoteConnectionManager Event Logs"
    type: bool
  - name: RecentFileCache
    description: "Amcache.hve (by Eric Zimmerman): RecentFileCache"
    type: bool
  - name: Recycle
    description: "Recycle Bin (by Mark Hallman): $Recycle.Bin, RECYCLER WinXP"
    type: bool
  - name: RegistryHives
    description: "System and user related Registry hives (by Eric Zimmerman): ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat DEFAULT transaction files, UsrClass.dat registry hive, UsrClass.dat registry transaction files, SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transaction files, SAM registry hive, SECURITY registry hive, SOFTWARE registry hive, SYSTEM registry hive, RegBack registry transaction files, SAM registry hive (RegBack), SECURITY registry hive (RegBack), SOFTWARE registry hive (RegBack), SYSTEM registry hive (RegBack), SYSTEM registry hive (RegBack), System Profile registry hive, System Profile registry transaction files, Local Service registry hive, Local Service registry transaction files, Network Service registry hive, Network Service registry transaction files, System Restore Points Registry Hives (XP)"
    type: bool
  - name: RegistryHivesSystem
    description: "System level/related Registry hives (by Eric Zimmerman / Mark Hallman): SAM registry transaction files, SECURITY registry transaction files, SOFTWARE registry transaction files, SYSTEM registry transaction files, SAM registry hive, SECURITY registry hive, SOFTWARE registry hive, SYSTEM registry hive, RegBack registry transaction files, SAM registry hive (RegBack), SECURITY registry hive (RegBack), SOFTWARE registry hive (RegBack), SYSTEM registry hive (RegBack), SYSTEM registry hive (RegBack), System Profile registry hive, System Profile registry transaction files, Local Service registry hive, Local Service registry transaction files, Network Service registry hive, Network Service registry transaction files, System Restore Points Registry Hives (XP)"
    type: bool
  - name: RegistryHivesUser
    description: "User Related Registry hives (by Eric Zimmerman / Mark Hallman): ntuser.dat registry hive XP, ntuser.dat registry hive, ntuser.dat registry transaction files, ntuser.dat DEFAULT registry hive, ntuser.dat DEFAULT transaction files, UsrClass.dat registry hive, UsrClass.dat registry transaction files"
    type: bool
  - name: RemoteAdmin
    description: "Composite target for files related to remote administration tools (by Drew Ervin): ScreenConnect Session Database, ScreenConnect Session Database, Application Event Log XP, Application Event Log Win7+, TeamViewer Connection Logs, TeamViewer Application Logs, TeamViewer Configuration Files, Kaseya Live Connect Logs (XP), Kaseya Live Connect Logs, Kaseya Agent Endpoint Service Logs (XP), Kaseya Agent Endpoint Service Logs, Kaseya Agent Service Log, Kaseya Setup Log, Kaseya Setup Log, RemoteConnectionManager Event Logs, LocalSessionManager Event Logs, RDPClient Event Logs, RDPCoreTS Event Logs, Ammyy, RDP Cache Files, RDP Cache Files, LogMeIn ProgramData Logs, LogMeIn Application Logs, RealVNC Log"
    type: bool
  - name: RogueKiller
    description: "RogueKiller Anti-Malware (by Adlice Software) (by Drew Ervin): RogueKiller Reports"
    type: bool
  - name: SDB
    description: "Shim SDB FIles (by Troy Larson): SDB Files, SDB Files x64"
    type: bool
  - name: SRUM
    description: "System Resource Usage Monitor (SRUM) Data (by Mark Hallman): SRUM"
    type: bool
  - name: SUPERAntiSpyware
    description: "SUPERAntiSpyware Data (by Drew Ervin): SUPERAntiSpyware Logs"
    type: bool
  - name: ScheduledTasks
    description: "Scheduled tasks (*.job and XML) (by Eric Zimmerman): at .job, at SchedLgU.txt, XML"
    type: bool
  - name: ScreenConnect
    description: "ScreenConnect Data (now known as ConnectWise Control) (by Drew Ervin): Application Event Log XP, Application Event Log Win7+, ScreenConnect Session Database, ScreenConnect Session Database"
    type: bool
  - name: SignatureCatalog
    description: "Obtain detached signature catalog files (by Mike Pilkington): SignatureCatalog"
    type: bool
  - name: Skype
    description: "Skype (by Eric Zimmerman): leveldb (Skype for Desktop +v8), main.db (App <v12), skype.db (App +v12), main.db XP, main.db Win7+, s4l-[username].db (App +v8)"
    type: bool
  - name: Sophos
    description: "Sophos Data (by Drew Ervin): Application Event Log XP, Sophos Logs (XP), Sophos Logs, Application Event Log Win7+"
    type: bool
  - name: StartupInfo
    description: "StartupInfo XML Files (by Hadar Yudovich): StartupInfo XML Files"
    type: bool
  - name: Symantec_AV_Logs
    description: "Symantec AV Logs (by Brian Maloney): Symantec Endpoint Protection Logs (XP), Symantec Endpoint Protection Logs, Symantec Endpoint Protection User Logs, Symantec Event Log Win7+, Application Event Log XP, Application Event Log Win7+"
    type: bool
  - name: Syscache
    description: "syscache.hve (by Phill Moore): Syscache transaction files, Syscache"
    type: bool
  - name: TeamViewerLogs
    description: "Team Viewer Logs (by Hadar Yudovich): TeamViewer Connection Logs, TeamViewer Application Logs, TeamViewer Configuration Files"
    type: bool
  - name: TeraCopy
    description: "TeraCopy log history (by Kevin Pagano): TeraCopy"
    type: bool
  - name: ThumbCache
    description: "Thumbcache DB (by Eric Zimmerman): Thumbcache DB"
    type: bool
  - name: TorrentClients
    description: "Torrent Clients (by Banaanhangwagen): TorrentClients - qBittorrent, TorrentClients - qBittorrent, TorrentClients - uTorrent, TorrentClients - BitTorrent"
    type: bool
  - name: Torrents
    description: "Torrent Files (by Tony Knutson): Torrents"
    type: bool
  - name: TrendMicro
    description: "Trend Micro Data (by Drew Ervin): Trend Micro Logs, Trend Micro Security Agent Report Logs, Trend Micro Security Agent Connection Logs"
    type: bool
  - name: USBDevicesLogs
    description: "USB devices log files (by Eric Zimmerman): Setupapi.log XP, Setupapi.log Win7+"
    type: bool
  - name: VIPRE
    description: "VIPRE Data (by Drew Ervin): VIPRE Business User Logs (v5-v6), VIPRE Business User Logs (up to v4), VIPRE Business Agent Logs, VIPRE Business User Logs (v7+)"
    type: bool
  - name: VNCLogs
    description: "VNC Logs (by Phill Moore): Application Event Log XP, Application Event Log Win7+, RealVNC Log"
    type: bool
  - name: VirtualDisks
    description: "Virtual Disks (by Phill Moore): VHD, VHDX, VDI, VMDK"
    type: bool
  - name: WBEM
    description: "Web-Based Enterprise Management (WBEM) (by Mark Hallman): WBEM"
    type: bool
  - name: WER
    description: "Windows Error Reporting (by Troy Larson): WER Files, Crash Dumps, Crash Dumps"
    type: bool
  - name: WebBrowsers
    description: "Web browser history, bookmarks, etc. (by Eric Zimmerman): Chrome Preferences, Chrome Shortcuts, Chrome Top Sites, Chrome bookmarks, Chrome Visited Links, Chrome Web Data, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Places, Downloads, Form history, Cookies, Signons, Webappstore, Favicons, Addons, Search, Index.dat History, Index.dat History subdirectory, Index.dat temp internet files, Index.dat cookies, Index.dat UserData, Index.dat Office XP, Index.dat Office, Local Internet Explorer folder, Roaming Internet Explorer folder, IE 9/10 History, IE 9/10 Cache, IE 9/10 Cookies, IE 9/10 Download History, IE 11 Metadata, IE 11 Cache, IE 11 Cookies, Edge folder, WebcacheV01.dat, Chrome bookmarks XP, Chrome Cookies XP, Chrome Current Session XP, Chrome Current Tabs XP, Chrome Favicons XP, Chrome History XP, Chrome Last Session XP, Chrome Last Tabs XP, Chrome Preferences XP, Chrome Shortcuts XP, Chrome Top Sites XP, Chrome bookmarks XP, Chrome Visited Links XP, Chrome Web Data XP, Chrome bookmarks, Chrome Cookies, Chrome Current Session, Chrome Current Tabs, Chrome Favicons, Chrome History, Chrome Last Session, Chrome Last Tabs"
    type: bool
  - name: WindowsDefender
    description: "Windows Defender Data (by Drew Ervin): Windows Defender Logs, Windows Defender Event Logs"
    type: bool
  - name: WindowsFirewall
    description: "Windows Firewall Logs (by Mike Cary): Windows Firewall Logs"
    type: bool
  - name: WindowsIndexSearch
    description: "Windows Index Search (by Mark Hallman): WindowsIndexSearch"
    type: bool
  - name: WindowsNotifcationsDB
    description: "Windows 10 Notification DB (by Hadar Yudovich): Windows 10 Notification DB, Windows 10 Notification DB"
    type: bool
  - name: WindowsTimeline
    description: "ActivitiesCache.db collector (by Lee Whitfield): ActivitiesCache.db-shm, ActivitiesCache.db-wal, ActivitiesCache.db"
    type: bool
  - name: XPRestorePoints
    description: "XP Restore Points - System Volume Information directory (by Phill Moore): System Volume Information"
    type: bool
  - name: iTunesBackup
    description: "iTunes Backups (by Tony Knutson): iTunes Backup Folder, iTunes Backup Folder"
    type: bool

  - name: KapeRules
    type: hidden
    description: A CSV file controlling the different Kape Target Rules
    default: |
      Id,Name,Category,Glob,Accessor,Comment
      1,AppData,UserData,Users\*\AppData\/**10,lazy_ntfs,
      2,Zips,Archives,/**10/*.zip,lazy_ntfs,This is an example of how to walk a drive for a file mask. Probably do not want to use this one as is
      3,User Files - Desktop,LiveUserFiles,Users\*\Desktop/**10,lazy_ntfs,
      4,User Files - Documents,LiveUserFiles,Users\*\Documents/**10,lazy_ntfs,
      5,User Files - Downloads,LiveUserFiles,Users\*\Downloads/**10,lazy_ntfs,
      6,User Files - Dropbox,LiveUserFiles,Users\*\Dropbox*\/**10,lazy_ntfs,
      7,Gigatribe Files Windows Vista/7/8/10,FileDownload,Users\*\AppData\Local\Shalsoft\*/**10,lazy_ntfs,Locates Gigatribe files and copies them
      8,Gigatribe Files Windows XP,FileDownload,Documents and settings\*\*\Application Data\Gigatribe\*/**10,lazy_ntfs,Locates Gigatribe files and copies them. Different path depending on the Operating System language. In Swedish the location is C:\Documents and settings\<username>\Lokala Inställningar\Application Data\Gigatribe
      9,Gigatribe Files Windows XP,FileDownload,Documents and settings\*\*\Application Data\Shalsoft\*/**10,lazy_ntfs,Locates Gigatribe files and copies them. Different path depending on the Operating System language. In Swedish the location is C:\Documents and settings\<username>\Lokala Inställningar\Application Data\Shalsoft
      10,TorrentClients - qBittorrent,FileDownload,Users\*\AppData\Roaming\qBittorrent\*.ini,lazy_ntfs,Locates settings files and copies them
      11,TorrentClients - qBittorrent,FileDownload,Users\*\AppData\Local\qBittorrent\logs,lazy_ntfs,Locates log files and copies them
      12,TorrentClients - uTorrent,FileDownload,Users\*\AppData\Roaming\uTorrent\*.dat,lazy_ntfs,Locates settings files and copies them
      13,TorrentClients - BitTorrent,FileDownload,Users\*\AppData\Roaming\BitTorrent\*.dat,lazy_ntfs,Locates settings files and copies them
      14,Torrents,FileDownload,/**10/*.torrent,lazy_ntfs,Locates .torrent files and copies them
      15,Thumbcache DB,FileKnowledge,Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db,lazy_ntfs,
      16,SignatureCatalog,FileMetadata,Windows*\System32\CatRoot/**10,lazy_ntfs,
      17,at .job,Persistence,Windows*\Tasks\*.job,lazy_ntfs,
      18,at SchedLgU.txt,Persistence,Windows*\SchedLgU.txt,lazy_ntfs,
      19,XML,Persistence,Windows*\system32\Tasks/**10,lazy_ntfs,
      20,BCD,Registry,Boot\BCD,lazy_ntfs,
      21,BCD Logs,Registry,Boot\BCD.LOG*,lazy_ntfs,
      22,Amcache,ApplicationCompatibility,Windows*\AppCompat\Programs\Amcache.hve,lazy_ntfs,
      23,Amcache transaction files,ApplicationCompatibility,Windows*\AppCompat\Programs\Amcache.hve.LOG*,lazy_ntfs,
      24,Application Event Log XP,EventLogs,Windows*\system32\config\AppEvent.evt,lazy_ntfs,
      25,Application Event Log Win7+,EventLogs,Windows*\system32\winevt\logs\application.evtx,lazy_ntfs,
      26,$SDS,FileSystem,$Secure:$SDS,ntfs,
      27,.bash_history,Windows Linux Profile,Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.bash_history,lazy_ntfs,
      28,.bash_logout,Windows Linux Profile,Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.bash_logout,lazy_ntfs,
      29,.bashrc,Windows Linux Profile,Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.bashrc,lazy_ntfs,
      30,.profile,Windows Linux Profile,Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.profile,lazy_ntfs,
      31,ActivitiesCache.db,FileFolderAccess,Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db,lazy_ntfs,
      32,ActivitiesCache.db-shm,FileFolderAccess,Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db-shm,lazy_ntfs,
      33,ActivitiesCache.db-wal,FileFolderAccess,Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db-wal,lazy_ntfs,
      34,Windows Firewall Logs,WindowsFirewallLogs,Windows*\System32\LogFiles\Firewall\pfirewall.*,lazy_ntfs,
      35,System Volume Information,Folder capture,System Volume Information/**10,lazy_ntfs,
      36,WER Files,Executables,ProgramData\Microsoft\Windows\WER/**10,lazy_ntfs,
      37,Crash Dumps,SQL Exploitation,Users\*\AppData\Local\CrashDumps\*.dmp,lazy_ntfs,
      38,Crash Dumps,SQL Exploitation,Windows*\*.dmp,lazy_ntfs,
      39,EncapsulationLogging,Executables,Windows*\Appcompat\Programs\EncapsulationLogging.hve,lazy_ntfs,
      40,EncapsulationLogging Logs,Executables,Windows*\Appcompat\Programs\EncapsulationLogging.log*,lazy_ntfs,
      41,SDB Files,Executables,Windows*\apppatch\Custom\*.sdb,lazy_ntfs,
      42,SDB Files x64,Executables,Windows*\apppatch\Custom\Custom64\*.sdb,lazy_ntfs,
      43,WindowsIndexSearch,FileKnowledge,programdata\microsoft\search\data\applications\windows\Windows.edb,lazy_ntfs,
      44,$LogFile,FileSystem,$LogFile,lazy_ntfs,
      45,$Boot,FileSystem,$Boot,lazy_ntfs,
      46,ntuser.dat registry hive XP,Registry,Documents and Settings\*\ntuser.dat,lazy_ntfs,
      47,ntuser.dat registry hive,Registry,Users\*\ntuser.dat,lazy_ntfs,
      48,ntuser.dat registry transaction files,Registry,Users\*\ntuser.dat.LOG*,lazy_ntfs,
      49,ntuser.dat DEFAULT registry hive,Registry,Windows*\System32\config\DEFAULT,lazy_ntfs,
      50,ntuser.dat DEFAULT transaction files,Registry,Windows*\System32\config\DEFAULT.LOG*,lazy_ntfs,
      51,UsrClass.dat registry hive,Registry,Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat,lazy_ntfs,
      52,UsrClass.dat registry transaction files,Registry,Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG*,lazy_ntfs,
      53,Lnk files from Recent,LnkFiles,Users\*\AppData\Roaming\Microsoft\Windows\Recent/**10,lazy_ntfs,Also includes automatic and custom jumplist directories
      54,Lnk files from Microsoft Office Recent,LnkFiles,Users\*\AppData\Roaming\Microsoft\Office\Recent/**10,lazy_ntfs,
      55,Lnk files from Recent (XP),LnkFiles,Documents and Settings\*\Recent/**10,lazy_ntfs,
      56,Desktop lnk files XP,LnkFiles,Documents and Settings\*\Desktop\*.lnk,lazy_ntfs,
      57,Desktop lnk files,LnkFiles,Users\*\Desktop\*.lnk,lazy_ntfs,
      58,Restore point lnk files XP,LnkFiles,System Volume Information\_restore*\RP*\*.lnk,lazy_ntfs,
      59,Local Group Policy INI Files,Communication,Windows*\system32\grouppolicy\*.ini,lazy_ntfs,
      60,Local Group Policy Files - Registry Policy Files,Communication,Windows*\system32\grouppolicy\*.pol,lazy_ntfs,
      61,Local Group Policy Files - Startup/Shutdown Scripts,Communication,Windows*\system32\grouppolicy\*\Scripts/**10,lazy_ntfs,
      62,StartupInfo XML Files,Persistence,Windows*\System32\WDI\LogFiles\StartupInfo\*.xml,lazy_ntfs,
      63,RemoteConnectionManager Event Logs,EventLogs,Windows*\system32\winevt\logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager*,lazy_ntfs,
      64,LocalSessionManager Event Logs,EventLogs,Windows*\system32\winevt\logs\Microsoft-Windows-TerminalServices-LocalSessionManager*,lazy_ntfs,
      65,RDPClient Event Logs,EventLogs,Windows*\system32\winevt\logs\Microsoft-Windows-TerminalServices-RDPClient*,lazy_ntfs,
      66,RDPCoreTS Event Logs,EventLogs,Windows*\system32\winevt\logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS*,lazy_ntfs,Can be used to correlate RDP logon failures by originating IP
      67,WDI Trace Logs 1,Event Trace Logs,Windows*\System32\WDI\LogFiles\*.etl*,lazy_ntfs,
      68,WDI Trace Logs 2,Event Trace Logs,Windows*\System32\WDI\{*/**10,lazy_ntfs,
      69,WMI Trace Logs,Event Trace Logs,Windows*\System32\LogFiles\WMI\*/**10,lazy_ntfs,
      70,SleepStudy Trace Logs,Event Trace Logs,Windows*\System32\SleepStudy*/**10,lazy_ntfs,
      71,Energy-NTKL Trace Logs,Event Trace Logs,ProgramData\Microsoft\Windows\PowerEfficiency Diagnostics\energy-ntkl.etl,lazy_ntfs,
      72,Event logs Win7+,EventLogs,Windows*\system32\winevt\logs\System.evtx,lazy_ntfs,
      73,Event logs Win7+,EventLogs,Windows*\system32\winevt\logs\Security.evtx,lazy_ntfs,
      74,Event logs Win7+,EventLogs,Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx,lazy_ntfs,
      75,Event logs Win7+,EventLogs,Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx,lazy_ntfs,
      76,RecentFileCache,ApplicationCompatability,Windows*\AppCompat\Programs\RecentFileCache.bcf,lazy_ntfs,
      77,$MFT,FileSystem,$MFT,lazy_ntfs,
      78,SRUM,Execution,Windows*\System32\SRU/**10,lazy_ntfs,
      79,LogFiles,Logs,Windows*\System32\LogFiles/**10,lazy_ntfs,
      999980,$J,FileSystem,$Extend\$UsnJrnl:$J,ntfs,
      81,$Max,FileSystem,$Extend\$UsnJrnl:$Max,ntfs,
      82,Setupapi.log XP,USBDevices,Windows\setupapi.log,lazy_ntfs,
      83,Setupapi.log Win7+,USBDevices,Windows*\inf\setupapi.dev.log,lazy_ntfs,
      84,$Recycle.Bin,Deleted Files,$Recycle.Bin\*/**10,lazy_ntfs,
      85,RECYCLER WinXP,Deleted Files,RECYCLER\*/**10,lazy_ntfs,
      86,Prefetch,Prefetch,Windows*\prefetch\*.pf,lazy_ntfs,
      87,Syscache,Program Execution,System Volume Information\Syscache.hve,lazy_ntfs,
      88,Syscache transaction files,Program Execution,System Volume Information\Syscache.hve.LOG*,lazy_ntfs,
      89,Windows 10 Notification DB,Notifications,Users\*\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db,lazy_ntfs,Locates Windows notification db files
      90,Windows 10 Notification DB,Notifications,Users\*\AppData\Local\Microsoft\Windows\Notifications\appdb.dat,lazy_ntfs,Locates Windows notification db files
      91,MOF files,WMI,/**10/*.MOF,lazy_ntfs,
      92,Event logs XP,EventLogs,Windows\system32\config\*.evt,lazy_ntfs,
      93,Event logs Win7+,EventLogs,Windows*\system32\winevt\logs\*.evtx,lazy_ntfs,
      94,RDP Cache Files,FileSystem,Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache,lazy_ntfs,
      95,RDP Cache Files,FileSystem,Documents and Settings\*\Local Settings\Application Data\Microsoft\Terminal Server Client\Cache,lazy_ntfs,
      96,SAM registry transaction files,Registry,Windows*\System32\config\SAM.LOG*,lazy_ntfs,
      97,SECURITY registry transaction files,Registry,Windows*\System32\config\SECURITY.LOG*,lazy_ntfs,
      98,SOFTWARE registry transaction files,Registry,Windows*\System32\config\SOFTWARE.LOG*,lazy_ntfs,
      99,SYSTEM registry transaction files,Registry,Windows*\System32\config\SYSTEM.LOG*,lazy_ntfs,
      100,SAM registry hive,Registry,Windows*\System32\config\SAM,lazy_ntfs,
      101,SECURITY registry hive,Registry,Windows*\System32\config\SECURITY,lazy_ntfs,
      102,SOFTWARE registry hive,Registry,Windows*\System32\config\SOFTWARE,lazy_ntfs,
      103,SYSTEM registry hive,Registry,Windows*\System32\config\SYSTEM,lazy_ntfs,
      104,RegBack registry transaction files,Registry,Windows*\System32\config\RegBack\*.LOG*,lazy_ntfs,
      105,SAM registry hive (RegBack),Registry,Windows*\System32\config\RegBack\SAM,lazy_ntfs,
      106,SECURITY registry hive (RegBack),Registry,Windows*\System32\config\RegBack\SECURITY,lazy_ntfs,
      107,SOFTWARE registry hive (RegBack),Registry,Windows*\System32\config\RegBack\SOFTWARE,lazy_ntfs,
      108,SYSTEM registry hive (RegBack),Registry,Windows*\System32\config\RegBack\SYSTEM,lazy_ntfs,
      109,SYSTEM registry hive (RegBack),Registry,Windows*\System32\config\RegBack\SYSTEM1,lazy_ntfs,
      110,System Profile registry hive,Registry,Windows*\System32\config\systemprofile\ntuser.dat,lazy_ntfs,
      111,System Profile registry transaction files,Registry,Windows*\System32\config\systemprofile\ntuser.dat.LOG*,lazy_ntfs,
      112,Local Service registry hive,Registry,Windows*\ServiceProfiles\LocalService\ntuser.dat,lazy_ntfs,
      113,Local Service registry transaction files,Registry,Windows*\ServiceProfiles\LocalService\ntuser.dat.LOG*,lazy_ntfs,
      114,Network Service registry hive,Registry,Windows*\ServiceProfiles\NetworkService\ntuser.dat,lazy_ntfs,
      115,Network Service registry transaction files,Registry,Windows*\ServiceProfiles\NetworkService\ntuser.dat.LOG*,lazy_ntfs,
      116,System Restore Points Registry Hives (XP),Registry,System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*,lazy_ntfs,
      117,WBEM,WBEM,Windows*\System32\wbem\Repository/**10,lazy_ntfs,
      118,$T,FileSystem,$Extend\$RmMetadata\$TxfLog\$Tops:$T,ntfs,
      119,LogMeIn ProgramData Logs,ApplicationLogs,ProgramData\LogMeIn\Logs/**10,lazy_ntfs,
      120,LogMeIn Application Logs,ApplicationLogs,Users\*\AppData\Local\temp\LogMeInLogs/**10,lazy_ntfs,"Contains RemoteAssist (formerly GoToAssist), GoToMeeting, and other GoTo* logs"
      121,Exchange client access log files,Logs,Program Files\Microsoft\Exchange Server\*\Logging/**10/*.log,lazy_ntfs,Highly dependent on Exchange configuration
      122,RealVNC Log,ApplicationLogs,Users\*\AppData\Local\RealVNC\vncserver.log,lazy_ntfs,https://www.realvnc.com/en/connect/docs/logging.html#logging
      123,main.db (App <v12),Communications,Users\*\AppData\Local\Packages\Microsoft.SkypeApp_*\LocalState\*\main.db,lazy_ntfs,
      124,skype.db (App +v12),Communications,Users\*\AppData\Local\Packages\Microsoft.SkypeApp_*\LocalState\*\skype.db,lazy_ntfs,
      125,main.db XP,Communications,Documents and Settings\*\Application Data\Skype\*\main.db,lazy_ntfs,
      126,main.db Win7+,Communications,Users\*\AppData\Roaming\Skype\*\main.db,lazy_ntfs,
      127,s4l-[username].db (App +v8),Communications,Users\*\AppData\Local\Packages\Microsoft.SkypeApp_*\LocalState\s4l-*.db,lazy_ntfs,
      128,leveldb (Skype for Desktop +v8),Communications,Users\*\AppData\Roaming\Microsoft\Skype for Desktop\IndexedDB\*.leveldb\*.log,lazy_ntfs,
      129,Ammyy Program Data,ApplicationLogs,ProgramData\Ammyy/**10,lazy_ntfs,"May not contain traditional log files, but presence of this folder may indicate historical usage"
      130,ScreenConnect Session Database,ApplicationLogs,Program Files*\ScreenConnect\App_Data\Session.db,lazy_ntfs,SQLite database with session information
      131,ScreenConnect Session Database,ApplicationLogs,Program Files*\ScreenConnect\App_Data\User.xml,lazy_ntfs,Contains each user's last authenticated time
      132,OneDrive User Files,Apps,Users\*\OneDrive*\/**10,lazy_ntfs,Caution -- This target will collect OneDrive contents from the local drive AND on-demand cloud files. Ensure your scope of authority permits cloud collections before use
      133,OneDrive Metadata Logs,Apps,Users\*\AppData\Local\Microsoft\OneDrive\logs\/**10,lazy_ntfs,
      134,OneDrive Metadata Settings,Apps,Users\*\AppData\Local\Microsoft\OneDrive\settings\/**10,lazy_ntfs,
      135,iTunes Backup Folder,Communications,Users\*\AppData\Roaming\Apple\Mobilesync\Backup/**10,lazy_ntfs,
      136,iTunes Backup Folder,Communications,Users\*\AppData\Roaming\Apple Computer\Mobilesync\Backup/**10,lazy_ntfs,
      137,Java WebStart Cache User Level - Default,Communication,Users\*\AppData\Local\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      138,Java WebStart Cache User Level - IE Protected Mode,Communication,Users\*\AppData\LocalLow\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      139,Java WebStart Cache System level,Communication,Windows*\System32\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      140,Java WebStart Cache System level - IE Protected Mode,Communication,Windows*\System32\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      141,Java WebStart Cache System level (SysWow64),Communication,Windows*\SysWOW64\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      142,Java WebStart Cache System level (SysWow64) - IE Protected Mode,Communication,Windows*\SysWOW64\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      143,Java WebStart Cache User Level - XP,Communications,Documents and Settings\*\Application Data\Sun\Java\Deployment\cache\*\*\*.idx,lazy_ntfs,
      144,Exchange TransportRoles log files,Logs,Program Files\Microsoft\Exchange Server\*\TransportRoles\Logs\/**10/*.log,lazy_ntfs,Highly dependent on Exchange configuration
      145,TeraCopy,TeraCopy,Users\*\AppData\Roaming\TeraCopy/**10,lazy_ntfs,
      146,Cisco Jabber Database,Communications,Users\*\AppData\Local\Cisco\Unified Communications\Jabber\CSF\History\*.db,lazy_ntfs,The Cisco Jabber process needs to be killed before database can be copied.
      147,Box User Files,Apps,Users\*\Box*\/**10,lazy_ntfs,Caution -- This target will collect Box Drive contents from the local drive AND on-demand cloud files. Ensure your scope of authority permits cloud collections before use
      148,Box Drive Application Metadata,Apps,Users\*\AppData\Local\Box\Box\*\/**10,lazy_ntfs,
      149,Box Sync Application Metadata,Apps,Users\*\AppData\Local\Box Sync\*\/**10,lazy_ntfs,
      150,Dropbox User Files,Apps,Users\*\Dropbox*\/**10,lazy_ntfs,
      151,Dropbox Metadata,Apps,Users\*\AppData\Local\Dropbox\info.json,lazy_ntfs,Getting individual files because folder may contain very large extraneous files
      152,Dropbox Metadata,Apps,Users\*\AppData\Local\Dropbox\*\filecache.dbx,lazy_ntfs,Getting individual files because folder may contain very large extraneous files
      153,Dropbox Metadata,Apps,Users\*\AppData\Local\Dropbox\*\config.dbx,lazy_ntfs,Getting individual files because folder may contain very large extraneous files
      154,Windows Protect Folder,FileSystem,Users\*\AppData\Roaming\Microsoft\Protect\*\/**10,lazy_ntfs,Required for offline decryption of Dropbox databases
      155,TeamViewer Connection Logs,Communications,Program Files*\TeamViewer\connections*.txt,lazy_ntfs,Includes connections_incoming.txt and connections.txt
      156,TeamViewer Application Logs,ApplicationLogs,Program Files*\TeamViewer\TeamViewer*_Logfile*,lazy_ntfs,Includes TeamViewer<version>_Logfile.log and TeamViewer<version>_Logfile_OLD.log
      157,TeamViewer Configuration Files,ApplicationLogs,Users\*\AppData\Roaming\TeamViewer\MRU\RemoteSupport/**10,lazy_ntfs,Includes miscellaneous config files
      158,Google Drive User Files,Apps,Users\*\Google Drive*\/**10,lazy_ntfs,Google Drive Backup and Sync Application
      159,Google Drive Metadata,Apps,Users\*\AppData\Local\Google\Drive\/**10,lazy_ntfs,Google Drive Backup and Sync Application
      160,Google File Stream Metadata,Apps,Users\*\AppData\Local\Google\DriveFS\/**10,lazy_ntfs,Google Drive File Stream Application
      161,Kaseya Live Connect Logs (XP),ApplicationLogs,Documents and Settings\*\Application Data\Kaseya\Log/**10,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
      162,Kaseya Live Connect Logs,ApplicationLogs,Users\*\AppData\Local\Kaseya\Log\KaseyaLiveConnect/**10,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
      163,Kaseya Agent Endpoint Service Logs (XP),ApplicationLogs,Documents and Settings\All Users\Application Data\Kaseya\Log\Endpoint/**10,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
      164,Kaseya Agent Endpoint Service Logs,ApplicationLogs,ProgramData\Kaseya\Log\Endpoint/**10,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
      165,Kaseya Agent Service Log,ApplicationLogs,Program Files*\Kaseya\*\agentmon.log*,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
      166,Kaseya Setup Log,ApplicationLogs,Users\*\AppData\Local\Temp\KASetup.log,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229011448
      167,Kaseya Setup Log,ApplicationLogs,Windows*\Temp\KASetup.log,lazy_ntfs,https://helpdesk.kaseya.com/hc/en-gb/articles/229011448
      168,PST XP,Communications,Documents and Settings\*\Local Settings\Application Data\Microsoft\Outlook\*.pst,lazy_ntfs,
      169,OST XP,Communications,Documents and Settings\*\Local Settings\Application Data\Microsoft\Outlook\*.ost,lazy_ntfs,
      170,PST,Communications,Users\*\AppData\Local\Microsoft\Outlook\*.pst,lazy_ntfs,
      171,OST,Communications,Users\*\AppData\Local\Microsoft\Outlook\*.ost,lazy_ntfs,
      172,Notepad++ backup,Text Editor,Users\*\AppData\Roaming\Notepad++\backup/**10,lazy_ntfs,Locates non-saved Notepad++ files and copies them.
      173,Confluence Wiki Log Files,Logs,Atlassian\Application Data\Confluence\logs\*.log*,lazy_ntfs,
      174,Confluence Wiki Log Files,Logs,Program Files\Atlassian\Confluence\logs\*.log,lazy_ntfs,
      175,Symantec Endpoint Protection Logs (XP),AntiVirus,Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV/**10,lazy_ntfs,
      176,Symantec Endpoint Protection Logs,AntiVirus,ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs/**10,lazy_ntfs,
      177,Symantec Endpoint Protection User Logs,AntiVirus,Users\*\AppData\Local\Symantec\Symantec Endpoint Protection\Logs/**10,lazy_ntfs,
      178,Symantec Event Log Win7+,EventLogs,Windows*\system32\winevt\logs\Symantec Endpoint Protection Client.evtx,lazy_ntfs,Symantec specific Windows event log
      179,Trend Micro Logs,Antivirus,ProgramData\Trend Micro\/**10,lazy_ntfs,
      180,Trend Micro Security Agent Report Logs,Antivirus,Program Files*\Trend Micro\Security Agent\Report\*.log,lazy_ntfs,
      181,Trend Micro Security Agent Connection Logs,Antivirus,Program Files*\Trend Micro\Security Agent\ConnLog\*.log,lazy_ntfs,
      182,MalwareBytes Anti-Malware Logs,Antivirus,ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs\mbam-log-*.xml,lazy_ntfs,
      183,MalwareBytes Anti-Malware Service Logs,Antivirus,ProgramData\Malwarebytes\MBAMService\logs\mbamservice.log,lazy_ntfs,
      184,MalwareBytes Anti-Malware Scan Logs,Antivirus,Users\*\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs/**10,lazy_ntfs,
      185,Sophos Logs (XP),Antivirus,Documents and Settings\All Users\Application Data\Sophos\Sophos *\Logs\/**10,lazy_ntfs,"Includes Anti-Virus, Client Firewall, Data Control, Device Control, Endpoint Defense, Network Threat Detection, Management Communications System, Patch Control, Tamper Protection"
      186,Sophos Logs,Antivirus,ProgramData\Sophos\Sophos *\Logs\/**10,lazy_ntfs,"Includes Anti-Virus, Client Firewall, Data Control, Device Control, Endpoint Defense, Network Threat Detection, Management Communications System, Patch Control, Tamper Protection"
      187,Avira Activity Logs,AntiVirus,ProgramData\Avira\Antivirus\LOGFILES/**10,lazy_ntfs,Collects the scan logs of Avira AntiVirus
      188,Windows Defender Logs,Antivirus,ProgramData\Microsoft\Microsoft AntiMalware\Support\/**10,lazy_ntfs,
      189,Windows Defender Event Logs,EventLogs,Windows*\System32\winevt\Logs\Microsoft-Windows-WindowsDefender*.evtx,lazy_ntfs,
      190,Avast AV Logs (XP),Antivirus,Documents And Settings\All Users\Application Data\Avast Software\Avast\Log/**10,lazy_ntfs,
      191,Avast AV Logs,Antivirus,ProgramData\Avast Software\Avast\Log\/**10,lazy_ntfs,
      192,Avast AV User Logs,Antivirus,Users\*\Avast Software\Avast\Log/**10,lazy_ntfs,
      193,Avast AV Index,Antivirus,ProgramData\Avast Software\Avast\Chest\index.xml,lazy_ntfs,
      194,SUPERAntiSpyware Logs,Antivirus,Users\*\AppData\Roaming\SUPERAntiSpyware\Logs\/**10,lazy_ntfs,
      195,F-Secure Logs,Antivirus,ProgramData\F-Secure\Log\/**10,lazy_ntfs,
      196,F-Secure User Logs,Antivirus,Users\*\AppData\Local\F-Secure\Log\/**10,lazy_ntfs,
      197,F-Secure Scheduled Scan Reports,Antivirus,ProgramData\F-Secure\Antivirus\ScheduledScanReports\/**10,lazy_ntfs,
      198,VIPRE Business Agent Logs,Antivirus,ProgramData\VIPRE Business Agent\Logs\/**10,lazy_ntfs,
      199,VIPRE Business User Logs (v7+),Antivirus,Users\*\AppData\Roaming\VIPRE Business\/**10,lazy_ntfs,
      200,VIPRE Business User Logs (v5-v6),Antivirus,Users\*\AppData\Roaming\GFI Software\AntiMalware\Logs\/**10,lazy_ntfs,
      201,VIPRE Business User Logs (up to v4),Antivirus,Users\*\AppData\Roaming\Sunbelt Software\AntiMalware\Logs\/**10,lazy_ntfs,
      202,ComboFix,Antivirus,ComboFix.txt,lazy_ntfs,
      203,HitmanPro Logs,Antivirus,ProgramData\HitmanPro\Logs/**10,lazy_ntfs,
      204,HitmanPro Alert Logs,Antivirus,ProgramData\HitmanPro.Alert\Logs/**10,lazy_ntfs,
      205,HitmanPro Database,Antivirus,ProgramData\HitmanPro.Alert\excalibur.db,lazy_ntfs,SQl Lite DB
      206,McAfee ePO Logs,AntiVirus,ProgramData\McAfee\Endpoint Security\Logs/**10,lazy_ntfs,
      207,McAfee Desktop Protection Logs XP,AntiVirus,Users\All Users\Application Data\McAfee\DesktopProtection/**10,lazy_ntfs,
      208,McAfee Desktop Protection Logs,AntiVirus,ProgramData\McAfee\DesktopProtection/**10,lazy_ntfs,
      209,McAfee Endpoint Security Logs,AntiVirus,ProgramData\McAfee\Endpoint Security\Logs\/**10,lazy_ntfs,
      210,McAfee Endpoint Security Logs,AntiVirus,ProgramData\McAfee\Endpoint Security\Logs_Old\/**10,lazy_ntfs,
      211,McAfee VirusScan Logs,AntiVirus,ProgramData\Mcafee\VirusScan\/**10,lazy_ntfs,
      212,RogueKiller Reports,Antivirus,ProgramData\RogueKiller\logs\AdliceReport_*.json,lazy_ntfs,
      213,Bitdefender Endpoint Security Logs,Antivirus,ProgramData\Bitdefender\Endpoint Security\Logs\/**10,lazy_ntfs,
      214,ESET NOD32 AV Logs (XP),Antivirus,Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\/**10,lazy_ntfs,
      215,ESET NOD32 AV Logs,Antivirus,ProgramData\ESET\ESET NOD32 Antivirus\Logs\/**10,lazy_ntfs,Parser available at https://github.com/laciKE/EsetLogParser
      216,Ammyy,Ammyy.tkape,ApplicationLogs,lazy_ntfs,
      217,VHD,Disk Images,/**10/*.VHD,lazy_ntfs,VHD
      218,VHDX,Disk Images,/**10/*.VHDX,lazy_ntfs,VHDX
      219,VDI,Disk Images,/**10/*.VDI,lazy_ntfs,VDI
      220,VMDK,Disk Images,/**10/*.VMDK,lazy_ntfs,VMDK
      221,MS SQL Errorlog,SQL Exploitation,Program Files\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG,lazy_ntfs,
      222,MS SQL Errorlogs,SQL Exploitation,Program Files\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG.*,lazy_ntfs,
      223,IIS log files,Logs,Windows*\system32\LogFiles\W3SVC*\*.log,lazy_ntfs,
      224,IIS log files,Logs,inetpub\logs\LogFiles\*.log,lazy_ntfs,
      225,IIS log files,Logs,inetpub\logs\LogFiles\W3SVC*\*.log,lazy_ntfs,
      226,IIS log files,Logs,Resources\directory\* \LogFiles\Web\W3SVC*\*.log,lazy_ntfs,
      227,NGINX Log Files,Logs,nginx\logs\*.log,lazy_ntfs,
      228,PowerShell Console Log,PowerShellConsleLog,users\*\Appdata\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt,lazy_ntfs,
      229,Apache Access Log,Webservers,/**10/access.log,lazy_ntfs,Locates Apache access.log file
      230,Edge folder,Communications,Users\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe/**10,lazy_ntfs,
      231,WebcacheV01.dat,Communications,Users\*\AppData\Local\Microsoft\Windows\WebCache,lazy_ntfs,
      232,Chrome Extension Files,Communication,Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions/**10,lazy_ntfs,
      233,Chrome Extension Files XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Extensions/**10,lazy_ntfs,
      234,Chrome bookmarks XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Bookmarks*,lazy_ntfs,
      235,Chrome Cookies XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Cookies*,lazy_ntfs,
      236,Chrome Current Session XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Current Session,lazy_ntfs,
      237,Chrome Current Tabs XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Current Tabs,lazy_ntfs,
      238,Chrome Favicons XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Favicons*,lazy_ntfs,
      239,Chrome History XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\History*,lazy_ntfs,
      240,Chrome Last Session XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Last Session,lazy_ntfs,
      241,Chrome Last Tabs XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Last Tabs,lazy_ntfs,
      242,Chrome Preferences XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Preferences,lazy_ntfs,
      243,Chrome Shortcuts XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Shortcuts*,lazy_ntfs,
      244,Chrome Top Sites XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Top Sites*,lazy_ntfs,
      245,Chrome bookmarks XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Bookmarks*,lazy_ntfs,
      246,Chrome Visited Links XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Visited Links,lazy_ntfs,
      247,Chrome Web Data XP,Communications,Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Web Data*,lazy_ntfs,
      248,Chrome bookmarks,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks*,lazy_ntfs,
      249,Chrome Cookies,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Cookies*,lazy_ntfs,
      250,Chrome Current Session,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Current Session,lazy_ntfs,
      251,Chrome Current Tabs,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Current Tabs,lazy_ntfs,
      252,Chrome Favicons,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Favicons*,lazy_ntfs,
      253,Chrome History,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\History*,lazy_ntfs,
      254,Chrome Last Session,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Last Session,lazy_ntfs,
      255,Chrome Last Tabs,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Last Tabs,lazy_ntfs,
      256,Chrome Preferences,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Preferences,lazy_ntfs,
      257,Chrome Shortcuts,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Shortcuts*,lazy_ntfs,
      258,Chrome Top Sites,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Top Sites*,lazy_ntfs,
      259,Chrome bookmarks,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks*,lazy_ntfs,
      260,Chrome Visited Links,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Visited Links,lazy_ntfs,
      261,Chrome Web Data,Communications,Users\*\AppData\Local\Google\Chrome\User Data\*\Web Data*,lazy_ntfs,
      262,Places,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite*,lazy_ntfs,
      263,Downloads,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\downloads.sqlite*,lazy_ntfs,
      264,Form history,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\formhistory.sqlite*,lazy_ntfs,
      265,Cookies,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite*,lazy_ntfs,
      266,Signons,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\signons.sqlite*,lazy_ntfs,
      267,Webappstore,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\webappstore.sqlite*,lazy_ntfs,
      268,Favicons,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\favicons.sqlite*,lazy_ntfs,
      269,Addons,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\addons.sqlite*,lazy_ntfs,
      270,Search,Communications,Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\search.sqlite*,lazy_ntfs,
      271,Places,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\places.sqlite*,lazy_ntfs,
      272,Downloads,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\downloads.sqlite*,lazy_ntfs,
      273,Form history,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\formhistory.sqlite*,lazy_ntfs,
      274,Cookies,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\cookies.sqlite*,lazy_ntfs,
      275,Signons,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\signons.sqlite*,lazy_ntfs,
      276,Webappstore,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\webappstore.sqlite*,lazy_ntfs,
      277,Favicons,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\favicons.sqlite*,lazy_ntfs,
      278,Addons,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\addons.sqlite*,lazy_ntfs,
      279,Search,Communications,Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\search.sqlite*,lazy_ntfs,
      280,Index.dat History,Communications,Documents and Settings\*\Local Settings\History\History.IE5\index.dat,lazy_ntfs,
      281,Index.dat History subdirectory,Communications,Documents and Settings\*\Local Settings\History\History.IE5\*\index.dat,lazy_ntfs,
      282,Index.dat temp internet files,Communications,Documents and Settings\*\Local Settings\Temporary Internet Files\Content.IE5\index.dat,lazy_ntfs,
      283,Index.dat cookies,Communications,Documents and Settings\*\Cookies\index.dat,lazy_ntfs,
      284,Index.dat UserData,Communications,Documents and Settings\*\Application Data\Microsoft\Internet Explorer\UserData\index.dat,lazy_ntfs,
      285,Index.dat Office XP,Communications,Documents and Settings\*\Application Data\Microsoft\Office\Recent\index.dat,lazy_ntfs,
      286,Index.dat Office,Communications,Users\*\AppData\Roaming\Microsoft\Office\Recent\index.dat,lazy_ntfs,
      287,Local Internet Explorer folder,Communications,Users\*\AppData\Local\Microsoft\Internet Explorer\/**10,lazy_ntfs,
      288,Roaming Internet Explorer folder,Communications,Users\*\AppData\Roaming\Microsoft\Internet Explorer\/**10,lazy_ntfs,
      289,IE 9/10 History,Communications,Users\*\AppData\Local\Microsoft\Windows\History\/**10,lazy_ntfs,
      290,IE 9/10 Cache,Communications,Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\/**10,lazy_ntfs,
      291,IE 9/10 Cookies,Communications,Users\*\AppData\Local\Microsoft\Windows\Cookies\/**10,lazy_ntfs,
      292,IE 9/10 Download History,Communications,Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\/**10,lazy_ntfs,
      293,IE 11 Metadata,Communications,Users\*\AppData\Local\Microsoft\Windows\WebCache,lazy_ntfs,
      294,IE 11 Cache,Communications,Users\*\AppData\Local\Microsoft\Windows\INetCache\/**10,lazy_ntfs,
      295,IE 11 Cookies,Communications,Users\*\AppData\Local\Microsoft\Windows\INetCookies\/**10,lazy_ntfs,
  - name: KapeTargets
    type: hidden
    description: Each parameter above represents a group of rules to be triggered. This table specifies which rule IDs will be included when the parameter is checked.
    default: |
      Group,RuleIds
      _BasicCollection,"[15, 17, 18, 19, 22, 23, 26, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 76, 77, 78, 80, 81, 82, 83, 84, 85, 86, 87, 88, 92, 93, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 118, 228]"
      _Boot,[45]
      _J,"[80, 81]"
      _LogFile,[44]
      _MFT,[77]
      _SDS,[26]
      _T,[118]
      Amcache,"[22, 23]"
      Ammyy,[129]
      ApacheAccessLog,[229]
      AppData,[1]
      ApplicationEvents,"[24, 25]"
      Avast,"[190, 191, 192, 193]"
      AviraAVLogs,[187]
      BCD,"[20, 21]"
      Bitdefender,[213]
      BoxDrive,"[147, 148, 149]"
      Chrome,"[234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261]"
      ChromeExtensions,"[232, 233]"
      CiscoJabber,[146]
      CloudStorage,"[132, 133, 134, 147, 148, 149, 150, 151, 152, 153, 154, 158, 159, 160]"
      CombinedLogs,"[34, 67, 68, 69, 70, 71, 92, 93, 228]"
      ComboFix,[202]
      ConfluenceLogs,"[173, 174]"
      DirectoryTraversalWildCardExample,[2]
      Dropbox,"[150, 151, 152, 153, 154]"
      ESET,"[214, 215]"
      Edge,"[230, 231]"
      EncapsulationLogging,"[39, 40]"
      EventLogs_RDP,"[72, 73, 74, 75]"
      EventLogs,"[92, 93]"
      EventTraceLogs,"[67, 68, 69, 70, 71]"
      EvidenceOfExecution,"[22, 23, 76, 86, 87, 88]"
      Exchange,"[121, 144]"
      ExchangeClientAccess,[121]
      ExchangeTransport,[144]
      FSecure,"[195, 196, 197]"
      FileSystem,"[26, 44, 45, 77, 80, 81, 118]"
      Firefox,"[262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279]"
      Gigatribe,"[7, 8, 9]"
      GoogleDrive,"[158, 159, 160]"
      GroupPolicy,"[59, 60, 61]"
      HitmanPro,"[203, 204, 205]"
      IISLogFiles,"[223, 224, 225, 226]"
      InternetExplorer,"[280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295]"
      JavaWebCache,"[137, 138, 139, 140, 141, 142, 143]"
      KapeTriage,"[17, 18, 19, 22, 23, 24, 25, 26, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 63, 64, 65, 66, 76, 77, 78, 80, 81, 86, 87, 88, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 118, 119, 120, 122, 130, 131, 155, 156, 157, 161, 162, 163, 164, 165, 166, 167, 216, 230, 231, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295]"
      Kaseya,"[161, 162, 163, 164, 165, 166, 167]"
      LinuxOnWindowsProfileFiles,"[27, 28, 29, 30]"
      LiveUserFiles,"[3, 4, 5, 6]"
      LnkFilesAndJumpLists,"[53, 54, 55, 56, 57, 58]"
      LogFiles,[79]
      LogMeIn,"[24, 25, 119, 120]"
      MOF,[91]
      MSSQLErrorLog,"[221, 222]"
      Malwarebytes,"[182, 183, 184]"
      McAfee,"[207, 208, 209, 210, 211]"
      McAfee_ePO,[206]
      MiniTimelineCollection,"[26, 44, 45, 46, 47, 48, 49, 50, 51, 52, 77, 80, 81, 92, 93, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 118]"
      NGINXLogs,[227]
      Notepad__,[172]
      OneDrive,"[132, 133, 134]"
      OutlookPSTOST,"[168, 169, 170, 171]"
      PowerShellConsole,[228]
      Prefetch,[86]
      RDPCache,"[94, 95]"
      RDPLogs,"[63, 64, 65, 66]"
      RecentFileCache,[76]
      Recycle,"[84, 85]"
      RegistryHives,"[46, 47, 48, 49, 50, 51, 52, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116]"
      RegistryHivesSystem,"[96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116]"
      RegistryHivesUser,"[46, 47, 48, 49, 50, 51, 52]"
      RemoteAdmin,"[24, 25, 63, 64, 65, 66, 94, 95, 119, 120, 122, 130, 131, 155, 156, 157, 161, 162, 163, 164, 165, 166, 167, 216]"
      RogueKiller,[212]
      SDB,"[41, 42]"
      SRUM,[78]
      SUPERAntiSpyware,[194]
      ScheduledTasks,"[17, 18, 19]"
      ScreenConnect,"[24, 25, 130, 131]"
      SignatureCatalog,[16]
      Skype,"[123, 124, 125, 126, 127, 128]"
      Sophos,"[24, 25, 185, 186]"
      StartupInfo,[62]
      Symantec_AV_Logs,"[24, 25, 175, 176, 177, 178]"
      Syscache,"[87, 88]"
      TeamViewerLogs,"[155, 156, 157]"
      TeraCopy,[145]
      ThumbCache,[15]
      TorrentClients,"[10, 11, 12, 13]"
      Torrents,[14]
      TrendMicro,"[179, 180, 181]"
      USBDevicesLogs,"[82, 83]"
      VIPRE,"[198, 199, 200, 201]"
      VNCLogs,"[24, 25, 122]"
      VirtualDisks,"[217, 218, 219, 220]"
      WBEM,[117]
      WER,"[36, 37, 38]"
      WebBrowsers,"[230, 231, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295]"
      WindowsDefender,"[188, 189]"
      WindowsFirewall,[34]
      WindowsIndexSearch,[43]
      WindowsNotifcationsDB,"[89, 90]"
      WindowsTimeline,"[31, 32, 33]"
      XPRestorePoints,[35]
      iTunesBackup,"[135, 136]"
  - name: Device
    default: "C:"
  - name: VSSAnalysis
    type: bool
    default:
    description: If set we run the collection across all VSS and collect only unique changes.

sources:
  - name: All File Metadata
    queries:
      # Select all the rule Ids to be included depending on the group selection.
      - |
        LET targets <= SELECT * FROM parse_csv(filename=KapeTargets, accessor="data")
        WHERE get(item=scope(), member=Group)

      # Filter only the rules in the rule table that have an Id we want.
      - |
        LET rule_specs_ntfs <= SELECT Id, Glob
        FROM parse_csv(filename=KapeRules, accessor="data")
        WHERE Id in array(array=targets.RuleIds) AND Accessor='ntfs'

      - |
        LET rule_specs_lazy_ntfs <= SELECT Id, Glob
        FROM parse_csv(filename=KapeRules, accessor="data")
        WHERE Id in array(array=targets.RuleIds) AND Accessor='lazy_ntfs'

      # Call the generic VSS file collector with the globs we want in a new CSV file.
      - |
        LET all_results <= SELECT * FROM if(
           condition=VSSAnalysis,
           then={
             SELECT * FROM chain(
               a={
                   SELECT * FROM Artifact.Windows.Collectors.VSS(
                      RootDevice=Device, Accessor="ntfs",
                      collectionSpec=serialize(item=rule_specs_ntfs, format="csv"))
               }, b={
                   SELECT * FROM Artifact.Windows.Collectors.VSS(
                      RootDevice=Device, Accessor="lazy_ntfs",
                      collectionSpec=serialize(item=rule_specs_lazy_ntfs, format="csv"))
               })
           }, else={
             SELECT * FROM chain(
               a={
                   SELECT * FROM Artifact.Windows.Collectors.File(
                      RootDevice=Device, Accessor="ntfs",
                      collectionSpec=serialize(item=rule_specs_ntfs, format="csv"))
               }, b={
                   SELECT * FROM Artifact.Windows.Collectors.File(
                      RootDevice=Device, Accessor="lazy_ntfs",
                      collectionSpec=serialize(item=rule_specs_lazy_ntfs, format="csv"))
               })
           })
      - SELECT * FROM all_results WHERE _Source =~ "Metadata"
  - name: Uploads
    queries:
      - SELECT * FROM all_results WHERE _Source =~ "Uploads"
```
   {{% /expand %}}

## Triage.Collection.Upload

A Generic uploader used by triaging artifacts.


Arg|Default|Description
---|------|-----------
path||This is the glob of the files we use.
type||The type of files these are.
accessor|file|

{{% expand  "View Artifact Source" %}}


```text
name: Triage.Collection.Upload
description: |
  A Generic uploader used by triaging artifacts.

parameters:
  - name: path
    description: This is the glob of the files we use.
  - name: type
    description: The type of files these are.
  - name: accessor
    default: file

sources:
  - queries:
      - |
        LET results = SELECT FullPath, Size,
               timestamp(epoch=Mtime.Sec) As Modifed,
               type AS Type, {
                 SELECT * FROM upload(files=FullPath, accessor=accessor)
               } AS FileDetails
        FROM glob(globs=path, accessor=accessor)
        WHERE NOT IsDir
      - |
        SELECT FullPath, Size, Modifed, Type,
               FileDetails.Path AS ZipPath,
               FileDetails.Md5 as Md5,
               FileDetails.Sha256 as SHA256
        FROM results
```
   {{% /expand %}}

## Triage.Collection.UploadTable

A Generic uploader used by triaging artifacts. This is similar to
`Triage.Collection.Upload` but uses a CSV table to drive it.


Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\n|A CSV table controlling upload. Must have the headers: Type, Accessor, Glob.

{{% expand  "View Artifact Source" %}}


```text
name: Triage.Collection.UploadTable
description: |
  A Generic uploader used by triaging artifacts. This is similar to
  `Triage.Collection.Upload` but uses a CSV table to drive it.

parameters:
  - name: triageTable
    description: "A CSV table controlling upload. Must have the headers: Type, Accessor, Glob."
    default: |
      Type,Accessor,Glob

sources:
  - queries:
      - |
        LET results = SELECT FullPath, Size,
               timestamp(epoch=Mtime.Sec) As Modifed,
               Type, {
                 SELECT * FROM upload(files=FullPath, accessor=Accessor)
               } AS FileDetails
        FROM glob(globs=split(string=Glob, sep=","), accessor=Accessor)
        WHERE NOT IsDir

      - |
        SELECT * FROM foreach(
         row={
           SELECT * FROM parse_csv(filename=triageTable, accessor='data')
         },
         query={
           SELECT FullPath, Size, Modifed, Type,
               FileDetails.Path AS ZipPath,
               FileDetails.Md5 as Md5,
               FileDetails.Sha256 as SHA256
          FROM results
        })
```
   {{% /expand %}}

## Windows.Forensics.Bam

The Background Activity Moderator (BAM) is a Windows service that
Controls activity of background applications.  This service exists
in Windows 10 only after Fall Creators update – version 1709.

It provides full path of the executable file that was run on the
system and last execution date/time


Arg|Default|Description
---|------|-----------
bamKeys|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Ser ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.Bam
description: |
  The Background Activity Moderator (BAM) is a Windows service that
  Controls activity of background applications.  This service exists
  in Windows 10 only after Fall Creators update – version 1709.

  It provides full path of the executable file that was run on the
  system and last execution date/time

reference:
  - https://www.andreafortuna.org/dfir/forensic-artifacts-evidences-of-program-execution-on-windows-systems/

parameters:
    - name: bamKeys
      default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*\*,HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*\*
    - name: userRegex
      default: .

sources:
  - precondition:
      SELECT OS from info() where OS = "windows"
    queries:
      - |
        LET users <= SELECT Name, UUID
            FROM Artifact.Windows.Sys.Users()
            WHERE Name =~ userRegex
      - |
        SELECT basename(path=dirname(path=FullPath)) as SID, {
            SELECT Name FROM users
            WHERE UUID = basename(path=dirname(path=FullPath))
          } As UserName,
          Name as Binary,
          timestamp(winfiletime=binary_parse(
               string=Data.value,
               target="int64").AsInteger) as Bam_time
        FROM glob(globs=split(string=bamKeys, sep=","), accessor="reg")
        WHERE Data.type = "BINARY"
```
   {{% /expand %}}

## Windows.Forensics.FilenameSearch

Did a specific file exist on this machine in the past or does it
still exist on this machine?

This common question comes up frequently in cases of IP theft,
discovery and other matters. One way to answer this question is to
search the $MFT file for any references to the specific filename. If
the filename is fairly unique then a positive hit on that name
generally means the file was present.

Simply determining that a filename existed on an endpoint in the
past is significant for some investigations.

This artifact applies a YARA search for a set of filenames of
interest on the $MFT file. For any hit, the artifact then identified
the MFT entry where the hit was found and attempts to resolve that
to an actual filename.


Arg|Default|Description
---|------|-----------
yaraRule|wide nocase:my secret file.txt|
Device|\\\\.\\c:|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.FilenameSearch
description: |
  Did a specific file exist on this machine in the past or does it
  still exist on this machine?

  This common question comes up frequently in cases of IP theft,
  discovery and other matters. One way to answer this question is to
  search the $MFT file for any references to the specific filename. If
  the filename is fairly unique then a positive hit on that name
  generally means the file was present.

  Simply determining that a filename existed on an endpoint in the
  past is significant for some investigations.

  This artifact applies a YARA search for a set of filenames of
  interest on the $MFT file. For any hit, the artifact then identified
  the MFT entry where the hit was found and attempts to resolve that
  to an actual filename.

parameters:
    - name: yaraRule
      default: wide nocase:my secret file.txt
    - name: Device
      default: "\\\\.\\c:"

sources:
  - queries:
      - |
        SELECT String.Offset AS Offset,
               String.HexData AS HexData,
               parse_ntfs(device=Device,
                          mft=String.Offset / 1024) AS MFT
        FROM yara(
             rules=yaraRule, files=Device + "/$MFT",
             end=10000000000,
             number=1000,
             accessor="ntfs")
```
   {{% /expand %}}

## Windows.Forensics.Prefetch

Windows keeps a cache of prefetch files. When an executable is run,
the system records properties about the executable to make it faster
to run next time. By parsing this information we are able to
determine when binaries are run in the past. On Windows10 we can see
the last 8 execution times and creation time (9 potential executions).

There are several parameter's availible for this artifact.
  - dateAfter enables search for prefetch evidence after this date.
  - dateBefore enables search for prefetch evidence before this date.
  - binaryRegex enables to filter on binary name, e.g evil.exe.
  - hashRegex enables to filter on prefetch hash.
  


Arg|Default|Description
---|------|-----------
prefetchGlobs|C:\\Windows\\Prefetch\\*.pf|
dateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ssZ
dateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ssZ
binaryRegex||Regex of executable name.
hashRegex||Regex of prefetch hash.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.Prefetch
description: |
  Windows keeps a cache of prefetch files. When an executable is run,
  the system records properties about the executable to make it faster
  to run next time. By parsing this information we are able to
  determine when binaries are run in the past. On Windows10 we can see
  the last 8 execution times and creation time (9 potential executions).

  There are several parameter's availible for this artifact.
    - dateAfter enables search for prefetch evidence after this date.
    - dateBefore enables search for prefetch evidence before this date.
    - binaryRegex enables to filter on binary name, e.g evil.exe.
    - hashRegex enables to filter on prefetch hash.
    
reference:
  - https://www.forensicswiki.org/wiki/Prefetch

author: matthew.green@cybereason.com

parameters:
    - name: prefetchGlobs
      default: C:\Windows\Prefetch\*.pf
    - name: dateAfter
      description: "search for events after this date. YYYY-MM-DDTmm:hh:ssZ"
      type: timestamp
    - name: dateBefore
      description: "search for events before this date. YYYY-MM-DDTmm:hh:ssZ"
      type: timestamp
    - name: binaryRegex
      description: "Regex of executable name."
    - name: hashRegex
      description: "Regex of prefetch hash."

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - query: |
        // Parse prefetch files and apply non time filters
        LET pf <= SELECT * FROM foreach(
              row={
                 SELECT * FROM glob(globs=prefetchGlobs)
              },
              query={
                SELECT
                    Executable,
                    FileSize,
                    Hash,
                    Version,
                    LastRunTimes,
                    RunCount,
                    // FilesAccessed,
                    FullPath,
                    Name AS PrefetchFileName,
                    timestamp(epoch=Ctime.sec) as CreationTime,
                    timestamp(epoch=Mtime.sec) as ModificationTime
                 FROM prefetch(filename=FullPath)
                 WHERE
                    if(condition=binaryRegex, then= Executable =~ binaryRegex,
                    else=TRUE) AND
                    if(condition=hashRegex, then= Hash =~ hashRegex,
                    else=TRUE)
              })

        // Flattern to enable time filters. Remember VQL is lazy.
        LET executionTimes = SELECT * FROM flatten(
                query = {
                    SELECT *,
                        FullPath as FilteredPath,
                        LastRunTimes as ExecutionTime
                    FROM pf
                })
            WHERE
                if(condition=dateAfter, then=ExecutionTime > timestamp(string=dateAfter),
                    else=TRUE) AND
                if(condition=dateBefore, then=ExecutionTime < timestamp(string=dateBefore),
                    else=TRUE)
        LET creationTimes = SELECT * FROM flatten(
                query = {
                    SELECT *,
                        FullPath as FilteredPath,
                        CreationTime as ExecutionTime
                    FROM pf
                    WHERE RunCount > 8
                })
            WHERE
                if(condition=dateAfter, then=ExecutionTime > timestamp(string=dateAfter),
                    else=TRUE) AND
                if(condition=dateBefore, then=ExecutionTime < timestamp(string=dateBefore),
                        else=TRUE)
            GROUP BY ExecutionTime

        // For stdOutput with timefilters we need to group by FullPath
        LET timeFiltered = SELECT FilteredPath
            FROM chain(
                a = { SELECT * FROM executionTimes },
                b = { SELECT * FROM creationTimes  })
            GROUP BY FilteredPath

        LET timeFilteredStdOut = SELECT * FROM foreach(
                row={
                        SELECT * FROM timeFiltered
                    },
                query={
                    SELECT *
                    FROM pf
                    WHERE FullPath = FilteredPath
                })

        SELECT *
        FROM if(condition = (dateBefore OR dateAfter),
            then={ SELECT * FROM timeFilteredStdOut },
            else={ SELECT * FROM pf  })
```
   {{% /expand %}}

## Windows.Forensics.RecentApps

GUI Program execution launched on the Win10 system is tracked in the
RecentApps key


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
RecentAppsKey|Software\\Microsoft\\Windows\\CurrentVersion\\Sear ...|
UserHomes|C:\\Users\\*\\NTUSER.DAT|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.RecentApps
description: |
  GUI Program execution launched on the Win10 system is tracked in the
  RecentApps key

reference:
  - https://www.sans.org/security-resources/posters/windows-forensics-evidence-of/75/download

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: UserFilter
    default: ""
    description: If specified we filter by this user ID.

  - name: ExecutionTimeAfter
    default: ""
    type: timestamp
    description: If specified only show executions after this time.

  - name: RecentAppsKey
    default: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\*

  - name: UserHomes
    default: C:\Users\*\NTUSER.DAT

sources:
  - queries:
      - LET TMP = SELECT * FROM foreach(
         row={
            SELECT FullPath FROM glob(globs=UserHomes)
         },
         query={
            SELECT AppId, AppPath, LaunchCount,
                   timestamp(winfiletime=LastAccessedTime) AS LastExecution,
                   timestamp(winfiletime=LastAccessedTime).Unix AS LastExecutionTS,
                   parse_string_with_regex(
                      string=Key.FullPath,
                      regex="/Users/(?P<User>[^/]+)/ntuser.dat").User AS User
            FROM read_reg_key(
               globs=url(scheme="ntfs",
                  path=FullPath,
                  fragment=RecentAppsKey).String,
               accessor="raw_reg")
         })

      - LET A1 = SELECT * FROM if(
          condition=UserFilter,
          then={
            SELECT * FROM TMP WHERE User =~ UserFilter
          }, else=TMP)

      - SELECT * FROM if(
          condition=ExecutionTimeAfter,
          then={
            SELECT * FROM A1 WHERE LastExecutionTS > ExecutionTimeAfter
          }, else=A1)
```
   {{% /expand %}}

## Windows.Forensics.SRUM

Process the SRUM database.

references:
  * https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492184583.pdf
  * https://cyberforensicator.com/2017/08/06/windows-srum-forensics/


Arg|Default|Description
---|------|-----------
SRUMLocation|c:\\windows\\system32\\sru\\srudb.dat|
accessor|ntfs|
ExecutableRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.SRUM
description: |
  Process the SRUM database.

  references:
    * https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492184583.pdf
    * https://cyberforensicator.com/2017/08/06/windows-srum-forensics/

type: client

parameters:
  - name: SRUMLocation
    default: c:\windows\system32\sru\srudb.dat
  - name: accessor
    default: ntfs
  - name: ExecutableRegex
    default: .
  - name: NetworkConnectionsGUID
    default: "{DD6636C4-8929-4683-974E-22C046A43763}"
    type: hidden
  - name: ApplicationResourceUsageGUID
    default: "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
    type: hidden
  - name: ExecutionGUID
    default: "{5C8CF1C7-7257-4F13-B223-970EF5939312}"
    type: hidden


sources:
  - name: Upload
    queries:
      - SELECT upload(file=SRUMLocation, accessor=accessor) AS Upload
        FROM scope()

  - name: Execution Stats
    queries:
      - SELECT  AutoIncId AS ID,
                TimeStamp,
                srum_lookup_id(file=SRUMLocation, accessor=accessor, id=AppId) AS App,
                srum_lookup_id(file=SRUMLocation, accessor=accessor, id=UserId) AS User,
                timestamp(winfiletime=EndTime) AS EndTime,
                DurationMS,
                NetworkBytesRaw
        FROM parse_ese(file=SRUMLocation, accessor=accessor, table=ExecutionGUID)
        WHERE App =~ ExecutableRegex

  - name: Application Resource Usage
    queries:
      - SELECT AutoIncId as SRUMId,
               TimeStamp,
               srum_lookup_id(file=SRUMLocation, accessor=accessor, id=AppId) AS App,
               srum_lookup_id(file=SRUMLocation, accessor=accessor, id=UserId) AS User,
               ForegroundCycleTime,
               BackgroundCycleTime,
               FaceTime,
               ForegroundContextSwitches,
               BackgroundContextSwitches,
               ForegroundBytesRead,
               ForegroundBytesWritten,
               ForegroundNumReadOperations,
               ForegroundNumWriteOperations,
               ForegroundNumberOfFlushes,
               BackgroundBytesRead,
               BackgroundBytesWritten,
               BackgroundNumReadOperations,
               BackgroundNumWriteOperations,
               BackgroundNumberOfFlushes
        FROM parse_ese(file=SRUMLocation, accessor=accessor, table=ApplicationResourceUsageGUID)
        WHERE App =~ ExecutableRegex

  - name: Network Connections
    queries:
    - SELECT AutoIncId as SRUMId,
             TimeStamp,
             srum_lookup_id(file=SRUMLocation, accessor=accessor, id=AppId) AS App,
             srum_lookup_id(file=SRUMLocation, accessor=accessor, id=UserId) AS User,
             InterfaceLuid,
             ConnectedTime,
             timestamp(winfiletime=ConnectStartTime) AS StartTime
      FROM parse_ese(file=SRUMLocation, accessor=accessor, table=NetworkConnectionsGUID)
      WHERE App =~ ExecutableRegex
```
   {{% /expand %}}

## Windows.Forensics.Timeline

Win10 records recently used applications and files in a “timeline”
accessible via the “WIN+TAB” key. The data is recorded in a SQLite
database.


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
Win10TimelineGlob|C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlat ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Forensics.Timeline
description: |
  Win10 records recently used applications and files in a “timeline”
  accessible via the “WIN+TAB” key. The data is recorded in a SQLite
  database.

parameters:
  - name: UserFilter
    default: ""
    description: If specified we filter by this user ID.

  - name: ExecutionTimeAfter
    default: ""
    type: timestamp
    description: If specified only show executions after this time.

  - name: Win10TimelineGlob
    default: C:\Users\*\AppData\Local\ConnectedDevicesPlatform\L.*\ActivitiesCache.db

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - LET timeline = SELECT * FROM foreach(
         row={
            SELECT FullPath FROM glob(globs=Win10TimelineGlob)
         },
         query={
            SELECT AppId, FullPath, LastModifiedTime
            FROM sqlite(file=FullPath, query="SELECT * FROM Activity")
         })
      - LET TMP = SELECT get(
               item=parse_json_array(data=AppId).application,
               member="0") AS Application,
             parse_string_with_regex(
               string=FullPath,
               regex="\\\\L.(?P<User>[^\\\\]+)\\\\").User AS User,
               LastModifiedTime,
               LastModifiedTime.Unix as LastExecutionTS
        FROM timeline
      - LET A1 = SELECT * FROM if(
          condition=UserFilter,
          then={
            SELECT * FROM TMP WHERE User =~ UserFilter
          }, else=TMP)
      - SELECT * FROM if(
          condition=ExecutionTimeAfter,
          then={
            SELECT * FROM A1 WHERE LastExecutionTS > ExecutionTimeAfter
          }, else=A1)
```
   {{% /expand %}}

## Windows.Collectors.File

Collects files using a set of globs. All globs must be on the same
device. The globs will be searched in one pass - so you can provide
many globs at the same time.


Arg|Default|Description
---|------|-----------
collectionSpec|Glob\nUsers\\*\\NTUser.dat\n|A CSV file with a Glob column with all the globs to collect.\nNOTE: Globs must not have a leading device since the device\nwill depend on the VSS.\n
RootDevice|C:|The device to apply all the glob on.
Accessor|lazy_ntfs|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Collectors.File
description: |
   Collects files using a set of globs. All globs must be on the same
   device. The globs will be searched in one pass - so you can provide
   many globs at the same time.

parameters:
  - name: collectionSpec
    description: |
       A CSV file with a Glob column with all the globs to collect.
       NOTE: Globs must not have a leading device since the device
       will depend on the VSS.
    default: |
       Glob
       Users\*\NTUser.dat
  - name: RootDevice
    description: The device to apply all the glob on.
    default: "C:"
  - name: Accessor
    default: lazy_ntfs

sources:
   - name: All Matches Metadata
     queries:
      # Generate the collection globs for each device
      - LET specs = SELECT "\\\\.\\" + RootDevice + "\\" + Glob AS Glob
            FROM parse_csv(filename=collectionSpec, accessor="data")
            WHERE log(message="Processing Device " + RootDevice + " With " + Accessor)

      # Join all the collection rules into a single Glob plugin. This ensure we
      # only make one pass over the filesystem. We only want LFNs.
      - |
        LET hits = SELECT FullPath AS SourceFile, Size,
               timestamp(epoch=Ctime.Sec) AS Created,
               timestamp(epoch=Mtime.Sec) AS Modified,
               timestamp(epoch=Atime.Sec) AS LastAccessed
        FROM glob(globs=specs.Glob, accessor=Accessor)
        WHERE NOT IsDir AND log(message="Found " + SourceFile)

      # Create a unique key to group by - modification time and path name.
      # Order by device name so we get C:\ above the VSS device.
      - LET all_results <= SELECT Created, LastAccessed,
              Modified, Size, SourceFile
        FROM hits

      - SELECT * FROM all_results

   - name: Uploads
     queries:
      # Upload the files
      - LET uploaded_tiles = SELECT Created, LastAccessed, Modified, SourceFile, Size,
               upload(file=SourceFile, accessor=Accessor, name=SourceFile) AS Upload
        FROM all_results

      # Seperate the hashes into their own column.
      - SELECT now() AS CopiedOnTimestamp, SourceFile, Upload.Path AS DestinationFile,
               Size AS FileSize, Upload.sha256 AS SourceFileSha256,
               Created, Modified, LastAccessed
        FROM uploaded_tiles
```
   {{% /expand %}}

## Windows.Collectors.VSS

Collects files with VSS deduplication.

Volume shadow copies is a windows feature where file system
snapshots can be made at various times. When collecting files it is
useful to go back through the VSS to see older versions of critical
files.

At the same time we dont want to collect multiple copies of the
same data.

This artifact runs the provided globs over all the VSS and collects
the unique modified time + path combinations.

If a file was modified in a previous VSS copy, this artifact will
retrieve it at multiple shadow copies.


Arg|Default|Description
---|------|-----------
collectionSpec|Glob\nUsers\\*\\NTUser.dat\n|A CSV file with a Glob column with all the globs to collect.\nNOTE: Globs must not have a leading device since the device\nwill depend on the VSS.\n
RootDevice|C:|The device to apply all the glob on.
Accessor|lazy_ntfs|
VSSDateRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Collectors.VSS
description: |
   Collects files with VSS deduplication.

   Volume shadow copies is a windows feature where file system
   snapshots can be made at various times. When collecting files it is
   useful to go back through the VSS to see older versions of critical
   files.

   At the same time we dont want to collect multiple copies of the
   same data.

   This artifact runs the provided globs over all the VSS and collects
   the unique modified time + path combinations.

   If a file was modified in a previous VSS copy, this artifact will
   retrieve it at multiple shadow copies.

parameters:
  - name: collectionSpec
    description: |
       A CSV file with a Glob column with all the globs to collect.
       NOTE: Globs must not have a leading device since the device
       will depend on the VSS.
    default: |
       Glob
       Users\*\NTUser.dat
  - name: RootDevice
    description: The device to apply all the glob on.
    default: "C:"
  - name: Accessor
    default: lazy_ntfs
  - name: VSSDateRegex
    default: .

sources:
   - name: All Matches Metadata
     queries:
      - LET originating_machine <= SELECT Data.SystemName AS System
            FROM glob(globs="/*", accessor=Accessor)
            WHERE Name = "\\\\.\\" + RootDevice

      # Generate the collection globs for each device
      - LET specs = SELECT Device + Glob AS Glob FROM parse_csv(
            filename=collectionSpec, accessor="data")
            WHERE log(message="Processing Device " + Device + " With " + Accessor)

      # Join all the collection rules into a single Glob plugin. This ensure we
      # only make one pass over the filesystem. We only want LFNs.
      - |
        LET hits = SELECT FullPath AS SourceFile, Size,
               timestamp(epoch=Ctime.Sec) AS Created,
               timestamp(epoch=Mtime.Sec) AS Modified,
               timestamp(epoch=Atime.Sec) AS LastAccessed,
               Device, strip(string=FullPath, prefix=Device) AS Path,
               Data.mft AS MFT, Data.name_type AS NameType
        FROM glob(globs=specs.Glob, accessor=Accessor)
        WHERE NOT IsDir

      # Get all volume shadows on this system.
      - LET volume_shadows = SELECT Data.InstallDate AS InstallDate,
               Data.DeviceObject + "\\" AS Device
        FROM glob(globs='/*', accessor=Accessor)
        WHERE Device =~ 'VolumeShadowCopy' AND
              Data.OriginatingMachine = originating_machine.System[0] AND
              InstallDate =~ VSSDateRegex

      # The target devices are the root device and all the VSS
      - LET target_devices = SELECT * FROM chain(
            a={SELECT "\\\\.\\" + RootDevice + "\\" AS Device from scope()},
            b=volume_shadows)

      # Get all the paths matching the collection globs.
      - LET all_matching = SELECT * FROM foreach(row=target_devices, query=hits)

      # Create a unique key to group by - modification time and path name.
      # Order by device name so we get C:\ above the VSS device.
      - LET all_results <= SELECT Created, LastAccessed, Path, MFT, NameType,
              Modified, Size, SourceFile, Device, format(format="%s:%v", args=[Modified, MFT]) AS Key
        FROM all_matching ORDER BY Device DESC
      - SELECT * FROM all_results

   - name: Uploads
     queries:
      # Get all the unique versions of the sort key - that is unique instances of
      # mod time + path. If a path has several mod time (i.e. different times in each VSS
      # we will get them all). But if the same path has the same mod time in all VSS we only
      # take the first one which due to the sorting above will be the root device usually.
      - LET unique_mtimes = SELECT * FROM all_results GROUP BY Key

      # Upload the files using the MFT accessor.
      - LET uploaded_tiles = SELECT Created, LastAccessed, Modified, MFT, SourceFile, Size,
               upload(file=Device+MFT, name=SourceFile, accessor="mft") AS Upload
        FROM unique_mtimes

      # Seperate the hashes into their own column.
      - SELECT now() AS CopiedOnTimestamp, SourceFile, Upload.Path AS DestinationFile,
               Size AS FileSize, Upload.sha256 AS SourceFileSha256,
               Created, Modified, LastAccessed, MFT
        FROM uploaded_tiles
```
   {{% /expand %}}

## Windows.NTFS.I30

Carve the $I30 index stream for a directory.

This can reveal previously deleted files. Optionally upload the I30
stream to the server as well.


Arg|Default|Description
---|------|-----------
DirectoryGlobs|C:\\Users\\|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.NTFS.I30
description: |
  Carve the $I30 index stream for a directory.

  This can reveal previously deleted files. Optionally upload the I30
  stream to the server as well.

parameters:
 - name: DirectoryGlobs
   default: C:\Users\

precondition:
  SELECT * FROM info() where OS = 'windows'

sources:
  - name: UploadI30Streams
    queries:
       - LET inodes = SELECT FullPath, Data.mft AS MFT,
             parse_ntfs(device=FullPath, inode=Data.mft) AS MFTInfo
         FROM glob(globs=DirectoryGlobs, accessor="ntfs")
         WHERE IsDir

       - LET upload_streams = SELECT * FROM foreach(
            row=MFTInfo.Attributes,
            query={
              SELECT Type, TypeId, Id, Inode, Size, Name, FullPath,
                     upload(accessor="mft", file=MFTInfo.Device + Inode,
                            name=FullPath + "/" + Inode) AS IndexUpload
              FROM scope()
              WHERE Type =~ "INDEX_"
            })

       - SELECT * FROM foreach(row=inodes, query=upload_streams)

  - name: AnalyzeI30
    queries:
       - SELECT * FROM foreach(
           row=inodes,
           query={
             SELECT FullPath, Name, NameType, Size, AllocatedSize,
                    IsSlack, SlackOffset, Mtime, Atime, Ctime, Btime, MFTId
             FROM parse_ntfs_i30(device=MFTInfo.Device, inode=MFT)
           })
```
   {{% /expand %}}

## Windows.NTFS.MFT

This artifact scans the $MFT file on the host showing all files
within the MFT.  This is useful in order to try and recover deleted
files. Take the MFT ID of a file of interest and provide it to the
Windows.NTFS.Recover artifact.


Arg|Default|Description
---|------|-----------
MFTFilename|C:/$MFT|
Accessor|ntfs|
FilenameRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.NTFS.MFT
description: |
  This artifact scans the $MFT file on the host showing all files
  within the MFT.  This is useful in order to try and recover deleted
  files. Take the MFT ID of a file of interest and provide it to the
  Windows.NTFS.Recover artifact.

parameters:
  - name: MFTFilename
    default: "C:/$MFT"

  - name: Accessor
    default: ntfs

  - name: FilenameRegex
    default: .

sources:
  - queries:
      - SELECT * FROM parse_mft(filename=MFTFilename, accessor=Accessor)
        WHERE FileName =~ FilenameRegex
```
   {{% /expand %}}

## Windows.NTFS.Recover

Attempt to recover deleted files.

This artifact uploads all streams from an MFTId. If the MFT entry is
not allocated there is a chance that the cluster that contain the
actual data of the file will be intact still on the disk. Therefore
this artifact can be used to attempt to recover a deleted file.

A common use is to recover deleted directory entries using the
Windows.NTFS.I30 artifact and identify MFT entries of interest. This
is artifact can be used to attempt to recover some data.


Arg|Default|Description
---|------|-----------
MFTId|81978|
Drive|\\\\.\\C:|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.NTFS.Recover
description: |
  Attempt to recover deleted files.

  This artifact uploads all streams from an MFTId. If the MFT entry is
  not allocated there is a chance that the cluster that contain the
  actual data of the file will be intact still on the disk. Therefore
  this artifact can be used to attempt to recover a deleted file.

  A common use is to recover deleted directory entries using the
  Windows.NTFS.I30 artifact and identify MFT entries of interest. This
  is artifact can be used to attempt to recover some data.

parameters:
 - name: MFTId
   default: 81978
 - name: Drive
   default: '\\.\C:'

precondition:
  SELECT * FROM info() where OS = 'windows'

sources:
  - name: Upload
    queries:
       - SELECT * FROM foreach(
            row=parse_ntfs(device=Drive, inode=MFTId).Attributes,
            query={
              SELECT Type, TypeId, Id, Inode, Size, Name, FullPath,
                     upload(accessor="mft", file=Drive + Inode,
                            name=FullPath + "/" + Inode) AS IndexUpload
              FROM scope()
            })
```
   {{% /expand %}}
