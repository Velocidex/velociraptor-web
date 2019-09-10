---
description: Triage artifacts simply collect various files as quickly as possible.
linktitle: Windows Triage
title: Windows Triage Artifacts
weight: 40

---
## Windows.Triage.Collectors.Amcache



Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\nAmcache,ntfs,C:\\Windows\\AppCompat\\Programs\\Amcache.hve\nAmcache transaction files,ntfs,C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG*\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Amcache

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: triageTable
    default: |
      Type,Accessor,Glob
      Amcache,ntfs,C:\Windows\AppCompat\Programs\Amcache.hve
      Amcache transaction files,ntfs,C:\Windows\AppCompat\Programs\Amcache.hve.LOG*

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.UploadTable(triageTable=triageTable)
```
   {{% /expand %}}

## Windows.Triage.Collectors.BCD

Boot Configuration Files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.BCD
description: |
  Boot Configuration Files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="BCD",
               path=[
                  "C:\\Boot\\BCD",
                  "C:\\Boot\\BCD.LOG*"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Chrome

Collect Chrome related artifacts.


Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\nChrome Bookmarks,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Bookmarks*\nChrome Bookmarks,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Bookmarks*\nChrome Bookmarks,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Bookmarks*\nChrome Bookmarks,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Bookmarks*\nChrome Cookies,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Cookies*\nChrome Cookies,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cookies*\nChrome Current Session,ntfs,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Current Session\nChrome Current Session,ntfs,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Current Session\nChrome Current Tab,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Current Tab\nChrome Current Tab,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Current Tab\nChrome Favicons,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Favicons*\nChrome Favicons,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Favicons*\nChrome History,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\History*\nChrome History,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History*\nChrome Last Session,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Last Session\nChrome Last Session,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Last Session\nChrome Last Tabs,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Last Tabs\nChrome Last Tabs,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Last Tabs\nChrome Preferences,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Preferences\nChrome Preferences,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Preferences\nChrome Shortcuts,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Shortcuts*\nChrome Shortcuts,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Shortcuts*\nChrome Top Sites,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Top Sites*\nChrome Top Sites,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Top Sites\nChrome Visited Links,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Visited Links\nChrome Visited Links,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Visited Links\nChrome Web Data,file,C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\Web Data*\nChrome Web Data,file,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Web Data*\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Chrome
description: |
  Collect Chrome related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: triageTable
    default: |
      Type,Accessor,Glob
      Chrome Bookmarks,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Bookmarks*
      Chrome Bookmarks,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks*
      Chrome Bookmarks,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Bookmarks*
      Chrome Bookmarks,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks*
      Chrome Cookies,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Cookies*
      Chrome Cookies,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Cookies*
      Chrome Current Session,ntfs,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Current Session
      Chrome Current Session,ntfs,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Current Session
      Chrome Current Tab,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Current Tab
      Chrome Current Tab,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Current Tab
      Chrome Favicons,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Favicons*
      Chrome Favicons,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Favicons*
      Chrome History,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\History*
      Chrome History,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\History*
      Chrome Last Session,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Last Session
      Chrome Last Session,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Last Session
      Chrome Last Tabs,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Last Tabs
      Chrome Last Tabs,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Last Tabs
      Chrome Preferences,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Preferences
      Chrome Preferences,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Preferences
      Chrome Shortcuts,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Shortcuts*
      Chrome Shortcuts,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Shortcuts*
      Chrome Top Sites,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Top Sites*
      Chrome Top Sites,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Top Sites
      Chrome Visited Links,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Visited Links
      Chrome Visited Links,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Visited Links
      Chrome Web Data,file,C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\Web Data*
      Chrome Web Data,file,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Web Data*

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.UploadTable(triageTable=triageTable)
```
   {{% /expand %}}

## Windows.Triage.Collectors.Edge

Collect Edge related artifacts.


Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\nEdge folder,ntfs,C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_*\\**\nWebcacheV01.dat,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Edge
description: |
  Collect Edge related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: triageTable
    default: |
      Type,Accessor,Glob
      Edge folder,ntfs,C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_*\**
      WebcacheV01.dat,ntfs,C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\**

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.UploadTable(triageTable=triageTable)
```
   {{% /expand %}}

## Windows.Triage.Collectors.EventLogs

Collect event log files.


Arg|Default|Description
---|------|-----------
EventLogGlobs|C:\\Windows\\system32\\config\\*.evt,C:\\Windows\\system32\\winevt\\logs\\*.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EventLogs
description: |
  Collect event log files.

parameters:
  - name: EventLogGlobs
    default: C:\Windows\system32\config\*.evt,C:\Windows\system32\winevt\logs\*.evtx

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM Artifact.Triage.Collection.Upload(
           type="EventLogs",
           path=split(string=EventLogGlobs, sep=","))
```
   {{% /expand %}}

## Windows.Triage.Collectors.EventTraceLogs

Collect event trace log files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EventTraceLogs
description: |
  Collect event trace log files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="WDI Trace Logs",
            path=[
              "C:\\Windows\\System32\\WDI\\LogFiles\\*.etl*",
              "C:\\Windows\\System32\\WDI\\{*"
            ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="WMI Trace Logs",
            path="C:\\Windows\\System32\\LogFiles\\WMI\\*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="SleepStudy Trace Logs",
            path="C:\\Windows\\System32\\SleepStudy*")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="Energy-NTKL Trace Logs",
            path="C:\\ProgramData\\Microsoft\\Windows\\PowerEfficiency Diagnostics\\energy-ntkl.etl")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.EvidenceOfExecution



{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EvidenceOfExecution

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Prefetch",
               path="C:\\Windows\\prefetch\\*.pf")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="RecentFileCache",
               path="C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Firefox

Collect Firefox related artifacts.


Arg|Default|Description
---|------|-----------
baseLocations|C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\,C:\\Documents and Settings\\*\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\|Globs for different possible locations of firefox profiles.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Firefox
description: |
  Collect Firefox related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: baseLocations
    description: Globs for different possible locations of firefox profiles.
    default: C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\,C:\Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Places",
               path=split(string=baseLocations, sep=",") + "places.sqlite*")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Downloads",
               path=split(string=baseLocations, sep=",") + "downloads.sqlite*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Form history",
               path=split(string=baseLocations, sep=",") + "formhistory.sqlite*")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Cookies",
               path=split(string=baseLocations, sep=",") + "cookies.sqlite*")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Signons",
               path=split(string=baseLocations, sep=",") + "signons.sqlite*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Webappstore",
               path=split(string=baseLocations, sep=",") + "webappstore.sqlite*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Favicons",
               path=split(string=baseLocations, sep=",") + "favicons.sqlite*")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Addons",
               path=split(string=baseLocations, sep=",") + "addons.sqlite*")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Search",
               path=split(string=baseLocations, sep=",") + "search.sqlite*")
          }
          )
```
   {{% /expand %}}

## Windows.Triage.Collectors.InternetExplorer

Collect Firefox related artifacts.


Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\nIndex.dat History,file,C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\index.dat\nIndex.dat History,file,C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\*\\index.dat\nIndex.dat temp internet files,file,C:\\Documents and Settings\\*\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat\nIndex.dat cookies,file,C:\\Documents and Settings\\*\\Cookies\\index.dat\nIndex.dat UserData,file,C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Internet Explorer\\UserData\\index.dat\nIndex.dat Office XP,file,C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Office\\Recent\\index.dat\nIndex.dat Office,file,C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\index.dat\nLocal Internet Explorer folder,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Internet Explorer\\**\nRoaming Internet Explorer folder,file,C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Internet Explorer\\**\nIE 9/10 History,file,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\History\\**\nIE 9/10 Cache,file,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\**\nIE 9/10 Cookies,file,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Cookies\\**\nIE 9/10 Download History,file,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory\\**\nIE 11 Metadata,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**\nIE 11 Cache,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\**\nIE 11 Cookies,file,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\**\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.InternetExplorer
description: |
  Collect Firefox related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: triageTable
    default: |
      Type,Accessor,Glob
      Index.dat History,file,C:\Documents and Settings\*\Local Settings\History\History.IE5\index.dat
      Index.dat History,file,C:\Documents and Settings\*\Local Settings\History\History.IE5\*\index.dat
      Index.dat temp internet files,file,C:\Documents and Settings\*\Local Settings\Temporary Internet Files\Content.IE5\index.dat
      Index.dat cookies,file,C:\Documents and Settings\*\Cookies\index.dat
      Index.dat UserData,file,C:\Documents and Settings\*\Application Data\Microsoft\Internet Explorer\UserData\index.dat
      Index.dat Office XP,file,C:\Documents and Settings\*\Application Data\Microsoft\Office\Recent\index.dat
      Index.dat Office,file,C:\Users\*\AppData\Roaming\Microsoft\Office\Recent\index.dat
      Local Internet Explorer folder,ntfs,C:\Users\*\AppData\Local\Microsoft\Internet Explorer\**
      Roaming Internet Explorer folder,file,C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\**
      IE 9/10 History,file,C:\Users\*\AppData\Local\Microsoft\Windows\History\**
      IE 9/10 Cache,file,C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\**
      IE 9/10 Cookies,file,C:\Users\*\AppData\Local\Microsoft\Windows\Cookies\**
      IE 9/10 Download History,file,C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\**
      IE 11 Metadata,ntfs,C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\**
      IE 11 Cache,ntfs,C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\**
      IE 11 Cookies,file,C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\**

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.UploadTable(triageTable=triageTable)
```
   {{% /expand %}}

## Windows.Triage.Collectors.Jabber

Jabber.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Jabber
description: |
  Jabber.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Cisco Jabber Database",
               accessor="ntfs",
               path=[
                 "C:\\Users\\*\\AppData\\Local\\Cisco\\Unified Communications\\Jabber\\CSF\\History\\*.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.LnkFiles

Lnk files and jump lists.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.LnkFiles
description: |
  Lnk files and jump lists.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Lnk files from Recent",
               path=[
                 "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\**",
                 "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\**",
                 "C:\\Documents and Settings\\*\\Recent\\**"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Desktop lnk files",
               path=[
                 "C:\\Documents and Settings\\*\\Desktop\\*.lnk",
                 "C:\\Users\\*\\Desktop\\*.lnk"
              ])
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Restore point lnk files XP",
               path="C:\\System Volume Information\\_restore*\\RP*\\*.lnk")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.NTFSMetadata



{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.NTFSMetadata

precondition: SELECT OS From info() where OS = 'windows'

reference:
  - https://github.com/EricZimmerman/KapeFiles

sources:
  - name: NTFS Metadata Files
    queries:
      - |
        SELECT * FROM Artifact.Triage.Collection.Upload(
        type="NTFS Metadata Files",
        accessor="ntfs",
        path=[
            "C:\\$MFT",
            "C:\\$LogFile",
            "C:\\$Extend\\$UsnJrnl:$J",
            "C:\\$Extend\\$UsnJrnl:$Max",
            "C:\\$Secure:$SDS",
            "C:\\$Boot",
            "C:\\$Extend\\$RmMetadata\\$TxfLog\\$Tops:$T"
        ])
```
   {{% /expand %}}

## Windows.Triage.Collectors.OutlookPST

Outlook PST and OST files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.OutlookPST
description: |
  Outlook PST and OST files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="PST",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Microsoft\\Outlook\\*.pst",
                 "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.pst"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="OST",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Microsoft\\Outlook\\*.ost",
                 "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.ost"
              ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.PowershellConsoleLogs

PowerShell Console Log File.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.PowershellConsoleLogs
description: |
  PowerShell Console Log File.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="PowerShell Console Log",
               path="C:\\users\\*\\Appdata\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.RecycleBin

Collect contents of Recycle Bin.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.RecycleBin
description: |
  Collect contents of Recycle Bin.


precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Recycle.Bin",
               path=[
                 "C:\\$Recycle.Bin\\**",
                 "C:\\RECYCLER\\**"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.RegistryHives

System and user related Registry hives.


Arg|Default|Description
---|------|-----------
triageTable|Type,Accessor,Glob\nntuser.dat registry hive,ntfs,C:\\Documents and Settings\\*\\ntuser.dat\nntuser.dat registry hive,ntfs,C:\\Users\\*\\ntuser.dat\nntuser.dat registry transaction files,ntfs,C:\\Documents and Settings\\*\\ntuser.dat.LOG*\nntuser.dat registry transaction files,ntfs,C:\\Users\\*\\ntuser.dat.LOG*\nUsrClass.dat registry hive,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat\nUsrClass.dat registry transaction files,ntfs,C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG*\nSAM registry transaction files,ntfs,C:\\Windows\\System32\\config\\SAM.LOG*\nSECURITY registry transaction files,ntfs,C:\\Windows\\System32\\config\\SECURITY.LOG*\nSYSTEM registry transaction files,ntfs,C:\\Windows\\System32\\config\\SYSTEM.LOG*\nSAM registry hive,ntfs,C:\\Windows\\System32\\config\\SAM\nSECURITY registry hive,ntfs,C:\\Windows\\System32\\config\\SECURITY\nSOFTWARE registry hive,ntfs,C:\\Windows\\System32\\config\\SOFTWARE\nSYSTEM registry hive,ntfs,C:\\Windows\\System32\\config\\SYSTEM\nRegBack registry transaction files,ntfs,C:\\Windows\\System32\\config\\RegBack\\*.LOG*\nSAM registry hive (RegBack),ntfs,C:\\Windows\\System32\\config\\RegBack\\SAM\nSECURITY registry hive (RegBack),ntfs,C:\\Windows\\System32\\config\\RegBack\\SECURITY\nSOFTWARE registry hive (RegBack),ntfs,C:\\Windows\\System32\\config\\RegBack\\SOFTWARE\nSYSTEM registry hive (RegBack),ntfs,C:\\Windows\\System32\\config\\RegBack\\SYSTEM\nSystem Profile registry hive,ntfs,C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat\nSystem Profile registry transaction files,ntfs,C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat.LOG*\nLocal Service registry hive,ntfs,C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat\nLocal Service registry transaction files,ntfs,C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat.LOG*\nNetwork Service registry hive,ntfs,C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat\nNetwork Service registry transaction files,ntfs,C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat.LOG*\nSystem Restore Points Registry Hives (XP),ntfs,C:\\System Volume Information\\_restore*\\RP*\\snapshot\\_REGISTRY_*\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.RegistryHives
description: |
  System and user related Registry hives.

precondition: SELECT OS From info() where OS = 'windows'

reference:
  - https://github.com/EricZimmerman/KapeFiles

parameters:
  - name: triageTable
    default: |
      Type,Accessor,Glob
      ntuser.dat registry hive,ntfs,C:\Documents and Settings\*\ntuser.dat
      ntuser.dat registry hive,ntfs,C:\Users\*\ntuser.dat
      ntuser.dat registry transaction files,ntfs,C:\Documents and Settings\*\ntuser.dat.LOG*
      ntuser.dat registry transaction files,ntfs,C:\Users\*\ntuser.dat.LOG*
      UsrClass.dat registry hive,ntfs,C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat
      UsrClass.dat registry transaction files,ntfs,C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG*
      SAM registry transaction files,ntfs,C:\Windows\System32\config\SAM.LOG*
      SECURITY registry transaction files,ntfs,C:\Windows\System32\config\SECURITY.LOG*
      SYSTEM registry transaction files,ntfs,C:\Windows\System32\config\SYSTEM.LOG*
      SAM registry hive,ntfs,C:\Windows\System32\config\SAM
      SECURITY registry hive,ntfs,C:\Windows\System32\config\SECURITY
      SOFTWARE registry hive,ntfs,C:\Windows\System32\config\SOFTWARE
      SYSTEM registry hive,ntfs,C:\Windows\System32\config\SYSTEM
      RegBack registry transaction files,ntfs,C:\Windows\System32\config\RegBack\*.LOG*
      SAM registry hive (RegBack),ntfs,C:\Windows\System32\config\RegBack\SAM
      SECURITY registry hive (RegBack),ntfs,C:\Windows\System32\config\RegBack\SECURITY
      SOFTWARE registry hive (RegBack),ntfs,C:\Windows\System32\config\RegBack\SOFTWARE
      SYSTEM registry hive (RegBack),ntfs,C:\Windows\System32\config\RegBack\SYSTEM
      System Profile registry hive,ntfs,C:\Windows\System32\config\systemprofile\ntuser.dat
      System Profile registry transaction files,ntfs,C:\Windows\System32\config\systemprofile\ntuser.dat.LOG*
      Local Service registry hive,ntfs,C:\Windows\ServiceProfiles\LocalService\ntuser.dat
      Local Service registry transaction files,ntfs,C:\Windows\ServiceProfiles\LocalService\ntuser.dat.LOG*
      Network Service registry hive,ntfs,C:\Windows\ServiceProfiles\NetworkService\ntuser.dat
      Network Service registry transaction files,ntfs,C:\Windows\ServiceProfiles\NetworkService\ntuser.dat.LOG*
      System Restore Points Registry Hives (XP),ntfs,C:\System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.UploadTable(
               triageTable=triageTable)
```
   {{% /expand %}}

## Windows.Triage.Collectors.SRUM

System Resource Usage Monitor (SRUM) Data.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.SRUM
description: |
  System Resource Usage Monitor (SRUM) Data.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SRUM",
               path="C:\\Windows\\System32\\SRU\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.ScheduledTasks

Scheduled tasks (*.job and XML).


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.ScheduledTasks
description: |
  Scheduled tasks (*.job and XML).

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="at .job",
               path="C:\\Windows\\Tasks\\*.job")
          },
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="at SchedLgU.txt",
               path="C:\\Windows\\SchedLgU.txt")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="XML",
               path="C:\\Windows\\system32\\Tasks\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Skype

Skype.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Skype
description: |
  Skype.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="main.db",
               path=[
                  "C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.SkypeApp_*\\LocalState\\*\\main.db",
                  "C:\\Documents and Settings\\*\\Application Data\\Skype\\*\\main.db",
                  "C:\\Users\\*\\AppData\\Roaming\\Skype\\*\\main.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.StartupInfo

StartupInfo XML Files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.StartupInfo
description: |
  StartupInfo XML Files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="StartupInfo XML Files",
               path=[
                  "C:\\Windows\\System32\\WDI\\LogFiles\\StartupInfo\\*.xml"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.TeraCopy

TeraCopy log history.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.TeraCopy
description: |
  TeraCopy log history.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="TeraCopy",
               path=[
                  "C:\\Users\\*\\AppData\\Roaming\\TeraCopy"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.ThumbDB

Thumbcache DB.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.ThumbDB
description: |
  Thumbcache DB.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Thumbcache DB",
               path=[
                  "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.USBDeviceLogs

USB devices log files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.USBDeviceLogs
description: |
  USB devices log files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Setupapi.log",
               path=[
                  "C:\\Windows\\setupapi.log",
                  "C:\\Windows\\inf\\setupapi.dev.log"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WBEM

Web-Based Enterprise Management (WBEM).


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WBEM
description: |
  Web-Based Enterprise Management (WBEM).

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WBEM",
               path=[
                 "C:\\Windows\\System32\\wbem\\Repository"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WindowsFirewall

Windows Firewall Logs.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WindowsFirewall
description: |
  Windows Firewall Logs.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Windows Firewall Logs",
               path="C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.*")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WindowsIndex

Windows Index Search.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WindowsIndex
description: |
  Windows Index Search.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WindowsIndexSearch",
               path="C:\\programdata\\microsoft\\search\\data\\applications\\windows\\Windows.edb")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.ProcessMemory

Dump process memory and upload to the server


Arg|Default|Description
---|------|-----------
processRegex|notepad|

{{% expand  "View Artifact Source" %}}


```
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

## Windows.Triage.WebBrowsers

A high level artifact for selecting all browser related artifacts.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.WebBrowsers
description: |
  A high level artifact for selecting all browser related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Windows.Triage.Collectors.Chrome() },
          a2={ SELECT * FROM Artifact.Windows.Triage.Collectors.Firefox() },
          a3={ SELECT * FROM Artifact.Windows.Triage.Collectors.Edge() },
          a4={ SELECT * FROM Artifact.Windows.Triage.Collectors.InternetExplorer() }
        )
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


```
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
               timestamp(epoch=Mtime.Sec) As Modified,
               type AS Type, {
                 SELECT * FROM upload(files=FullPath, accessor=accessor)
               } AS FileDetails
        FROM glob(globs=path, accessor=accessor)
        WHERE NOT IsDir
      - |
        SELECT FullPath, Size, Modified, Type,
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


```
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
               timestamp(epoch=Mtime.Sec) As Modified,
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
           SELECT FullPath, Size, Modified, Type,
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
bamKeys|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\*\\*,HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\*\\*|

{{% expand  "View Artifact Source" %}}


```
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

sources:
  - precondition:
      SELECT OS from info() where OS = "windows"
    queries:
      - |
        LET users <= SELECT Name, UUID FROM Artifact.Windows.Sys.Users()
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


```
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
             number_of_hits=1000,
             accessor="ntfs")
```
   {{% /expand %}}

## Windows.Forensics.Prefetch

Windows keeps a cache of prefetch files. When an executable is run,
the system records properties about the executable to make it faster
to run next time. By parsing this information we are able to
determine when binaries are run in the past. On Windows10 we can see
the last 8 execution times.


Arg|Default|Description
---|------|-----------
prefetchGlobs|C:\\Windows\\Prefetch\\*.pf|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Forensics.Prefetch
description: |
  Windows keeps a cache of prefetch files. When an executable is run,
  the system records properties about the executable to make it faster
  to run next time. By parsing this information we are able to
  determine when binaries are run in the past. On Windows10 we can see
  the last 8 execution times.

reference:
  - https://www.forensicswiki.org/wiki/Prefetch

parameters:
    - name: prefetchGlobs
      default: C:\Windows\Prefetch\*.pf

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row={
             SELECT * FROM glob(globs=prefetchGlobs)
          },
          query={
             SELECT Name AS PrefetchFileName,
                    Executable, FileSize, LastRunTimes,
                    LastRunTimes.Unix AS LastExecutionTS,
                    RunCount
             FROM prefetch(filename=FullPath)
          })
```
   {{% /expand %}}

## Windows.Forensics.RecentApps

GUI Program execution launched on the Win10 system is tracked in the
RecentApps key


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
RecentAppsKey|Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\\*|
UserHomes|C:\\Users\\*\\NTUSER.DAT|

{{% expand  "View Artifact Source" %}}


```
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

## Windows.Forensics.Timeline

Win10 records recently used applications and files in a “timeline”
accessible via the “WIN+TAB” key. The data is recorded in a SQLite
database.


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
Win10TimelineGlob|C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\L.*\\ActivitiesCache.db|

{{% expand  "View Artifact Source" %}}


```
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

