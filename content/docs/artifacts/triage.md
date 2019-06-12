---
description: Triage artifacts simply collect various files as quickly as possible.
linktitle: Windows Triage
menu:
  docs: {parent: Artifacts, weight: 15}
title: Windows Triage Artifacts
toc: true

---
## Windows.Triage.Collectors.Amcache

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_AmcacheDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_AmcacheDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Amcache
description: |
  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Amcache",
               accessor="ntfs",
               path="C:\\Windows\\AppCompat\\Programs\\Amcache.hve")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Amcache transaction files",
               accessor="ntfs",
               path="C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG*")
          })
```
   </div></a>

## Windows.Triage.Collectors.BCD

Boot Configuration Files.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_BCDDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_BCDDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.BCD
description: |
  Boot Configuration Files.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="BCD",
               path=[
                  "C:\\Boot\\BCD",
                  "C:\\Boot\\BCD.LOG*"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.Chrome

Collect Chrome related artifacts.

{{ Query "SELECT * FROM Rows" }}


Arg|Default|Description
---|------|-----------
baseLocations|C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\|Globs for different possible locations of firefox profiles.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_ChromeDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_ChromeDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Chrome
description: |
  Collect Chrome related artifacts.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: baseLocations
    description: Globs for different possible locations of firefox profiles.
    default: C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome bookmarks",
               path=split(string=baseLocations, sep=",") + "Bookmarks*")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Cookies",
               path=split(string=baseLocations, sep=",") + "Cookies*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Current Session",
               path=split(string=baseLocations, sep=",") + "Current Session")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Current Tabs",
               path=split(string=baseLocations, sep=",") + "Current Tabs")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Favicons",
               path=split(string=baseLocations, sep=",") + "Favicons*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome History",
               path=split(string=baseLocations, sep=",") + "History*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Last Session",
               path=split(string=baseLocations, sep=",") + "Last Session")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Last Tabs",
               path=split(string=baseLocations, sep=",") + "Last Tabs")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Preferences",
               path=split(string=baseLocations, sep=",") + "Preferences")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Shortcuts",
               path=split(string=baseLocations, sep=",") + "Shortcuts*")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Top Sites",
               path=split(string=baseLocations, sep=",") + "Top Sites*")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Visited Links",
               path=split(string=baseLocations, sep=",") + "Visited Links")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Web Data",
               path=split(string=baseLocations, sep=",") + "Web Data*")
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.Edge

Collect Edge related artifacts.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_EdgeDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_EdgeDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Edge
description: |
  Collect Edge related artifacts.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Edge folder",
               path="C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_*\\**")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WebcacheV01.dat",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**")
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.EventLogs

Collect event log files.

{{ Query "SELECT * FROM Rows" }}


Arg|Default|Description
---|------|-----------
EventLogGlobs|C:\\Windows\\system32\\config\\*.evt,C:\\Windows\\system32\\winevt\\logs\\*.evtx|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_EventLogsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_EventLogsDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.EventLogs
description: |
  Collect event log files.

  {{ Query "SELECT * FROM Rows" }}

parameters:
  - name: EventLogGlobs
    default: C:\Windows\system32\config\*.evt,C:\Windows\system32\winevt\logs\*.evtx

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM Artifact.Triage.Collection.Upload(
           type="EventLogs",
           path=split(string=EventLogGlobs, sep=","))
```
   </div></a>

## Windows.Triage.Collectors.EventTraceLogs

Collect event trace log files.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_EventTraceLogsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_EventTraceLogsDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.EventTraceLogs
description: |
  Collect event trace log files.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.EvidenceOfExecution

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_EvidenceOfExecutionDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_EvidenceOfExecutionDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.EvidenceOfExecution
description: |
  {{ Query "SELECT * FROM Rows" }}

includes:
  - Windows.Triage.Collectors.Amcache

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.Firefox

Collect Firefox related artifacts.

{{ Query "SELECT * FROM Rows" }}


Arg|Default|Description
---|------|-----------
baseLocations|C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\,C:\\Documents and Settings\\*\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\|Globs for different possible locations of firefox profiles.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_FirefoxDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_FirefoxDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Firefox
description: |
  Collect Firefox related artifacts.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: baseLocations
    description: Globs for different possible locations of firefox profiles.
    default: C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\,C:\Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.InternetExplorer

Collect Firefox related artifacts.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_InternetExplorerDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_InternetExplorerDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.InternetExplorer
description: |
  Collect Firefox related artifacts.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat History",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\index.dat",
                 "C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\*\\index.dat"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat temp internet files",
               path="C:\\Documents and Settings\\*\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat cookies",
               path="C:\\Documents and Settings\\*\\Cookies\\index.dat")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat UserData",
               path="C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Internet Explorer\\UserData\\index.dat")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat Office XP",
               path="C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Office\\Recent\\index.dat")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat Office",
               path="C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\index.dat")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Internet Explorer folder",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Internet Explorer\\**")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Roaming Internet Explorer folder",
               path="C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Internet Explorer\\**")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 History",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\History\\**")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Cache",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\**")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Cookies",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Cookies\\**")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Download History",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory\\**")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Metadata",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**")
          },
          b5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Cache",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\**")
          },
          b6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Cookies",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\**")
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.Jabber

Jabber.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_JabberDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_JabberDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Jabber
description: |
  Jabber.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Cisco Jabber Database",
               accessor="ntfs",
               path=[
                 "C:\\Users\\*\\AppData\\Local\\Cisco\\Unified Communications\\Jabber\\CSF\\History\\*.db"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.LnkFiles

Lnk files and jump lists.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_LnkFilesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_LnkFilesDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.LnkFiles
description: |
  Lnk files and jump lists.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.NTFSMetadata

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_NTFSMetadataDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_NTFSMetadataDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.NTFSMetadata
description: |
  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - name: NTFS Metadata Files
    queries:
      - SELECT * FROM Artifact.Triage.Collection.Upload(
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
   </div></a>

## Windows.Triage.Collectors.OutlookPST

Outlook PST and OST files.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_OutlookPSTDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_OutlookPSTDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.OutlookPST
description: |
  Outlook PST and OST files.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.PowershellConsoleLogs

PowerShell Console Log File.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_PowershellConsoleLogsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_PowershellConsoleLogsDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.PowershellConsoleLogs
description: |
  PowerShell Console Log File.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="PowerShell Console Log",
               path="C:\\users\\*\\Appdata\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt")
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.RecycleBin

Collect contents of Recycle Bin.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_RecycleBinDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_RecycleBinDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.RecycleBin
description: |
  Collect contents of Recycle Bin.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Recycle.Bin",
               path=[
                 "C:\\$Recycle.Bin\\**",
                 "C:\\RECYCLER\\**"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.RegistryHives

System and user related Registry hives.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_RegistryHivesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_RegistryHivesDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.RegistryHives
description: |
  System and user related Registry hives.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'
reference:
  - https://github.com/EricZimmerman/KapeFiles

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="ntuser.dat registry hive",
               accessor="ntfs",
               path=[
                 "C:\\Documents and Settings\\*\\ntuser.dat",
                 "C:\\Users\\*\\ntuser.dat"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="ntuser.dat registry transaction files",
               accessor="ntfs",
               path="C:\\Users\\*\\ntuser.dat.LOG*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="UsrClass.dat registry hive",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="UsrClass.dat registry transaction files",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG*")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SAM.LOG*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SECURITY.LOG*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SOFTWARE.LOG*")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SYSTEM.LOG*")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SAM")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SECURITY")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SOFTWARE")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SYSTEM")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="RegBack registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\*.LOG*")
          },
          b5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SAM")
          },
          b6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SECURITY")
          },
          b7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SOFTWARE")
          },
          b8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SYSTEM")
          },
          b9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SYSTEM")
          },
          ba={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Profile registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat")
          },
          c1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Profile registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat.LOG*")
          },
          c2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Service registry hive",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat")
          },
          c3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Service registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat.LOG*")
          },
          c4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Network Service registry hive",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat")
          },
          c5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Network Service registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat.LOG*")
          },
          c6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Restore Points Registry Hives (XP)",
               accessor="ntfs",
               path="C:\\System Volume Information\\_restore*\\RP*\\snapshot\\_REGISTRY_*")
          }

        )
```
   </div></a>

## Windows.Triage.Collectors.SRUM

System Resource Usage Monitor (SRUM) Data.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_SRUMDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_SRUMDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.SRUM
description: |
  System Resource Usage Monitor (SRUM) Data.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SRUM",
               path="C:\\Windows\\System32\\SRU\\**")
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.ScheduledTasks

Scheduled tasks (*.job and XML).

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_ScheduledTasksDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_ScheduledTasksDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.ScheduledTasks
description: |
  Scheduled tasks (*.job and XML).

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.Skype

Skype.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_SkypeDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_SkypeDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.Skype
description: |
  Skype.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
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
   </div></a>

## Windows.Triage.Collectors.StartupInfo

StartupInfo XML Files.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_StartupInfoDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_StartupInfoDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.StartupInfo
description: |
  StartupInfo XML Files.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="StartupInfo XML Files",
               path=[
                  "C:\\Windows\\System32\\WDI\\LogFiles\\StartupInfo\\*.xml"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.TeraCopy

TeraCopy log history.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_TeraCopyDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_TeraCopyDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.TeraCopy
description: |
  TeraCopy log history.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="TeraCopy",
               path=[
                  "C:\\Users\\*\\AppData\\Roaming\\TeraCopy"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.ThumbDB

Thumbcache DB.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_ThumbDBDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_ThumbDBDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.ThumbDB
description: |
  Thumbcache DB.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Thumbcache DB",
               path=[
                  "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.USBDeviceLogs

USB devices log files.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_USBDeviceLogsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_USBDeviceLogsDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.USBDeviceLogs
description: |
  USB devices log files.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Setupapi.log",
               path=[
                  "C:\\Windows\\setupapi.log",
                  "C:\\Windows\\inf\\setupapi.dev.log"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.WBEM

Web-Based Enterprise Management (WBEM).

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_WBEMDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_WBEMDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.WBEM
description: |
  Web-Based Enterprise Management (WBEM).

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WBEM",
               path=[
                 "C:\\Windows\\System32\\wbem\\Repository"
               ])
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.WindowsFirewall

Windows Firewall Logs.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_WindowsFirewallDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_WindowsFirewallDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.WindowsFirewall
description: |
  Windows Firewall Logs.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Windows Firewall Logs",
               path="C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.*"
          }
        )
```
   </div></a>

## Windows.Triage.Collectors.WindowsIndex

Windows Index Search.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_Collectors_WindowsIndexDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_Collectors_WindowsIndexDetails" style="width: fit-content">


```
name: Windows.Triage.Collectors.WindowsIndex
description: |
  Windows Index Search.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WindowsIndexSearch",
               path="C:\\programdata\\microsoft\\search\\data\\applications\\windows\\Windows.edb")
          }
        )
```
   </div></a>

## Windows.Triage.WebBrowsers

A high level artifact for selecting all browser related artifacts.

{{ Query "SELECT * FROM Rows" }}



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Triage_WebBrowsersDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Triage_WebBrowsersDetails" style="width: fit-content">


```
name: Windows.Triage.WebBrowsers
description: |
  A high level artifact for selecting all browser related artifacts.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Windows.Triage.Collectors.Chrome() },
          a2={ SELECT * FROM Artifact.Windows.Triage.Collectors.Firefox() },
          a3={ SELECT * FROM Artifact.Windows.Triage.Collectors.Edge() },
          a4={ SELECT * FROM Artifact.Windows.Triage.Collectors.InternetExplorer() }
        )
```
   </div></a>

## Triage.Collection.Upload

A Generic uploader used by triaging artifacts.


Arg|Default|Description
---|------|-----------
path||This is the glob of the files we use.
type||The type of files these are.
accessor|file|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Triage_Collection_UploadDetails">View Artifact</a>
 <div class="collapse dn" id="Triage_Collection_UploadDetails" style="width: fit-content">


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
      - LET results = SELECT FullPath, Size,
               timestamp(epoch=Mtime.Sec) As Modifed,
               type AS Type, {
                 SELECT * FROM upload(files=FullPath, accessor=accessor)
               } AS FileDetails
        FROM glob(globs=path, accessor=accessor)
        WHERE NOT IsDir
      - SELECT FullPath, Size, Modifed, Type,
               FileDetails.Path AS ZipPath,
               FileDetails.Md5 as Md5,
               FileDetails.Sha256 as SHA256
        FROM results
```
   </div></a>

## Windows.Forensics.Bam

The Background Activity Moderator (BAM) is a Windows service that
Controls activity of background applications.  This service exists
in Windows 10 only after Fall Creators update – version 1709.

It provides full path of the executable file that was run on the
system and last execution date/time


Arg|Default|Description
---|------|-----------
bamKeys|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Forensics_BamDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Forensics_BamDetails" style="width: fit-content">


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
      default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*

sources:
  - precondition:
      SELECT OS from info() where OS = "windows"
    queries:
      - LET users <= SELECT Name, UUID FROM Artifact.Windows.Sys.Users()
      - SELECT basename(path=dirname(path=FullPath)) as SID, {
            SELECT Name FROM users WHERE UUID = basename(path=dirname(path=FullPath))
          } As UserName,
          Name as Binary,
          timestamp(winfiletime=binary_parse(
          string=Data.value, target="int64").AsInteger) as Bam_time
        FROM glob(globs=bamKeys + "\\*", accessor="reg")
        WHERE Data.type = "BINARY"
```
   </div></a>

