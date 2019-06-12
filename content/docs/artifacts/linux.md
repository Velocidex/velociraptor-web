---
description: Linux Artifacts
linktitle: Linux Artifacts
menu:
  docs: {parent: Artifacts, weight: 1}
title: Linux Artifacts
toc: true

---
## Linux.Applications.Chrome.Extensions

Fetch Chrome extensions.

Chrome extensions are installed into the user's home directory.  We
search for manifest.json files in a known path within each system
user's home directory. We then parse the manifest file as JSON.

Many extensions use locale packs to resolve strings like name and
description. In this case we detect the default locale and load
those locale files. We then resolve the extension's name and
description from there.


Arg|Default|Description
---|------|-----------
extensionGlobs|/.config/google-chrome/*/Extensions/*/*/manifest.json|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Applications_Chrome_ExtensionsDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Applications_Chrome_ExtensionsDetails" style="width: fit-content">


```
name: Linux.Applications.Chrome.Extensions
description: |
  Fetch Chrome extensions.

  Chrome extensions are installed into the user's home directory.  We
  search for manifest.json files in a known path within each system
  user's home directory. We then parse the manifest file as JSON.

  Many extensions use locale packs to resolve strings like name and
  description. In this case we detect the default locale and load
  those locale files. We then resolve the extension's name and
  description from there.

parameters:
  - name: extensionGlobs
    default: /.config/google-chrome/*/Extensions/*/*/manifest.json
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        /* For each user on the system, search for extension manifests
           in their home directory. */
        LET extension_manifests = SELECT * from foreach(
          row={
             SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Homedir + '/' + extensionGlobs)
          })

      - |
        /* If the Manifest declares a default_locale then we
           load and parse the messages file. In this case the
           messages are actually stored in the locale file
           instead of the main manifest.json file.
        */
        LET maybe_read_locale_file =
           SELECT * from if(
              condition={
                 select * from scope() where Manifest.default_locale
              },
              then={
                 SELECT Manifest,
                        Uid, User,
                        Filename as LocaleFilename,
                        ManifestFilename,
                        parse_json(data=Data) AS LocaleManifest
                 FROM read_file(
                         -- Munge the filename to get the messages.json path.
                         filenames=regex_replace(
                           source=ManifestFilename,
                           replace="/_locales/" + Manifest.default_locale +
                                   "/messages.json",
                           re="/manifest.json$"))
              },
              else={
                  -- Just fill in empty Locale results.
                  SELECT Manifest,
                         Uid, User,
                         "" AS LocaleFilename,
                         "" AS ManifestFilename,
                         "" AS LocaleManifest
                  FROM scope()
              })

      - |
        LET parse_json_files = SELECT * from foreach(
           row={
             SELECT Filename as ManifestFilename,
                    Uid, User,
                    parse_json(data=Data) as Manifest
             FROM read_file(filenames=FullPath)
           },
           query=maybe_read_locale_file)

      - |
        LET parsed_manifest_files = SELECT * from foreach(
          row=extension_manifests,
          query=parse_json_files)

      - |
        SELECT Uid, User,

               /* If the manifest name contains __MSG_ then the real
                  name is stored in the locale manifest. This condition
                  resolves the Name column either to the main manifest or
                  the locale manifest.
               */
               if(condition="__MSG_" in Manifest.name,
                  then=get(item=LocaleManifest,
                     member=regex_replace(
                        source=Manifest.name,
                        replace="$1",
                        re="(?:__MSG_(.+)__)")).message,
                  else=Manifest.name) as Name,

               if(condition="__MSG_" in Manifest.description,
                  then=get(item=LocaleManifest,
                     member=regex_replace(
                        source=Manifest.description,
                        replace="$1",
                        re="(?:__MSG_(.+)__)")).message,
                  else=Manifest.description) as Description,

               /* Get the Identifier and Version from the manifest filename */
               regex_replace(
                 source=ManifestFilename,
                 replace="$1",
                 re="(?:.+Extensions/([^/]+)/([^/]+)/manifest.json)$") AS Identifier,
               regex_replace(
                 source=ManifestFilename,
                 replace="$2",
                 re="(?:.+Extensions/([^/]+)/([^/]+)/manifest.json)$") AS Version,

               Manifest.author as Author,
               Manifest.background.persistent AS Persistent,
               regex_replace(
                 source=ManifestFilename,
                 replace="$1",
                 re="(.+Extensions/.+/)manifest.json$") AS Path,

               Manifest.oauth2.scopes as Scopes,
               Manifest.permissions as Permissions,
               Manifest.key as Key

        FROM parsed_manifest_files
```
   </div></a>

## Linux.Applications.Chrome.Extensions.Upload

Upload all users chrome extension.

We dont bother actually parsing anything here, we just grab all the
extension files in user's home directory.


Arg|Default|Description
---|------|-----------
extensionGlobs|/.config/google-chrome/*/Extensions/**|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Applications_Chrome_Extensions_UploadDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Applications_Chrome_Extensions_UploadDetails" style="width: fit-content">


```
name: Linux.Applications.Chrome.Extensions.Upload
description: |
  Upload all users chrome extension.

  We dont bother actually parsing anything here, we just grab all the
  extension files in user's home directory.

parameters:
  - name: extensionGlobs
    default: /.config/google-chrome/*/Extensions/**
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        /* For each user on the system, search for extension files
           in their home directory and upload them. */
        SELECT * from foreach(
          row={
             SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid,
                    upload(file=FullPath) as Upload
             FROM glob(globs=Homedir + '/' + extensionGlobs)
          })
```
   </div></a>

## Linux.Applications.Docker.Info

Get Dockers info by connecting to its socket.

Arg|Default|Description
---|------|-----------
dockerSocket|/var/run/docker.sock|Docker server socket. You will normally need to be root to connect.\n


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Applications_Docker_InfoDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Applications_Docker_InfoDetails" style="width: fit-content">


```
name: Linux.Applications.Docker.Info
description: Get Dockers info by connecting to its socket.
parameters:
  - name: dockerSocket
    description: |
      Docker server socket. You will normally need to be root to connect.
    default: /var/run/docker.sock
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        LET data = SELECT parse_json(data=Content) as JSON
        FROM http_client(url=dockerSocket + ":unix/info")
      - |
        SELECT JSON.ID as ID,
               JSON.Containers as Containers,
               JSON.ContainersRunning as ContainersRunning,
               JSON.ContainersPaused as ContainersPaused,
               JSON.ContainersStopped as ContainersStopped,
               JSON.Images as Images,
               JSON.Driver as Driver,
               JSON.MemoryLimit as MemoryLimit,
               JSON.SwapLimit as SwapLimit,
               JSON.KernelMemory as KernelMemory,
               JSON.CpuCfsPeriod as CpuCfsPeriod,
               JSON.CpuCfsQuota as CpuCfsQuota,
               JSON.CPUShares as CPUShares,
               JSON.CPUSet as CPUSet,
               JSON.IPv4Forwarding as IPv4Forwarding,
               JSON.BridgeNfIptables as BridgeNfIptables,
               JSON.BridgeNfIp6tables as BridgeNfIp6tables,
               JSON.OomKillDisable as OomKillDisable,
               JSON.LoggingDriver as LoggingDriver,
               JSON.CgroupDriver as CgroupDriver,
               JSON.KernelVersion as KernelVersion,
               JSON.OperatingSystem as OperatingSystem,
               JSON.OSType as OSType,
               JSON.Architecture as Architecture,
               JSON.NCPU as NCPU,
               JSON.MemTotal as MemTotal,
               JSON.HttpProxy as HttpProxy,
               JSON.HttpsProxy as HttpsProxy,
               JSON.NoProxy as NoProxy,
               JSON.Name as Name,
               JSON.ServerVersion as ServerVersion,
               JSON.DockerRootDir as DockerRootDir
        FROM data
```
   </div></a>

## Linux.Applications.Docker.Version

Get Dockers version by connecting to its socket.

Arg|Default|Description
---|------|-----------
dockerSocket|/var/run/docker.sock|Docker server socket. You will normally need to be root to connect.\n


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Applications_Docker_VersionDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Applications_Docker_VersionDetails" style="width: fit-content">


```
name: Linux.Applications.Docker.Version
description: Get Dockers version by connecting to its socket.
parameters:
  - name: dockerSocket
    description: |
      Docker server socket. You will normally need to be root to connect.
    default: /var/run/docker.sock
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        LET data = SELECT parse_json(data=Content) as JSON
        FROM http_client(url=dockerSocket + ":unix/version")
      - |
        SELECT JSON.Version as Version,
               JSON.ApiVersion as ApiVersion,
               JSON.MinAPIVersion as MinAPIVersion,
               JSON.GitCommit as GitCommit,
               JSON.GoVersion as GoVersion,
               JSON.Os as Os,
               JSON.Arch as Arch,
               JSON.KernelVersion as KernelVersion,
               JSON.BuildTime as BuildTime
        FROM data
```
   </div></a>

## Linux.Debian.AptSources

Parse Debian apt sources.

We first search for \*.list files which contain lines of the form

.. code:: console

   deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted

For each line we construct the cache file by spliting off the
section (last component) and replacing / and " " with _.

We then try to open the file. If the file exists we parse some
metadata from it. If not we leave those columns empty.


Arg|Default|Description
---|------|-----------
linuxAptSourcesGlobs|/etc/apt/sources.list,/etc/apt/sources.list.d/*.list|Globs to find apt source *.list files.
aptCacheDirectory|/var/lib/apt/lists/|Location of the apt cache directory.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Debian_AptSourcesDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Debian_AptSourcesDetails" style="width: fit-content">


```
name: Linux.Debian.AptSources
description: |
  Parse Debian apt sources.

  We first search for \*.list files which contain lines of the form

  .. code:: console

     deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted

  For each line we construct the cache file by spliting off the
  section (last component) and replacing / and " " with _.

  We then try to open the file. If the file exists we parse some
  metadata from it. If not we leave those columns empty.

reference:
  - https://osquery.io/schema/3.2.6#apt_sources
parameters:
  - name: linuxAptSourcesGlobs
    description: Globs to find apt source *.list files.
    default: /etc/apt/sources.list,/etc/apt/sources.list.d/*.list
  - name:  aptCacheDirectory
    description: Location of the apt cache directory.
    default: /var/lib/apt/lists/
sources:
  - precondition:
      SELECT OS From info() where OS = 'linux'
    queries:
       - |
         /* Search for files which may contain apt sources. The user can
            pass new globs here. */
         LET files = SELECT FullPath from glob(
           globs=split(string=linuxAptSourcesGlobs, sep=","))

       - |
         /* Read each line in the sources which is not commented.
            Deb lines look like:
            deb [arch=amd64] http://dl.google.com/linux/chrome-remote-desktop/deb/ stable main
            Contains URL, base_uri and components.
         */
         LET deb_sources = SELECT *
           FROM parse_records_with_regex(
             file=files.FullPath,
             regex="(?m)^ *(?P<Type>deb(-src)?) (?:\\[arch=(?P<Arch>[^\\]]+)\\] )?" +
                  "(?P<URL>https?://(?P<base_uri>[^ ]+))" +
                  " +(?P<components>.+)")

       - |
         /* We try to get at the Release file in /var/lib/apt/ by munging
           the components and URL.
           Strip the last component off, convert / and space to _ and
           add _Release to get the filename.
         */
         LET parsed_apt_lines = SELECT Arch, URL,
            base_uri + " " + components as Name, Type,
            FullPath as Source, aptCacheDirectory + regex_replace(
              replace="_",
              re="_+",
              source=regex_replace(
                replace="_", re="[ /]",
                source=base_uri + "_dists_" + regex_replace(
                   source=components,
                   replace="", re=" +[^ ]+$")) + "_Release"
              )  as cache_file
         FROM deb_sources

       - |
         /* This runs if the file was found. Read the entire file into
            memory and parse the same record using multiple RegExps.
         */
         LET parsed_cache_files = SELECT Name, Arch, URL, Type,
           Source, parse_string_with_regex(
                string=Record,
                regex=["Codename: (?P<Release>[^\\s]+)",
                       "Version: (?P<Version>[^\\s]+)",
                       "Origin: (?P<Maintainer>[^\\s]+)",
                       "Architectures: (?P<Architectures>[^\\s]+)",
                       "Components: (?P<Components>[^\\s]+)"]) as Record
           FROM parse_records_with_regex(file=cache_file, regex="(?sm)(?P<Record>.+)")

       - |
         // Foreach row in the parsed cache file, collect the FileInfo too.
         LET add_stat_to_parsed_cache_file = SELECT * from foreach(
           query={
             SELECT FullPath, Mtime, Ctime, Atime, Record, Type,
               Name, Arch, URL, Source from stat(filename=cache_file)
           }, row=parsed_cache_files)

       - |
         /* For each row in the parsed file, run the appropriate query
            depending on if the cache file exists.
            If the cache file is not found, we just copy the lines we
            parsed from the source file and fill in empty values for
            stat.
         */
         LET parse_cache_or_pass = SELECT * from if(
           condition={
              SELECT * from stat(filename=cache_file)
           },
           then=add_stat_to_parsed_cache_file,
           else={
           SELECT Source, Null as Mtime, Null as Ctime,
               Null as Atime, Type,
               Null as Record, Arch, URL, Name from scope()
           })

       - |
         -- For each parsed apt .list file line produce some output.
         SELECT * from foreach(
             row=parsed_apt_lines,
             query=parse_cache_or_pass)
```
   </div></a>

## Linux.Debian.Packages

Parse dpkg status file.

Arg|Default|Description
---|------|-----------
linuxDpkgStatus|/var/lib/dpkg/status|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Debian_PackagesDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Debian_PackagesDetails" style="width: fit-content">


```
name: Linux.Debian.Packages
description: Parse dpkg status file.
parameters:
  - name: linuxDpkgStatus
    default: /var/lib/dpkg/status
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        /* First pass - split file into records start with
           Package and end with \n\n.

           Then parse each record using multiple RegExs.
        */
        LET packages = SELECT parse_string_with_regex(
            string=Record,
            regex=['Package:\\s(?P<Package>.+)',
                   'Installed-Size:\\s(?P<InstalledSize>.+)',
                   'Version:\\s(?P<Version>.+)',
                   'Source:\\s(?P<Source>.+)',
                   'Architecture:\\s(?P<Architecture>.+)']) as Record
            FROM parse_records_with_regex(
                   file=linuxDpkgStatus,
                   regex='(?sm)^(?P<Record>Package:.+?)\\n\\n')
      - |
        SELECT Record.Package as Package,
               atoi(string=Record.InstalledSize) as InstalledSize,
               Record.Version as Version,
               Record.Source as Source,
               Record.Architecture as Architecture from packages
```
   </div></a>

## Linux.Mounts

List mounted filesystems by reading /proc/mounts

Arg|Default|Description
---|------|-----------
ProcMounts|/proc/mounts|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_MountsDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_MountsDetails" style="width: fit-content">


```
name: Linux.Mounts
description: List mounted filesystems by reading /proc/mounts
parameters:
  - name: ProcMounts
    default: /proc/mounts
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        SELECT Device, Mount, FSType, split(string=Opts, sep=",") As Options
               FROM parse_records_with_regex(
                   file=ProcMounts,
                   regex='(?m)^(?P<Device>[^ ]+) (?P<Mount>[^ ]+) (?P<FSType>[^ ]+) '+
                         '(?P<Opts>[^ ]+)')
```
   </div></a>

## Linux.Proc.Arp

ARP table via /proc/net/arp.

Arg|Default|Description
---|------|-----------
ProcNetArp|/proc/net/arp|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Proc_ArpDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Proc_ArpDetails" style="width: fit-content">


```
name: Linux.Proc.Arp
description: ARP table via /proc/net/arp.
parameters:
  - name: ProcNetArp
    default: /proc/net/arp
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'

    queries:
      - |
        SELECT * from split_records(
           filenames=ProcNetArp,
           regex='\\s{3,20}',
           first_row_is_headers=true)
```
   </div></a>

## Linux.Proc.Modules

Module listing via /proc/modules.

Arg|Default|Description
---|------|-----------
ProcModules|/proc/modules|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Proc_ModulesDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Proc_ModulesDetails" style="width: fit-content">


```
name: Linux.Proc.Modules
description: Module listing via /proc/modules.
parameters:
  - name: ProcModules
    default: /proc/modules
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'

    queries:
      - |
        SELECT Name,
          atoi(string=Size) As Size,
          atoi(string=UseCount) As UseCount,
          Status, Address
        FROM split_records(
           filenames=ProcModules,
           regex='\\s+',
           columns=['Name', 'Size', 'UseCount', 'UsedBy', 'Status', 'Address'])
```
   </div></a>

## Linux.Ssh.AuthorizedKeys

Find and parse ssh authorized keys files.

Arg|Default|Description
---|------|-----------
sshKeyFiles|.ssh/authorized_keys*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Ssh_AuthorizedKeysDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Ssh_AuthorizedKeysDetails" style="width: fit-content">


```
name: Linux.Ssh.AuthorizedKeys
description: Find and parse ssh authorized keys files.
parameters:
  - name: sshKeyFiles
    default: '.ssh/authorized_keys*'
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        // For each user on the system, search for authorized_keys files.
        LET authorized_keys = SELECT * from foreach(
          row={
             SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Homedir + '/' + sshKeyFiles)
          })
      - |
        // For each authorized keys file, extract each line on a different row.
        // Note: This duplicates the path, user and uid on each key line.
        SELECT * from foreach(
          row=authorized_keys,
          query={
            SELECT Uid, User, FullPath, Key from split_records(
               filenames=FullPath, regex="\n", columns=["Key"])
          })
```
   </div></a>

## Linux.Ssh.KnownHosts

Find and parse ssh known hosts files.

Arg|Default|Description
---|------|-----------
sshKnownHostsFiles|.ssh/known_hosts*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Ssh_KnownHostsDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Ssh_KnownHostsDetails" style="width: fit-content">


```
name: Linux.Ssh.KnownHosts
description: Find and parse ssh known hosts files.
parameters:
  - name: sshKnownHostsFiles
    default: '.ssh/known_hosts*'
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        // For each user on the system, search for known_hosts files.
        LET authorized_keys = SELECT * from foreach(
          row={
             SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Homedir + '/' + sshKnownHostsFiles)
          })
      - |
        // For each known_hosts file, extract each line on a different row.
        SELECT * from foreach(
          row=authorized_keys,
          query={
            SELECT Uid, User, FullPath, Line from split_records(
               filenames=FullPath, regex="\n", columns=["Line"])
            /* Ignore comment lines. */
            WHERE not Line =~ "^[^#]+#"
          })
```
   </div></a>

## Linux.Sys.ACPITables

Firmware ACPI functional table common metadata and content.

Arg|Default|Description
---|------|-----------
kLinuxACPIPath|/sys/firmware/acpi/tables|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Sys_ACPITablesDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Sys_ACPITablesDetails" style="width: fit-content">


```
name: Linux.Sys.ACPITables
description: Firmware ACPI functional table common metadata and content.
reference:
  - https://osquery.io/schema/3.2.6#acpi_tables
parameters:
  - name: kLinuxACPIPath
    default: /sys/firmware/acpi/tables
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        LET hashes = SELECT Name, Size, hash(path=FullPath) as Hash
                     FROM glob(globs=kLinuxACPIPath + '/*')
      - |
        SELECT Name, Size, Hash.MD5, Hash.SHA1, Hash.SHA256 from hashes
```
   </div></a>

## Linux.Sys.CPUTime

Displays information from /proc/stat file about the time the cpu
cores spent in different parts of the system.


Arg|Default|Description
---|------|-----------
procStat|/proc/stat|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Sys_CPUTimeDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Sys_CPUTimeDetails" style="width: fit-content">


```
name: Linux.Sys.CPUTime
description: |
  Displays information from /proc/stat file about the time the cpu
  cores spent in different parts of the system.
parameters:
  - name: procStat
    default: /proc/stat
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        LET raw = SELECT * FROM split_records(
           filenames=procStat,
           regex=' +',
           columns=['core', 'user', 'nice', 'system',
                    'idle', 'iowait', 'irq', 'softirq',
                    'steal', 'guest', 'guest_nice'])
        WHERE core =~ 'cpu.+'
      - |
        SELECT core AS Core,
               atoi(string=user) as User,
               atoi(string=nice) as Nice,
               atoi(string=system) as System,
               atoi(string=idle) as Idle,
               atoi(string=iowait) as IOWait,
               atoi(string=irq) as IRQ,
               atoi(string=softirq) as SoftIRQ,
               atoi(string=steal) as Steal,
               atoi(string=guest) as Guest,
               atoi(string=guest_nice) as GuestNice FROM raw
```
   </div></a>

## Linux.Sys.Crontab

Displays parsed information from crontab.


Arg|Default|Description
---|------|-----------
cronTabGlob|/etc/crontab,/etc/cron.d/**,/var/at/tabs/**,/var/spool/cron/**,/var/spool/cron/crontabs/**|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Sys_CrontabDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Sys_CrontabDetails" style="width: fit-content">


```
name: Linux.Sys.Crontab
description: |
  Displays parsed information from crontab.
parameters:
  - name: cronTabGlob
    default: /etc/crontab,/etc/cron.d/**,/var/at/tabs/**,/var/spool/cron/**,/var/spool/cron/crontabs/**
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        LET raw = SELECT * FROM foreach(
          row={
            SELECT FullPath from glob(globs=split(string=cronTabGlob, sep=","))
          },
          query={
            SELECT FullPath, data, parse_string_with_regex(
              string=data,
              regex=[
                 /* Regex for event (Starts with @) */
                 "^(?P<Event>@[a-zA-Z]+)\\s+(?P<Command>.+)",

                 /* Regex for regular command. */
                 "^(?P<Minute>[^\\s]+)\\s+"+
                 "(?P<Hour>[^\\s]+)\\s+"+
                 "(?P<DayOfMonth>[^\\s]+)\\s+"+
                 "(?P<Month>[^\\s]+)\\s+"+
                 "(?P<DayOfWeek>[^\\s]+)\\s+"+
                 "(?P<Command>.+)$"]) as Record

            /* Read lines from the file and filter ones that start with "#" */
            FROM split_records(
               filenames=FullPath,
               regex="\n", columns=["data"]) WHERE not data =~ "^\\s*#"
            }) WHERE Record.Command

      - |
        SELECT Record.Event AS Event,
               Record.Minute AS Minute,
               Record.Hour AS Hour,
               Record.DayOfMonth AS DayOfMonth,
               Record.Month AS Month,
               Record.DayOfWeek AS DayOfWeek,
               Record.Command AS Command,
               FullPath AS Path
        FROM raw
```
   </div></a>

## Linux.Sys.LastUserLogin

Find and parse system wtmp files. This indicate when the user last logged in.

Arg|Default|Description
---|------|-----------
wtmpGlobs|/var/log/wtmp*|
wtmpProfile|{\n  "timeval": [8, {\n   "tv_sec": [0, ["int"]],\n   "tv_usec": [4, ["int"]]\n  }],\n  "exit_status": [4, {\n   "e_exit": [2, ["short int"]],\n   "e_termination": [0, ["short int"]]\n  }],\n  "timezone": [8, {\n   "tz_dsttime": [4, ["int"]],\n   "tz_minuteswest": [0, ["int"]]\n  }],\n  "utmp": [384, {\n   "__glibc_reserved": [364, ["Array", {\n    "count": 20,\n    "target": "char",\n    "target_args": null\n   }]],\n   "ut_addr_v6": [348, ["Array", {\n    "count": 4,\n    "target": "int",\n    "target_args": null\n   }]],\n   "ut_exit": [332, ["exit_status"]],\n   "ut_host": [76, ["String", {\n    "length": 256\n   }]],\n   "ut_id": [40, ["String", {\n    "length": 4\n   }]],\n   "ut_line": [8, ["String", {\n    "length": 32\n   }]],\n   "ut_pid": [4, ["int"]],\n   "ut_session": [336, ["int"]],\n   "ut_tv": [340, ["timeval"]],\n   "ut_type": [0, ["Enumeration", {\n     "target": "short int",\n     "choices": {\n        "0": "EMPTY",\n        "1": "RUN_LVL",\n        "2": "BOOT_TIME",\n        "5": "INIT_PROCESS",\n        "6": "LOGIN_PROCESS",\n        "7": "USER_PROCESS",\n        "8": "DEAD_PROCESS"\n      }\n   }]],\n   "ut_user": [44, ["String", {\n    "length": 32\n   }]]\n  }]\n}\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Sys_LastUserLoginDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Sys_LastUserLoginDetails" style="width: fit-content">


```
name: Linux.Sys.LastUserLogin
description: Find and parse system wtmp files. This indicate when the
             user last logged in.
parameters:
  - name: wtmpGlobs
    default: /var/log/wtmp*

    # This is automatically generated from dwarf symbols by Rekall:
    # gcc -c -g -o /tmp/test.o /tmp/1.c
    # rekall dwarfparser /tmp/test.o

    # And 1.c is:
    # #include "utmp.h"
    # struct utmp x;

  - name: wtmpProfile
    default: |
       {
         "timeval": [8, {
          "tv_sec": [0, ["int"]],
          "tv_usec": [4, ["int"]]
         }],
         "exit_status": [4, {
          "e_exit": [2, ["short int"]],
          "e_termination": [0, ["short int"]]
         }],
         "timezone": [8, {
          "tz_dsttime": [4, ["int"]],
          "tz_minuteswest": [0, ["int"]]
         }],
         "utmp": [384, {
          "__glibc_reserved": [364, ["Array", {
           "count": 20,
           "target": "char",
           "target_args": null
          }]],
          "ut_addr_v6": [348, ["Array", {
           "count": 4,
           "target": "int",
           "target_args": null
          }]],
          "ut_exit": [332, ["exit_status"]],
          "ut_host": [76, ["String", {
           "length": 256
          }]],
          "ut_id": [40, ["String", {
           "length": 4
          }]],
          "ut_line": [8, ["String", {
           "length": 32
          }]],
          "ut_pid": [4, ["int"]],
          "ut_session": [336, ["int"]],
          "ut_tv": [340, ["timeval"]],
          "ut_type": [0, ["Enumeration", {
            "target": "short int",
            "choices": {
               "0": "EMPTY",
               "1": "RUN_LVL",
               "2": "BOOT_TIME",
               "5": "INIT_PROCESS",
               "6": "LOGIN_PROCESS",
               "7": "USER_PROCESS",
               "8": "DEAD_PROCESS"
             }
          }]],
          "ut_user": [44, ["String", {
           "length": 32
          }]]
         }]
       }

sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        SELECT * from foreach(
          row={
            SELECT FullPath from glob(globs=split(string=wtmpGlobs, sep=","))
          },
          query={
            SELECT ut_type, ut_id, ut_host.AsString as Host,
                   ut_user.AsString as User,
                   timestamp(epoch=ut_tv.tv_sec.AsInteger) as login_time
            FROM binary_parse(
                   file=FullPath,
                   profile=wtmpProfile,
                   target="Array",
                   args=dict(Target="utmp")
                 )
          })
```
   </div></a>

## Linux.Sys.Users

Get User specific information like homedir, group etc from /etc/passwd.

Arg|Default|Description
---|------|-----------
PasswordFile|/etc/passwd|The location of the password file.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Linux_Sys_UsersDetails">View Artifact</a>
 <div class="collapse dn" id="Linux_Sys_UsersDetails" style="width: fit-content">


```
name: Linux.Sys.Users
description: Get User specific information like homedir, group etc from /etc/passwd.
parameters:
  - name: PasswordFile
    default: /etc/passwd
    description: The location of the password file.
sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'
    queries:
      - |
        SELECT User, Description, Uid, Gid, Homedir, Shell
          FROM parse_records_with_regex(
            file=PasswordFile,
            regex='(?m)^(?P<User>[^:]+):([^:]+):' +
                  '(?P<Uid>[^:]+):(?P<Gid>[^:]+):(?P<Description>[^:]*):' +
                  '(?P<Homedir>[^:]+):(?P<Shell>[^:\\s]+)')
```
   </div></a>

