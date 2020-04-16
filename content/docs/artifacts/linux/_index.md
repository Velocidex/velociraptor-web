---
description: Linux Artifacts
linktitle: Linux Artifacts
title: Linux Artifacts
weight: 10

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
extensionGlobs|/.config/google-chrome/*/Extensions/*/*/manifest.j ...|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Applications.Chrome.Extensions.Upload

Upload all users chrome extension.

We dont bother actually parsing anything here, we just grab all the
extension files in user's home directory.


Arg|Default|Description
---|------|-----------
extensionGlobs|/.config/google-chrome/*/Extensions/**|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Applications.Docker.Info

Get Dockers info by connecting to its socket.

Arg|Default|Description
---|------|-----------
dockerSocket|/var/run/docker.sock|Docker server socket. You will normally need to be root to connect.\n

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Applications.Docker.Version

Get Dockers version by connecting to its socket.

Arg|Default|Description
---|------|-----------
dockerSocket|/var/run/docker.sock|Docker server socket. You will normally need to be root to connect.\n

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

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
linuxAptSourcesGlobs|/etc/apt/sources.list,/etc/apt/sources.list.d/*.li ...|Globs to find apt source *.list files.
aptCacheDirectory|/var/lib/apt/lists/|Location of the apt cache directory.

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Debian.Packages

Parse dpkg status file.

Arg|Default|Description
---|------|-----------
linuxDpkgStatus|/var/lib/dpkg/status|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Events.ProcessExecutions

This artifact collects process execution logs from the Linux kernel.

This artifact relies on the presence of `auditctl` usually included
in the auditd package. On Ubuntu you can install it using:

```
apt-get install auditd
```


Arg|Default|Description
---|------|-----------
pathToAuditctl|/sbin/auditctl|We depend on auditctl to install the correct process execution rules.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Events.ProcessExecutions
description: |
  This artifact collects process execution logs from the Linux kernel.

  This artifact relies on the presence of `auditctl` usually included
  in the auditd package. On Ubuntu you can install it using:

  ```
  apt-get install auditd
  ```

precondition: SELECT OS From info() where OS = 'linux'

type: CLIENT_EVENT

parameters:
  - name: pathToAuditctl
    default: /sbin/auditctl
    description: We depend on auditctl to install the correct process execution rules.

sources:
  - queries:
     # Install the auditd rule if possible.
     - LET _ <= SELECT * FROM execve(argv=[pathToAuditctl, "-a",
          "exit,always", "-F", "arch=b64", "-S", "execve", "-k", "procmon"])

     - LET exec_log = SELECT timestamp(string=Timestamp) AS Time, Sequence,
           atoi(string=Process.PID) AS Pid,
           atoi(string=Process.PPID) AS Ppid,
           Process.PPID AS PPID,
           atoi(string=Summary.Actor.Primary) AS UserId,
           Process.Title AS CmdLine,
           Process.Exe AS Exe,
           Process.CWD AS CWD
       FROM audit()
       WHERE "procmon" in Tags AND Result = 'success'

     # Cache Uid -> Username mapping.
     - LET users <= SELECT User, atoi(string=Uid) AS Uid
       FROM Artifact.Linux.Sys.Users()

     # Enrich the original artifact with more data.
     - SELECT Time, Pid, Ppid, UserId,
              { SELECT User from users WHERE Uid = UserId} AS User,
              regex_replace(source=read_file(filename= "/proc/" + PPID + "/cmdline"),
                            replace=" ", re="[\\0]") AS Parent,
              CmdLine,
              Exe, CWD
       FROM exec_log
```
   {{% /expand %}}

## Linux.Events.SSHBruteforce

This is a monitoring artifact which detects a successful SSH login
preceeded by some failed attempts within the last hour.

This is particularly important in the case of ssh brute forcers. If
one of the brute force password attempts succeeded the password
guessing program will likely report the success and move on. This
alert might provide sufficient time for admins to lock down the
account before attackers can exploit the weak password.


Arg|Default|Description
---|------|-----------
syslogAuthLogPath|/var/log/auth.log|
SSHGrok|%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY}  ...|A Grok expression for parsing SSH auth lines.
MinimumFailedLogins|2|Minimum number of failed logins before a successful login.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Events.SSHBruteforce
description: |
  This is a monitoring artifact which detects a successful SSH login
  preceeded by some failed attempts within the last hour.

  This is particularly important in the case of ssh brute forcers. If
  one of the brute force password attempts succeeded the password
  guessing program will likely report the success and move on. This
  alert might provide sufficient time for admins to lock down the
  account before attackers can exploit the weak password.

reference:
  - https://www.elastic.co/blog/grokking-the-linux-authorization-logs

type: CLIENT_EVENT

parameters:
  - name: syslogAuthLogPath
    default: /var/log/auth.log

  - name: SSHGrok
    description: A Grok expression for parsing SSH auth lines.
    default: >-
      %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}: %{DATA:event} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:system.auth.ssh.signature})?

  - name: MinimumFailedLogins
    description: Minimum number of failed logins before a successful login.
    default: 2

sources:
  - queries:
      # Basic syslog parsing via GROK expressions.
      - LET failed_login = SELECT grok(grok=SSHGrok, data=Line) AS FailedEvent,
            Line as FailedLine
        FROM watch_syslog(filename=syslogAuthLogPath)
        WHERE FailedEvent.program = "sshd" AND FailedEvent.event = "Failed"
              AND FailedEvent.method = "password"

      - LET last_failed_events = SELECT * FROM fifo(
              query=failed_login, max_rows=50, max_age=3600)

      - LET _ <= SELECT * FROM last_failed_events

      - LET success_login = SELECT grok(grok=SSHGrok, data=Line) AS Event, Line
        FROM watch_syslog(filename=syslogAuthLogPath)
        WHERE Event.program = "sshd" AND Event.event = "Accepted"
              AND Event.method = "password"

      - SELECT Event, Line, {
           SELECT FailedLine FROM last_failed_events
           WHERE Event.user = FailedEvent.user
        } AS Failures
        FROM success_login
        WHERE len(list=Failures) > int(int=MinimumFailedLogins)
```
   {{% /expand %}}

## Linux.Events.SSHLogin

This monitoring artifact watches the auth.log file for new
successful SSH login events and relays them back to the server.


Arg|Default|Description
---|------|-----------
syslogAuthLogPath|/var/log/auth.log|
SSHGrok|%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY}  ...|A Grok expression for parsing SSH auth lines.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Events.SSHLogin
description: |
  This monitoring artifact watches the auth.log file for new
  successful SSH login events and relays them back to the server.

reference:
  - https://www.elastic.co/blog/grokking-the-linux-authorization-logs

type: CLIENT_EVENT

parameters:
  - name: syslogAuthLogPath
    default: /var/log/auth.log

  - name: SSHGrok
    description: A Grok expression for parsing SSH auth lines.
    default: >-
      %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}: %{DATA:event} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:system.auth.ssh.signature})?

sources:
  - queries:
      # Basic syslog parsing via GROK expressions.
      - LET success_login = SELECT grok(grok=SSHGrok, data=Line) AS Event, Line
        FROM watch_syslog(filename=syslogAuthLogPath)
        WHERE Event.program = "sshd" AND Event.event = "Accepted"
      - SELECT timestamp(string=Event.timestamp) AS Time,
              Event.user AS User,
              Event.method AS Method,
              Event.IP AS SourceIP,
              Event.pid AS Pid
        FROM success_login
```
   {{% /expand %}}

## Linux.Mounts

List mounted filesystems by reading /proc/mounts

Arg|Default|Description
---|------|-----------
ProcMounts|/proc/mounts|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Proc.Arp

ARP table via /proc/net/arp.

Arg|Default|Description
---|------|-----------
ProcNetArp|/proc/net/arp|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Proc.Modules

Module listing via /proc/modules.

Arg|Default|Description
---|------|-----------
ProcModules|/proc/modules|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Search.FileFinder

Find files on the filesystem using the filename or content.


## Performance Note

This artifact can be quite expensive, especially if we search file
content. It will require opening each file and reading its entire
content. To minimize the impact on the endpoint we recommend this
artifact is collected with a rate limited way (about 20-50 ops per
second).

This artifact is useful in the following scenarios:

  * We need to locate all the places on our network where customer
    data has been copied.

  * We’ve identified malware in a data breach, named using short
    random strings in specific folders and need to search for other
    instances across the network.

  * We believe our user account credentials have been dumped and
    need to locate them.

  * We need to search for exposed credit card data to satisfy PCI
    requirements.

  * We have a sample of data that has been disclosed and need to
    locate other similar files


Arg|Default|Description
---|------|-----------
SearchFilesGlob|/home/*/**|Use a glob to define the files that will be searched.
Keywords|None|A comma delimited list of strings to search for.
Upload_File|N|
Calculate_Hash|N|
MoreRecentThan||
ModifiedBefore||

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Search.FileFinder
description: |
  Find files on the filesystem using the filename or content.


  ## Performance Note

  This artifact can be quite expensive, especially if we search file
  content. It will require opening each file and reading its entire
  content. To minimize the impact on the endpoint we recommend this
  artifact is collected with a rate limited way (about 20-50 ops per
  second).

  This artifact is useful in the following scenarios:

    * We need to locate all the places on our network where customer
      data has been copied.

    * We’ve identified malware in a data breach, named using short
      random strings in specific folders and need to search for other
      instances across the network.

    * We believe our user account credentials have been dumped and
      need to locate them.

    * We need to search for exposed credit card data to satisfy PCI
      requirements.

    * We have a sample of data that has been disclosed and need to
      locate other similar files


precondition:
  SELECT * FROM info() where OS = 'linux'

parameters:
  - name: SearchFilesGlob
    default: /home/*/**
    description: Use a glob to define the files that will be searched.

  - name: Keywords
    default:
    description: A comma delimited list of strings to search for.

  - name: Upload_File
    default: N
    type: bool

  - name: Calculate_Hash
    default: N
    type: bool

  - name: MoreRecentThan
    default: ""
    type: timestamp

  - name: ModifiedBefore
    default: ""
    type: timestamp


sources:
  - queries:
    - LET file_search = SELECT FullPath,
               Sys.mft as Inode,
               Mode.String AS Mode, Size,
               Mtime.Sec AS Modified,
               timestamp(epoch=Atime.Sec) AS ATime,
               timestamp(epoch=Mtime.Sec) AS MTime,
               timestamp(epoch=Ctime.Sec) AS CTime, IsDir
        FROM glob(globs=SearchFilesGlob,
                  accessor="file")

    - LET more_recent = SELECT * FROM if(
        condition=MoreRecentThan,
        then={
          SELECT * FROM file_search
          WHERE Modified > parse_float(string=MoreRecentThan)
        }, else=file_search)

    - LET modified_before = SELECT * FROM if(
        condition=ModifiedBefore,
        then={
          SELECT * FROM more_recent
          WHERE Modified < parse_float(string=ModifiedBefore)
        }, else=more_recent)

    - LET keyword_search = SELECT * FROM if(
        condition=Keywords,
        then={
          SELECT * FROM foreach(
            row={
               SELECT * FROM modified_before
            },
            query={
               SELECT FullPath, Inode, Mode,
                      Size, Modified, ATime, MTime, CTime,
                      str(str=String.Data) As Keywords

               FROM yara(files=FullPath,
                         key=Keywords,
                         rules="wide nocase ascii:"+Keywords,
                         accessor="file")
            })
        }, else=modified_before)

    - SELECT FullPath, Inode, Mode, Size, Modified, ATime,
             MTime, CTime, Keywords,
               if(condition=(Upload_File = "Y" and NOT IsDir ),
                  then=upload(file=FullPath,
                              accessor="file")) AS Upload,
               if(condition=(Calculate_Hash = "Y" and NOT IsDir ),
                  then=hash(path=FullPath,
                            accessor="file")) AS Hash
      FROM keyword_search
```
   {{% /expand %}}

## Linux.Ssh.AuthorizedKeys

Find and parse ssh authorized keys files.

Arg|Default|Description
---|------|-----------
sshKeyFiles|.ssh/authorized_keys*|Glob of authorized_keys file relative to a user's home directory.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Ssh.AuthorizedKeys
description: Find and parse ssh authorized keys files.
parameters:
  - name: sshKeyFiles
    default: '.ssh/authorized_keys*'
    description: Glob of authorized_keys file relative to a user's home directory.

sources:
  - precondition: |
      SELECT OS From info() where OS = 'linux'

    queries:
      - LET authorized_keys = SELECT * from foreach(
          row={
             SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Homedir + '/' + sshKeyFiles)
          })

      - SELECT * from foreach(
          row=authorized_keys,
          query={
            SELECT Uid, User, FullPath, Key, Comment,
                   timestamp(epoch=Mtime.sec) AS Mtime
            FROM split_records(
               filenames=FullPath, regex=" +", columns=["Type", "Key", "Comment"])
               WHERE Type =~ "ssh"
          })
```
   {{% /expand %}}

## Linux.Ssh.KnownHosts

Find and parse ssh known hosts files.

Arg|Default|Description
---|------|-----------
sshKnownHostsFiles|.ssh/known_hosts*|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Ssh.PrivateKeys

SSH Private keys can be either encrypted or unencrypted. Unencrypted
private keys are more risky because an attacker can use them without
needing to unlock them with a password.

This artifact searches for private keys in the usual locations and
also records if they are encrypted or not.

## references
- https://attack.mitre.org/techniques/T1145/


Arg|Default|Description
---|------|-----------
KeyGlobs|/home/*/.ssh/id_{rsa,dsa}|

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Ssh.PrivateKeys
description: |
  SSH Private keys can be either encrypted or unencrypted. Unencrypted
  private keys are more risky because an attacker can use them without
  needing to unlock them with a password.

  This artifact searches for private keys in the usual locations and
  also records if they are encrypted or not.

  ## references
  - https://attack.mitre.org/techniques/T1145/

precondition: SELECT OS From info() where OS = 'linux'

parameters:
  - name: KeyGlobs
    default: /home/*/.ssh/id_{rsa,dsa}

sources:
  - queries:
      - SELECT FullPath,
               timestamp(epoch=Mtime.Sec) AS Mtime,
               if(condition={
                     SELECT * from yara(rules="wide ascii:ENCRYPTED", files=FullPath)
                  }, then="Yes", else="No") AS Encrypted
        FROM glob(globs=KeyGlobs)
```
   {{% /expand %}}

## Linux.Sys.ACPITables

Firmware ACPI functional table common metadata and content.

Arg|Default|Description
---|------|-----------
kLinuxACPIPath|/sys/firmware/acpi/tables|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Sys.BashShell

This artifact allows running arbitrary commands through the system
shell.

Since Velociraptor typically runs as root, the commands will also
run as root.

This is a very powerful artifact since it allows for arbitrary
command execution on the endpoints. Therefore this artifact requires
elevated permissions (specifically the `EXECVE`
permission). Typically it is only available with the `administrator`
role.


Arg|Default|Description
---|------|-----------
Command|ls -l /|

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Sys.BashShell
description: |
  This artifact allows running arbitrary commands through the system
  shell.

  Since Velociraptor typically runs as root, the commands will also
  run as root.

  This is a very powerful artifact since it allows for arbitrary
  command execution on the endpoints. Therefore this artifact requires
  elevated permissions (specifically the `EXECVE`
  permission). Typically it is only available with the `administrator`
  role.

required_permissions:
  - EXECVE

parameters:
  - name: Command
    default: "ls -l /"

sources:
  - query: |
      SELECT * FROM execve(argv=["/bin/bash", "-c", Command])
```
   {{% /expand %}}

## Linux.Sys.CPUTime

Displays information from /proc/stat file about the time the cpu
cores spent in different parts of the system.


Arg|Default|Description
---|------|-----------
procStat|/proc/stat|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Sys.Crontab

Displays parsed information from crontab.


Arg|Default|Description
---|------|-----------
cronTabGlob|/etc/crontab,/etc/cron.d/**,/var/at/tabs/**,/var/s ...|
cronTabScripts|/etc/cron.daily/*,/etc/cron.hourly/*,/etc/cron.mon ...|

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Sys.Crontab
description: |
  Displays parsed information from crontab.
parameters:
  - name: cronTabGlob
    default: /etc/crontab,/etc/cron.d/**,/var/at/tabs/**,/var/spool/cron/**,/var/spool/cron/crontabs/**
  - name: cronTabScripts
    default: /etc/cron.daily/*,/etc/cron.hourly/*,/etc/cron.monthly/*,/etc/cron.weekly/*

precondition: SELECT OS From info() where OS = 'linux'

sources:
  - name: CronTabs
    queries:
      - LET raw = SELECT * FROM foreach(
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
                 "(?P<User>[^\\s]+)\\s+"+
                 "(?P<Command>.+)$"]) as Record

            /* Read lines from the file and filter ones that start with "#" */
            FROM split_records(
               filenames=FullPath,
               regex="\n", columns=["data"]) WHERE not data =~ "^\\s*#"
            }) WHERE Record.Command

      - SELECT Record.Event AS Event,
               Record.User AS User,
               Record.Minute AS Minute,
               Record.Hour AS Hour,
               Record.DayOfMonth AS DayOfMonth,
               Record.Month AS Month,
               Record.DayOfWeek AS DayOfWeek,
               Record.Command AS Command,
               FullPath AS Path
        FROM raw

  - name: Uploaded
    queries:
      - SELECT FullPath, upload(filename=FullPath) AS Upload
        FROM glob(globs=split(string=cronTabGlob + "," + cronTabScripts, sep=","))
```
   {{% /expand %}}

## Linux.Sys.LastUserLogin

Find and parse system wtmp files. This indicate when the user last logged in.

Arg|Default|Description
---|------|-----------
wtmpGlobs|/var/log/wtmp*|
wtmpProfile|{\n  "timeval": [8, {\n   "tv_sec": [0, ["int"]],\ ...|

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Sys.Maps

A running binary may link other binaries into its address
space. These shared objects contain exported functions which may be
used by the binary.

This artifact parses the /proc/<pid>/maps to emit all mapped files
into the process.


Arg|Default|Description
---|------|-----------
processRegex|.|A regex applied to process names.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Sys.Maps
description: |
  A running binary may link other binaries into its address
  space. These shared objects contain exported functions which may be
  used by the binary.

  This artifact parses the /proc/<pid>/maps to emit all mapped files
  into the process.

precondition: SELECT OS From info() where OS = 'linux'

parameters:
  - name: processRegex
    description: A regex applied to process names.
    default: .

sources:
  - queries:
      - LET processes = SELECT Pid, Name, Username
        FROM pslist()
        WHERE Name =~ processRegex
      - SELECT Pid, Name, Username,
               "0x" + Record.Start AS StartHex,
               "0x" + Record.End AS EndHex,
               Record.Perm AS Perm,
               atoi(string="0x" + Record.Size) AS Size,
               "0x" + Record.Size AS SizeHex,
               Record.Filename AS Filename,
               if(condition=Record.Deleted, then=TRUE, else=FALSE) AS Deleted
        FROM foreach(
          row=processes,
          query={
            SELECT parse_string_with_regex(
                    string=Line,
                    regex="(?P<Start>^[^-]+)-(?P<End>[^\\s]+)\\s+(?P<Perm>[^\\s]+)\\s+(?P<Size>[^\\s]+)\\s+[^\\s]+\\s+(?P<PermInt>[^\\s]+)\\s+(?P<Filename>.+?)(?P<Deleted> \\(deleted\\))?$") AS Record,
                  Pid, Name, Username
            FROM parse_lines(
               filename=format(format="/proc/%d/maps", args=[Pid]),
               accessor='file'
            )
          })
```
   {{% /expand %}}

## Linux.Sys.SUID

When the setuid or setgid bits are set on Linux or macOS for an
application, this means that the application will run with the
privileges of the owning user or group respectively [1]. Normally an
application is run in the current user’s context, regardless of
which user or group owns the application. There are instances where
programs need to be executed in an elevated context to function
properly, but the user running them doesn’t need the elevated
privileges. Instead of creating an entry in the sudoers file, which
must be done by root, any user can specify the setuid or setgid flag
to be set for their own applications. These bits are indicated with
an "s" instead of an "x" when viewing a file's attributes via ls
-l. The chmod program can set these bits with via bitmasking, chmod
4777 [file] or via shorthand naming, chmod u+s [file].

An adversary can take advantage of this to either do a shell escape
or exploit a vulnerability in an application with the setsuid or
setgid bits to get code running in a different user’s
context. Additionally, adversaries can use this mechanism on their
own malware to make sure they're able to execute in elevated
contexts in the future [2].

## References:
- https://attack.mitre.org/techniques/T1166/


Arg|Default|Description
---|------|-----------
GlobExpression|/usr/**|

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Sys.SUID
description: |
  When the setuid or setgid bits are set on Linux or macOS for an
  application, this means that the application will run with the
  privileges of the owning user or group respectively [1]. Normally an
  application is run in the current user’s context, regardless of
  which user or group owns the application. There are instances where
  programs need to be executed in an elevated context to function
  properly, but the user running them doesn’t need the elevated
  privileges. Instead of creating an entry in the sudoers file, which
  must be done by root, any user can specify the setuid or setgid flag
  to be set for their own applications. These bits are indicated with
  an "s" instead of an "x" when viewing a file's attributes via ls
  -l. The chmod program can set these bits with via bitmasking, chmod
  4777 [file] or via shorthand naming, chmod u+s [file].

  An adversary can take advantage of this to either do a shell escape
  or exploit a vulnerability in an application with the setsuid or
  setgid bits to get code running in a different user’s
  context. Additionally, adversaries can use this mechanism on their
  own malware to make sure they're able to execute in elevated
  contexts in the future [2].

  ## References:
  - https://attack.mitre.org/techniques/T1166/

parameters:
  - name: GlobExpression
    default: /usr/**

sources:
  - queries:
      - SELECT Mode.String AS Mode,
               FullPath, Size,
               timestamp(epoch=Mtime.Sec) AS Mtime,
               Sys.Uid AS OwnerID,
               Sys.Gid AS GroupID
        FROM glob(globs=GlobExpression) WHERE Mode =~ '^u'
```
   {{% /expand %}}

## Linux.Sys.Users

Get User specific information like homedir, group etc from /etc/passwd.

Arg|Default|Description
---|------|-----------
PasswordFile|/etc/passwd|The location of the password file.

{{% expand  "View Artifact Source" %}}


```text
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
   {{% /expand %}}

## Linux.Syslog.SSHLogin

Parses the auth logs to determine all SSH login attempts.


Arg|Default|Description
---|------|-----------
syslogAuthLogPath|/var/log/auth.log*|
SSHGrok|%{SYSLOGTIMESTAMP:Timestamp} (?:%{SYSLOGFACILITY}  ...|A Grok expression for parsing SSH auth lines.

{{% expand  "View Artifact Source" %}}


```text
name: Linux.Syslog.SSHLogin
description: |
  Parses the auth logs to determine all SSH login attempts.

reference:
  - https://www.elastic.co/blog/grokking-the-linux-authorization-logs

type: CLIENT

parameters:
  - name: syslogAuthLogPath
    default: /var/log/auth.log*

  - name: SSHGrok
    description: A Grok expression for parsing SSH auth lines.
    default: >-
      %{SYSLOGTIMESTAMP:Timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}: %{DATA:event} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:system.auth.ssh.signature})?

sources:
  - queries:
      # Basic syslog parsing via GROK expressions.
      - SELECT timestamp(string=Event.Timestamp) AS Time,
               Event.IP AS IP,
               Event.event AS Result,
               Event.method AS Method,
               Event.user AS AttemptedUser,
               FullPath
        FROM foreach(
          row={
              SELECT FullPath FROM glob(globs=syslogAuthLogPath)
          }, query={
              SELECT grok(grok=SSHGrok, data=Line) AS Event, FullPath
              FROM parse_lines(filename=FullPath)
              WHERE Event.program = "sshd"
          })
```
   {{% /expand %}}

