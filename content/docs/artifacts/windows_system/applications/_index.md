---
description: These artifacts collect information related to the windows applications.
linktitle: Applications
title: Applications
weight: 50

---
## Windows.Applications.ChocolateyPackages

Chocolatey packages installed in a system.

Arg|Default|Description
---|------|-----------
ChocolateyInstall||

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Applications.ChocolateyPackages
description: Chocolatey packages installed in a system.
parameters:
  - name: ChocolateyInstall
    default: ""

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - LET files = SELECT FullPath,
              parse_xml(file=FullPath) AS Metadata
              -- Use the ChocolateyInstall parameter if it is set.

          FROM glob(globs=if(
             condition=ChocolateyInstall,
             then=ChocolateyInstall,

             -- Otherwise just use the environment.
             else=environ(var='ChocolateyInstall')) + '/lib/*/*.nuspec')

      - SELECT * FROM if(
        condition=if(condition=ChocolateyInstall,
                     then=ChocolateyInstall,
                     else=environ(var="ChocolateyInstall")),
        then={
            SELECT FullPath,
                   Metadata.package.metadata.id as Name,
                   Metadata.package.metadata.version as Version,
                   Metadata.package.metadata.summary as Summary,
                   Metadata.package.metadata.authors as Authors,
                   Metadata.package.metadata.licenseUrl as License
            FROM files
        })
```
   {{% /expand %}}

## Windows.Applications.Chrome.Cookies

Enumerate the users chrome cookies.

The cookies are typically encrypted by the DPAPI using the user's
credentials. Since Velociraptor is typically not running in the user
context we can not decrypt these. It may be possible to decrypt the
cookies off line.

The pertinant information from a forensic point of view is the
user's Created and LastAccess timestamp and the fact that the user
has actually visited the site and obtained a cookie.


Arg|Default|Description
---|------|-----------
cookieGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Co ...|
cookieSQLQuery|SELECT creation_utc, host_key, name, value, path,  ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Applications.Chrome.Cookies
description: |
  Enumerate the users chrome cookies.

  The cookies are typically encrypted by the DPAPI using the user's
  credentials. Since Velociraptor is typically not running in the user
  context we can not decrypt these. It may be possible to decrypt the
  cookies off line.

  The pertinant information from a forensic point of view is the
  user's Created and LastAccess timestamp and the fact that the user
  has actually visited the site and obtained a cookie.

parameters:
  - name: cookieGlobs
    default: \AppData\Local\Google\Chrome\User Data\*\Cookies
  - name: cookieSQLQuery
    default: |
      SELECT creation_utc, host_key, name, value, path, expires_utc,
             last_access_utc, encrypted_value
      FROM cookies
  - name: userRegex
    default: .

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        LET cookie_files = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
          },
          query={
             SELECT User, FullPath, Mtime from glob(
               globs=Directory + cookieGlobs)
          })

      - |
        SELECT * FROM foreach(row=cookie_files,
          query={
            SELECT timestamp(winfiletime=creation_utc * 10) as Created,
                   timestamp(winfiletime=last_access_utc * 10) as LastAccess,
                   timestamp(winfiletime=expires_utc * 10) as Expires,
                   host_key, name, path, value,
                   base64encode(string=encrypted_value) as EncryptedValue
            FROM sqlite(
              file=FullPath,
              query=cookieSQLQuery)
          })
```
   {{% /expand %}}

## Windows.Applications.Chrome.Extensions

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
extensionGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Ex ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Applications.Chrome.Extensions
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
    default: \AppData\Local\Google\Chrome\User Data\*\Extensions\*\*\manifest.json
  - name: userRegex
    default: .

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        /* For each user on the system, search for extension manifests
           in their home directory. */
        LET extension_manifests = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Directory + extensionGlobs)
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
                           replace="\\_locales\\" + Manifest.default_locale +
                                   "\\messages.json",
                           re="\\\\manifest.json$"))
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
                 re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Identifier,
               regex_replace(
                 source=ManifestFilename,
                 replace="$2",
                 re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Version,

               Manifest.author as Author,
               Manifest.background.persistent AS Persistent,
               regex_replace(
                 source=ManifestFilename,
                 replace="$1",
                 re="(.+Extensions\\\\.+\\\\)manifest.json$") AS Path,

               Manifest.oauth2.scopes as Scopes,
               Manifest.permissions as Permissions,
               Manifest.key as Key

        FROM parsed_manifest_files
```
   {{% /expand %}}

## Windows.Applications.Chrome.History

Enumerate the users chrome history.


Arg|Default|Description
---|------|-----------
historyGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Hi ...|
urlSQLQuery|SELECT url as visited_url, title, visit_count,\n   ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Applications.Chrome.History
description: |
  Enumerate the users chrome history.

parameters:
  - name: historyGlobs
    default: \AppData\Local\Google\Chrome\User Data\*\History
  - name: urlSQLQuery
    default: |
      SELECT url as visited_url, title, visit_count,
             typed_count, last_visit_time
      FROM urls
  - name: userRegex
    default: .

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        LET history_files = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
          },
          query={
             SELECT User, FullPath, Mtime from glob(
               globs=Directory + historyGlobs)
          })

      - |
        SELECT * FROM foreach(row=history_files,
          query={
            SELECT User, FullPath,
                   timestamp(epoch=Mtime.Sec) as Mtime,
                   visited_url,
                   title, visit_count, typed_count,
                   timestamp(winfiletime=last_visit_time * 10) as last_visit_time
            FROM sqlite(
              file=FullPath,
              query=urlSQLQuery)
          })
```
   {{% /expand %}}

## Windows.Applications.OfficeMacros

Office macros are a favourite initial infection vector. Many users
click through the warning dialogs.

This artifact scans through the given directory glob for common
office files. We then try to extract any embedded macros by parsing
the OLE file structure.

If a macro calls an external program (e.g. Powershell) this is very
suspicious!


Arg|Default|Description
---|------|-----------
officeExtensions|*.{xls,xlsm,doc,docx,ppt,pptm}|
officeFileSearchGlob|C:\\Users\\**\\|The directory to search for office documents.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Applications.OfficeMacros
description: |
  Office macros are a favourite initial infection vector. Many users
  click through the warning dialogs.

  This artifact scans through the given directory glob for common
  office files. We then try to extract any embedded macros by parsing
  the OLE file structure.

  If a macro calls an external program (e.g. Powershell) this is very
  suspicious!

parameters:
  - name: officeExtensions
    default: "*.{xls,xlsm,doc,docx,ppt,pptm}"
  - name: officeFileSearchGlob
    default: C:\Users\**\
    description: The directory to search for office documents.

sources:
  - queries:
      - |
        SELECT * FROM foreach(
           row={
              SELECT FullPath FROM glob(globs=officeFileSearchGlob + officeExtensions)
           },
           query={
               SELECT * from olevba(file=FullPath)
           })
```
   {{% /expand %}}

