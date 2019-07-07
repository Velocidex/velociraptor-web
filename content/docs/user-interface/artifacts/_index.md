---
title: Velociraptor Artifacts
linktitle: Velociraptor Artifacts
weight: 30
---

Velociraptor's main job is to collect `Artifacts`, but what is an
`Artifact`?. An artifact is simply a yaml file which tells
Velociraptor how to collect a set of files or information in order to
answer a specific question.

Before we can discuss how artifacts are used within Velociraptor, we
need to understand what Artifacts are and how they relate of
Velociraptor.


## Artifact definitions

Artifacts are supposed to be defined and tweaked by the
user. Therefore they are defined using YAML in a simple human readable
file format.

Below is an example of a typical artifact definition.

```yaml
name: Windows.Sys.Users
description: |
  List User accounts that were logged into the machine in the past by
  searching for registry artifacts.

  What local or domain users have previously logged into an endpoint?

parameters:
  - name: remoteRegKey
    default: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
        - SELECT "" as Uid, "" as Gid,
               lookupSID(
                 sid=basename(path=Key.FullPath)
               ) as Name,
               Key.FullPath as Description,
               ProfileImagePath as Directory,
               basename(path=Key.FullPath) as UUID,
               Key.Mtime.Sec as Mtime,
               "roaming" as Type
           FROM read_reg_key(globs=remoteRegKey, accessor="reg")

reports:
  - type: CLIENT
    template: |

      Users that logged in previously.
      ===============================

      {{ .Description }}

      The following table shows basic information about the users on this system.

      {{ Query "users" "SELECT Name, UUID, Type, Mtime FROM source()" | Table }}
```

We can see the main sections:

1. The `name` of the artifact is a dot separated string used to
   identify the Artifact in the UI. We typically name the artifact
   using a heirarchical category based naming scheme.

2. The `description` section contains a human readable description of
   the purpose of this artifact, how it works and when to use it. The
   description section is searchable in the GUI so you should provide
   enough context there to assist a user in selecting this artifact.

2. The `parameters` section is a list of parameters provided to the
   artifact. When the user selects this artifact in the GUI, they are
   also given the option to tweak these parameters. Parameters may
   also specify a default value and a helpful description to help
   users set the correct value.

3. The sources section contains a list of evidence sources. Each
   source specifies a series of VQL queries. The queries may retrieve
   specific information or files.

   * A `precondition` is a VQL query which must be satisfied before
     the source is collected. This is typically used to limit an
     artifact to a specific operating system or version.

   * The `queries` section is a list of VQL queries, executed one at
     the time, which produce a single result set (i.e. a table with
     specified columns and rows). Typically the `queries` section
     consists of a list of `LET` VQL statements followed by a single
     `SELECT`.

4. Finally the `reports` section specifies a set of report templates
   to be used to analyze the results collected from the artifact. You
   can read more about [report templates]({{< relref "templates.md" >}}).

{{% notice tip %}}

At a high level, an artifact answers a specific question. As an
investigator we ask questions relevant to our case, and the artifact
maps these questions to a mechanical collection providing sufficient
evidence to cast light on our question. The Velociraptor GUI allows
one to search artifacts by their description section.

{{% /notice %}}


### Reports

The artifact contains a `report` that helps the user make sense of the
collected evidence and provides simple post processing
capabilities. Reports are templates that are evaluated on the
artifact's results and produce simple markdown, graphs, tables and
other primitives. Reports may issue VQL statements to further analyze
the collected data and therefore may produce any output.

The report presents a human readable post processing on
the collected artifact - collating and correlating evidence from
multiple sources in order to answer the high level question posed by
the artifact.

The purpose of the artifact is to encapsulate expert knowledge into
the artifact to both document and guide investigators through the
investigation process. Even experienced investigators can benefit from
artifacts, since they do not need to worry about forgetting to collect
a particular source, or wrongly interpreting some of its finding.

In the above example, the high level question is `What domain users
have logged into this endpoint?`. To answer this question we extract
registry artifacts created whenever a user gains an interactive logon
session to a machine. The report helps us to understand what the
registry artifacts actually mean. We can see the report can run
further VQL queries to highlight or post process the results, perhaps
drawing our attention to particularly interesting findings.

## Artifact Types

Velociraptor uses VQL for many different purposes. Since Artifacts are
a nice way to package VQL queries, there are a number of different
types of artifacts depending on the specific VQL contained within them.

For a full reference of VQL see [VQL Reference]({{< ref "/docs/vql_reference" >}}), but for now we just need to distinguish between two main types of VQL queries:

1. A `Collection Query` is a query which runs once and collects a
   table of results, then terminates.

2. An `Event Query` is a query which runs forever, waiting for some
   events to occur. When the event occurs, the query will emit one or
   more rows and continue waiting. Output from Event Queries is
   streamed for as long as the query continues running.

Therefore we have 4 types of artifacts:

1. A [client collection artifact]({{< relref "client_artifacts" >}})
   encapsulates VQL queries primarily designed to run on the endpoint
   and return a table of results. These are typically used to capture
   some piece of information from the host - for example, the list of
   installed programs, the presence of a registry key etc.

2. A [client event artifact]({{< relref "client_events" >}}) encapsulates
   Event Queries that are running on the client, streaming rows to the
   server. These are typically used to monitor for specific events on
   the client. For example, watching the event log for a new event of
   interest.

3. A [server collection artifact]({{< relref "server_artifacts" >}}) is
   an artifact that contains a Collection Query that is designed to
   run on the server. Typically these artifacts are used to perform
   some post processing on the server or provide server state
   information.

4. A [server event artifact]({{< relref "server_events" >}}) is an
   artifact containing event queries permanently running on the
   server. These are typically used to watch the entire Velociraptor
   deployment for specific conditions. For example, a server event
   artifact might monitor process execution logs from all clients and
   automatically decode encoded powershell command lines, alerting on
   suspicious occurances.
