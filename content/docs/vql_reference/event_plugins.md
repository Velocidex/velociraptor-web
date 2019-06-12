---
title: VQL Event PLugins
linktitle: VQL Event PLugins
description: VQL Event plugins are plugins which never terminate - but instead generate rows based on events.
date: 2019-02-01
publishdate: 2019-02-01
lastmod: 2019-02-01
categories: [vql]
keywords: []
menu:
  docs:
    parent: "vql_reference"
    weight: 50
weight: 1
draft: false
aliases: []
toc: true
---

Event plugins are useful for creating client monitoring
artifacts. Currently, client side monitoring artifacts are specified
in the `Events` section of the server configuration file. When clients
connect to the server, they receive a list of monitoring artifacts
they are to run. The client runs all artifacts in parallel and their
results are streamed to the server.


## watch_csv

Arg | Description
----|------------
filename|One or more files to parse
accessor|The accessor to use for openning the file.

This plugin is the event version of `parse_csv()`. When the CSV file
grows this plugin will emit the new rows.

## watch_evtx

Arg | Description
----|------------
filename|One or more files to parse
accessor|The accessor to use for openning the file.



Watch an EVTX file and stream events from it. This is the Event plugin
version of `parse_evtx()`.


{{% notice note %}}

It often takes several seconds for events to be flushed to the event
log and so this plugin's event may be delayed. For some applications
this results in a race condition with the event itself - for example,
files mentioned in the event may already be removed by the time the
event is triggered.

{{% /notice %}}

## clock

Arg | Description
----|------------
period|Wait this many seconds between events.
ms|Wait this many milliseconds between events..

This plugin generates events periodically. The periodicity can be
controlled either via the `period` or the `ms` parameter. Each row
will be a go [time.Time](https://golang.org/pkg/time/#Time)
object. You can access its unix epoch time with the Sec column.

### Example

The following will generate an event every 10 seconds.

```sql
SELECT Sec FROM clock(period=10)
```

## diff

Arg | Description
----|------------
query|Source for cached rows.
key|The column to use as key."
period|Number of seconds between evaluation of the query.

The `diff()` plugin runs a non-event query periodically and calculates
the difference between its result set from the last run.

This can be used to create event queries which watch for changes from
simpler non-event queries.

The `key` parameter is the name of the column which is used to
determine row equivalency.

{{% notice note %}}

There is only a single equivalence row specified by the `key`
parameter, and it must be a string. If you need to watch multiple
columns you need to create a new column which is the concatenation of
other columns. For example `format(format="%s%d", args=[Name, Pid])`

{{% /notice %}}

### Example

The following VQL monitors all removable drives and lists files on
newly inserted drives, or files that have been added to removable
drives.

```sql
LET removable_disks = SELECT Name AS Drive, Size
FROM glob(globs="/*", accessor="file")
WHERE Data.Description =~ "Removable"

LET file_listing = SELECT FullPath, timestamp(epoch=Mtime.Sec) As Modified, Size
FROM glob(globs=Drive+"\\**", accessor="file") LIMIT 1000

SELECT * FROM diff(
  query={ SELECT * FROM foreach(row=removable_disks, query=file_listing) },
  key="FullPath",
  period=10)
  WHERE Diff = "added"
```

## fifo

Arg | Description
----|------------
query|Source for cached rows.
max_age|max_age,doc=Maximum number of seconds to hold rows in the fifo.
max_rows|Maximum number of rows to hold in the fifo.

The `fifo()` plugin allows for VQL queries to apply across historical
data. The fifo plugin accepts another event query as parameter, then
retains the last `max_rows` rows from it in an internal queue. Every
subsequent evaluation from the query will return the full set of rows
in the queue. Older rows are expired from the queue according to the
`max_age` parameter.

Fifos are usually used to form queries that look for specific pattern
of behavior. For example, a successful logon followed by failed
logons. In this case the fifo retains the recent history of failed
logons in its internal queue, then when a successful logon occurs we
can check the recent failed ones in its queue.

### Example

The following checks for 5 failed logons followed by a successful
logon.

```sql
LET failed_logon = SELECT EventData as FailedEventData,
   System as FailedSystem
FROM watch_evtx(filename=securityLogFile)
WHERE System.EventID.Value = 4625

LET last_5_events = SELECT FailedEventData, FailedSystem
    FROM fifo(query=failed_logon,
              max_rows=500,
              max_age=atoi(string=failedLogonTimeWindow))

LET success_logon = SELECT EventData as SuccessEventData,
   System as SuccessSystem
FROM watch_evtx(filename=securityLogFile)
WHERE System.EventID.Value = 4624

SELECT * FROM foreach(
  row=success_logon,
  query={
   SELECT SuccessSystem.TimeCreated.SystemTime AS LogonTime,
          SuccessSystem, SuccessEventData,
          enumerate(items=FailedEventData) as FailedEventData,
          FailedSystem, count(items=SuccessSystem) as Count
   FROM last_5_events
   WHERE FailedEventData.SubjectUserName = SuccessEventData.SubjectUserName
   GROUP BY LogonTime
      })  WHERE Count > atoi(string=failureCount)
```

## dns

Monitor dns queries. This plugin opens a raw socket and monitors
network traffic for DNS questions and answers.

{{% notice note %}}

When Velociraptor attempts to open a raw socket, sometimes Windows
Defender treats that as suspicious behavior and quaranteens the
Velociraptor binary. This can be avoided by signing the binary which
signals to Windows Defender that the binary is legitimate.

If you do not intend to build Velociraptor from source, use the
official signed Velociraptor binaries which should not trigger alerts
from Windows Defender.

{{% /notice %}}

## netstat

Collect network information using the network APIs.

## proc_dump

Arg | Description
----|------------
pid|Process ID to dump.

Dumps a process into a crashdump. The crashdump file can be opened
with the windows debugger as normal. The plugin returns the filename
of the crash dump which is a temporary file - the file will be removed
when the query completes, so if you want to hold on to it, you should
use the upload() plugin to upload it to the server or otherwise copy
it.

## wmi_events

Arg | Description
----|------------
query|WMI query to run.
namespace|WMI namespace
wait|Wait this many seconds for events and then quit.

This plugin sets up a [WMI
event](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/receiving-a-wmi-event)
listener query.
