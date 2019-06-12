---
title: VQL Server Plugins
linktitle: VQL Server Plugins
description: VQL Queries can also be run on the server.
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

When run on the server, VQL Queries have access to server state, and
so can schedule new artifact collection flows on client, manage client
label, and retrieve artifact results from hunts. It is therefore
possible to post process artifacts on the server in arbitrary ways.

Server VQL queries can also be event driven which allows one to set up
higher order escalations and alerting based on client side events.


## mail

Arg | Description
----|------------
to|Who to send mail to
cc|Who to cc the mail
subject|The subject of the mail
body|The body of the message
period|How long to wait before sending the next mail - help to throttle mails.

This plugin sends a mail. In order to use it you must have the Mail
section configured in the server's config file.

Usually you would use the `foreach()` plugin to send a mail from
another event query.

Mails will not be sent more frequently than the specified period. Most
mail servers implement rate limiting or spam detection so if this is
set too low it is possible to overload the server. Currently we do not batch messages, rather drop them if sent too quickly.

## collect

Arg | Description
----|------------
client_id|The client to schedule collection on
artifacts|A list of one or more artifact names to collect.
env|A dict of parameters to populate the scope with.

The function schedules an artifact collection flow on the server for
the client. It is equivalent to the GUI functionality and allows us to
automatically collect client artifacts in response to some event.

The function will return a flow id which can be used to track flow
until completion.

## clients

Arg | Description
----|------------
search|A search expression for clients.

This plugin returns all clients retrieved by the search term. The
search term is the same as in the GUI and may consist of:

- a plain word searchs for a host name
- May contain wild cards (`my*hostname`)
- May contain a prefix such as host:, label:, user:

## flows

Arg | Description
----|------------
client_id|The client to use

Returns a list of flows launched on the client by client id.

## compress

Arg | Description
----|------------
path|A VFS path into the file store

This function compresses a file within the file store. A compressed
file is archived so it takes less space. It is still possible to see
the file and read it but not to seek within it.

## elastic

Arg | Description
----|------------
query|A delegate query to run. Rows from this query will be inserted into elastic.
threads|How many uploader threads to use.
index|The name of the elastic index to use.
type|The name of the elastic type to use.

This plugin uploads rows into Elastic Search. We do not define the
index, so if it is not already defined, Elastic will define it as a
default index.

This plugin is experimental.

## file_store

Arg | Description
----|------------
path|A VFS path

Velociraptor uses the concept of a Virtual File System to manage the
information about clients etc. The VFS path is a path into the file
store. Of course ultimately (at least in the current implementation)
the file store is storing files on disk, but the disk filename is not
necessarily the same as the VFS path (for example non representable
characters are escaped).

You can use the `file_store()` function to return the real file path
on disk. This probably only makes sense for VQL queries running on the
server which can independently open the file.

In future the file store may be abstracted (e.g. files may not be
locally stored at all) and this function may stop working.

## hunts

Returns all the hunts scheduled in the system.

## hunt_results

Arg | Description
----|------------
hunt_id|The hunt id to use
artifact|The name of the artifact to retrieve results for
brief|If set less information is returned.

This plugin returns the results from a hunt. Since hunts may collect
multiple artifacts at the same time, the plugin only retrieves one
artifact at the time. The returned rows have the flow_id and client_id
appended (since hunt results come from multiple clients).

This plugin is very useful to see the results from a hunt. It always gets the most recent results so as the hunt progresses, there will be more rows returned.

The plugin is useful for performing stacking (using group by) or
further narrowing the hunt result on demand.

## hunt_flows

Arg | Description
----|------------
hunt_id|The hunt id to use

Retrieve the flows launched by a hunt. This is useful to quickly
identified which client returned results, without necessarily counting
them. Flow object contains high level context about the flow
execution.


## label

Arg | Description
----|------------
client_id|The client to use
labels|One or more label
op|An operation on the labels (add, remove)

This function adds or removed labels from clients.

## monitoring

Arg | Description
----|------------
client_id|The client to use. If not specified we search all clients.
artifact|The artifact to retrieve
date_regex|A regular expression applied to the date file.

Velociraptor can monitor events on endpoints using the Event
monitoring framework. This causes events to be streamed from the
client and stored on the server within the client's monitoring part of
the VFS.

One installs event monitoring artifacts by naming them in the server's
configuration files. Rows returned from these artifacts will be
written to CSV files on the server. Each file is named by the day it
is written.

This plugin allows to query monitoring logs collected by the server
and therefore post process them. For example it is possible to search
process execution logs for certain process names, or stack them using
group by queries.

For efficiency it is possible to specify a regex which should match
the date. Since monitoring CSV files are stored with the date as a
filename, we can avoid openning files which are not interesting or too
old.

## watch_monitoring

Arg | Description
----|------------
client_id|The client to use. If not specified we search all clients.
artifact|The artifact to retrieve
date_regex|A regular expression applied to the date file.

This plugin is similar to the `monitoring()` plugin but it is an event
plugin watching the specified artifact file instead. When an event is
stored in the monitoring CSV file it is also relayed to this plugin
(We are essentially tailing the monitoring CSV files).

This allows us to implement an event query which watches for client
side events and acts on them (e.g. by esclating or responding).

If the client id is not specified, we watch for events from all
clients.

## collected_artifacts

Arg | Description
----|------------
client_id|The client id.
flow_id|The flow id (you can get these from the flows() plugin).
artifact|The artifact name to retrieve.
source|If the artifact contains multiple named sources, setting this will fetch a named source.

This plugin emits the results from an artifact collected on a
client. You can get a list of such artifacts by querying the `flows()`
plugin. If the artifact contains multiple named sources, the plugin
allows for a single source to be selected.

Note that a VQL plugin simply returns the results collected and saved
by another query run by the artifact. It is most useful for post
processing the results.

## source

Arg | Description
----|------------
source|The name of the source to query.

This is a convenience function to use in reports. It simply called
collected_artifacts() above with the client_id, flow_id and artifact
fetched from the environment.

When a report is generated these values are prefilled in the
environment by the template expander.
