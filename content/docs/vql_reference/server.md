---
title: VQL Server Plugins
weight: 30
---

VQL Queries can also be run on the server. When run on the server, VQL
Queries have access to server state, and so can schedule new artifact
collection flows on client, manage client label, and retrieve artifact
results from hunts. It is therefore possible to post process artifacts
on the server in arbitrary ways.

Server VQL queries can also be event driven which allows one to set up
higher order escalations and alerting based on client side events.


## clients

Arg | Description | Type
----|-------------|-----
search | Client search string. Can have the following prefixes: 'lable:', 'host:' | string
client_id |  | string

This plugin returns all clients retrieved by the search term. The
search term is the same as in the GUI and may consist of:

- a plain word searchs for a host name
- May contain wild cards (`my*hostname`)
- May contain a prefix such as host:, label:, user:

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

{{% notice note %}}

This plugin is currently disabled because it seems to have an
extremely large binary footprint. You can enable it and recompile the
binary if you need it.

{{% /notice %}}

## flows

Arg | Description | Type
----|-------------|-----
client_id |  |  list of string (required)

Returns a list of flows launched on the client by client id.

## hunt_flows

Arg | Description | Type
----|-------------|-----
hunt_id | The hunt id to inspect. | string (required)

Retrieve the flows launched by a hunt. This is useful to quickly
identified which client returned results, without necessarily counting
them. Flow object contains high level context about the flow
execution.

## hunt_results

Arg | Description | Type
----|-------------|-----
artifact | The artifact to retrieve | string (required)
source | An optional source within the artifact. | string
hunt_id | The hunt id to read. | string (required)
brief | If set we return less columns. | bool

This plugin returns the results from a hunt. Since hunts may collect
multiple artifacts at the same time, the plugin only retrieves one
artifact at the time. The returned rows have the flow_id and client_id
appended (since hunt results come from multiple clients).

This plugin is very useful to see the results from a hunt. It always gets the most recent results so as the hunt progresses, there will be more rows returned.

The plugin is useful for performing stacking (using group by) or
further narrowing the hunt result on demand.

## hunts

Returns all the hunts scheduled in the system.

## mail

Arg | Description | Type
----|-------------|-----
subject | The subject. | string
body | The body of the mail. | string (required)
period | How long to wait before sending the next mail - help to throttle mails. | int64 (required)
to | Receipient of the mail |  list of string (required)
cc | A cc for the mail |  list of string

This plugin sends a mail. In order to use it you must have the Mail
section configured in the server's config file.

Usually you would use the `foreach()` plugin to send a mail from
another event query.

Mails will not be sent more frequently than the specified period. Most
mail servers implement rate limiting or spam detection so if this is
set too low it is possible to overload the server. Currently we do not
batch messages, rather drop them if sent too quickly.

## search

Arg | Description | Type
----|-------------|-----
type | The type of search (e.g. 'key') | string
query | The query string. | string
offset | Skip this many results. | uint64
limit | Only return limited results | uint64

Search the server client's index.

## source

Arg | Description | Type
----|-------------|-----
start_time | Start return events from this date (for event sources) | int64
mode | HUNT or CLIENT mode can be empty | string
flow_id | A flow ID (client or server artifacts) | string
hunt_id | Retrieve sources from this hunt (combines all results from all clients) | string
artifact | The name of the artifact collection to fetch | string
source | An optional named source within the artifact | string
client_id | The client id to extract | string
day_name | Only extract this day's Monitoring logs (deprecated) | string
end_time | Stop end events reach this time (event sources). | int64

This is the main plugin to use in server VQL to fetch results. It
automatically figures out what type the artifact is and where the CSV
files are. The plugin can take many of these parameters from the
report context so when used in a report it usually needs very few
actual arguments.


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
