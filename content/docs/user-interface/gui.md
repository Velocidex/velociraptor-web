---
title: Searching for clients
linktitle: Searching for clients
date: 2019-05-01
publishdate: 2019-05-01
lastmod: 2019-05-01
categories: [manual]
keywords: [usage,docs]
menu:
  docs:
    parent: "manual"
    weight: 10
weight: 0010
draft: false
aliases: [/manual/gui]
toc: true
---

One of the most common tasks we do is search for a client. This allows
us to interact with a specific endpoint and investigate it, collecting
various information about it.

When starting the GUI we are presented with the main application front
page.


![Front page](../search.png)

At the top of the screen we see a hamburger menu to the left and a
search box. Clicking the menu opens the main application navigation
menu.

The search box allows us to find a specific endpoint (Velociraptor
refers to endpoints as `clients`). We may search for the client by
host name, label or client id. Simply click on the seach bar without
any search term to show some random clients. The search box features a
type ahead completion, so simply start typing the hostname and
Velociraptor will show some suggestions.

Alternatively it is possible to apply regular expressions to the
search term and all hosts matching will be retrieved.

{{% notice note %}}

Internally each client has a unique client ID - Velociraptor uses the
client Id to distinguish between hosts, rather than the hostname. This
is done since a hostname is not a reliable unique indicator of an
endpoint. Many systems change their hostname based on DHCP settings,
or even multiple machines may be assigned the same hostname due to
misconfiguration.

Velociraptor always uses the unique client id for the host, but will
usually also show the host's fully qualified domain name (FQDN) as
well.

{{% /notice %}}



The results from the search are shown as a table.

![Search page](../search2.png)


The table contains three columns:

1. The online state of the host is shown as a color icon. A green dot
   indicated that the host is currently connected to the server, a
   yellow icon indicates the host is not currently connected but was
   connected less than 24 hours ago. A red icon indicates that the
   host has not been seen for 24 hours or more.

2. The client ID of the host is shown.

3. The hostname reported by the host.

4. The operating system version. This indicates if the host is a
   Windows/Linux/OSX machine and its respective version.

5. Any labels applied to the host.

## Labels

Hosts may have labels attached to them. A label is any name associated
with a host. Labels are useful when we need to hunt for a well defined
group of hosts, then we can restrict the hunt to one or more labels to
avoid collecting unnecesary data or accessing machines we should not
be.

It is possible to manipulate the labels via the search screen. Simply
select the hosts in the GUI and then click the "add labels" button.

![Adding labels](../labels.png)

Although it is possible to manipulate lables via the GUI, It is
usually easier to use VQL queries to add or remove labels via the
[Label]({{< relref "/docs/vql_reference/server.md#label" >}}) plugin.
