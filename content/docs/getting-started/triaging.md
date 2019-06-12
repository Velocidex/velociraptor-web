---
title: Triaging
linktitle: Triaging
description: Velociraptor can also be used as a triage collection tool.
categories: [getting started]
keywords: [usage,docs]
menu:
  docs:
    parent: "getting-started"
    weight: 5
draft: false
aliases: [/getting-started/triage/]
toc: false
---

We can use Velociraptor to hunt for many artifacts across the
network. However ultimately, the Velociraptor agent simply runs VQL to
collect its artifacts. What if we can just collect the artifacts
interactive?

We certainly can do this!

## Triaging a system.

When triaging a system our goal is to collect and preserve as much
data from the system as possible, as quickly as possible.

First lets see what artifacts come built in with Velociraptor:

```shell
$ velociraptor artifact list
Admin.Client.Upgrade
Admin.Events.PostProcessUploads
Admin.System.CompressUploads
Demo.Plugins.Fifo
Generic.Applications.Office.Keywords
...
```

Now we just select which artifact to collect and specify an output zip
file to store the results to:

```
F:\>velociraptor.exe artifacts collect -v Windows.Triage.WebBrowsers --output f:\output\test.zip
[INFO] 2019-04-01T03:49:38-07:00 Loaded 99 built in artifacts
[INFO] 2019-04-01T03:49:38-07:00 Collecting file \C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cookies
[INFO] 2019-04-01T03:49:38-07:00 Collecting file \C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cookies-journal
[INFO] 2019-04-01T03:49:38-07:00 Collecting file \C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Current Session
...
```
