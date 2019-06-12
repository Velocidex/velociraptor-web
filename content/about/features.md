---
title: Velociraptor Features
linktitle: Velociraptor Features
description: Velociraptor has many features.
date: 2017-02-01
publishdate: 2017-02-01
lastmod: 2017-02-01
menu:
  docs:
    parent: "about"
    weight: 20
weight: 20
sections_weight: 20
draft: false
toc: true
---

Velociraptor has many features and its feature set is growing
daily. The following is an overview of the most significant features.


## Endpoint operations

* Find files on endpoints using glob expressions, file metadata and
  even Yara signatures.
* Search through registry using glob expressions, metadata and even
  Yara signatures.
* Apply Yara signatures to process memory.
* Acquire process memory based on various conditions for further
  examination by Windbg.
* Upload entire files from endpoints automatically and on demand.
* Raw NTFS parsing for access to locked files like the pagefile and
  registry hives.
* Full WMI support - Artifacts can express WMI queries and combine
  these with other queries (e.g. download files mentioned in the WMI
  results).

## Event streaming to monitoring endpoint activity.

* Velociraptor supports streaming event queries - data can be collected
  automatically from endpoints and stored on the server. For example
  all these may be streamed to the server:

  - Process execution logs.
  - High value events parsed from the event logs.
  - DNS Queries and answers

* Escalations can be automatically actioned server side upon
  collection of client events.
* Interactive shell is available for those unexpected times when you
  need to get hands on!

## User interface and automation

* Advanced GUI making many tasks easy. GUI supports SSL and SSO for
  strong identity management.
* Server side VQL allows for automating the server using VQL - launch
  further collection automatically when certain conditions are
  detected.
* A python API allows for full control of the server from python
  including post processing acquired data.

## Endpoint resource management

* Client supports throttling - you can run very intensive operations
  on the client at a controlled rate to limit impact on endpoint
  performance.
