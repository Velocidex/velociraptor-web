---
title: "Velociraptor Documentation"
date: 2017-03-02T12:00:00-05:00
---

Velociraptor is an advanced opensource endpoint monitoring and DFIR
tool. Velociraptor has many features and its feature set is
growing.

If you are new to Velociraptor, you should start by reading the
`Getting Started` guide, and run a test deployment. Once you are ready
to learn more, read the `User Interface` guide to become more familiar
with the GUI.

Just to give you a taste of what Velociraptor can do for you, here are
some of the more interesting features:


#### Endpoint operations

* Find files and registry keys on endpoints using glob expressions,
  file metadata and even Yara signatures.
* Apply Yara signatures to process memory.
* Acquire process memory based on various conditions for further
  examination by Windbg.
* Upload entire files from endpoints automatically and on demand.

* Raw NTFS and Registry hive parsing for access to locked files such
  as the pagefile and registry hives.

* Full WMI support - Artifacts can express WMI queries and combine
  these with other queries (e.g. download files mentioned in the WMI
  results).

#### Event streaming to monitoring endpoint activity.

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

#### User interface and automation

* Advanced GUI making many tasks easy. GUI supports SSL and SSO for
  strong identity management.
* Server side VQL allows for automating the server using VQL - launch
  further collection automatically when certain conditions are
  detected.
* A python API allows for full control of the server from python
  including post processing acquired data.

#### Endpoint resource management

* Client supports throttling - you can run very intensive operations
  on the client at a controlled rate to limit impact on endpoint
  performance.
