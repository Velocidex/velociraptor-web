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

To give you a taste of what Velociraptor can do, here are some of the more interesting features:

## Easy setup and deployment

* Velociraptor ships as a singe executable which has no dependencies and requires no installation routine
* Settings are defined by a pair of config files - one for the server and one for each endpoint
* All comms between endpoints and the server are encrypted
* The GUI supports SSL and SSO via Google Auth for strong identity management
* Once an endpoint is started, it's instantly available on the server dashboard (after a browser refresh).

## Endpoint operations

* Quickly search for endpoints and connect to them for fast browsing and evidence collection
* Easily browse the contents of endpoint file systems, even bypass locked files using raw NTFS access
* Remotely inspect and download files of interest all through the GUI
* Search for files across all endpoints using glob expressions, file metadata and even Yara signatures
* Collect files from endpoints automatically and on demand
* Search and parse the Windows Registry for keys and values of interest
* Perform triage collection of the most common digital forensic artefacts using build-in collection templates
* Use the built-in library of artefacts to easily hunt for a wide range of forensic artefacts simultaneously across a whole network
* Acquire process memory based on various conditions for further examination by Windbg
* Apply Yara signatures to process memory
* Extend VQL with WMI to build powerful queries for interrogation and data collection
* An interactive shell is even available, for those unexpected times when you need to get hands-on.

## Event streaming to monitor endpoint activity

* Velociraptor also supports streaming event queries on endpoints themselves, meaning that data can be collected automatically from endpoints and stored on the server, for continual monitoring and real-time alerting, or for archival and investigation after the fact. Examples include:

  - Operating system logging events such as privileged account activities and process execution
  - Extended logging, for example through Sysmon integration
  - DNS queries and responses.

* Escalations can be automatically actioned on the server, upon collection of client events

## User interface and automation

* An advanced GUI which makes many simple tasks easy
* Server-side VQL allows for automating the server using VQL queries too, for example to launch further collection automatically when certain conditions are
  detected
* A Python API also allows for full control of the server using Python, including post processing acquired data.

## Endpoint resource management

* Endpoint activities can be carefully managed, for example client-side throttling allows you to run intensive operations on the endpoints at a controlled rate to minimise impact on endpoint performance.
