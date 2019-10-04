---
title: About Velociraptor
linktitle: Overview
description: Velociraptor's features, roadmap, license and motivation.
date: 2019-02-01
publishdate: 2019-02-01
lastmod: 2019-02-01
categories: []
keywords: []
menu:
  docs:
    parent: "about"
    weight: 1
weight: 1
draft: false
aliases: [/docs/]
toc: false
---

## So what is Velociraptor?

Velociraptor is a unique, advanced open-source endpoint monitoring, digital forensic and cyber response platform.

It was originally developed by DFIR professionals who needed a powerful and efficient way to hunt and monitor activities across fleets of endpoints for specific artefacts, in a wide range of digital forensic and cyber incident response investigations such as:

* Responding to data breaches
* Reconstructing attacker activities through digital forensic analysis
* Hunting for evidence of sophisticated adversaries
* Investigating malware outbreaks and other suspicious network activities
* Continual monitoring for suspicious user activities, such as files copies to USB devices
* Disclosure of confidential information outside the network
* Gathering endpoint data over time, for use in threat hunting and future investigations.

Velociraptor is actively being used by DFIR professionals across cases such as these and continues to grow and develop based on their feedback and ideas.

## VQL - the Velociraptor difference

The most powerful feature of Velociraptor is its framework for creating highly customized **artifacts** which allow a user to collect, query and monitor almost any aspect of a single endpoint, groups of endpoints or an entire network.

<!--
For some great examples of how artefacts can be used, refer to the [Use Cases](../docs/use_cases).
-->

For technical details on how artefacts work, check out the [VQL Reference](../docs/vql_reference) documentation.

### Example - collecting user activities from a single endpoint

Here's a simple example. Below is a VQL artefact named **Windows.Registry.NTUser.Upload** which is part of Velociraptor's default artefact collection.

This artefact first lists all users (using another artefact named **Artifact.Windows.Sys.Users**) then for each user, collects their NTUSER.DAT registry hive from the endpoint, using raw NTFS access to bypass Windows file system access controls (using the **upload** function).

```text
1 LET users = SELECT Name, Directory as HomeDir
2    FROM Artifact.Windows.Sys.Users()
3    WHERE Directory
4 SELECT upload(file="\\\\.\\" + HomeDir + "\\ntuser.dat",
5              accessor="ntfs") as Upload
6 FROM users
```

All these artifacts and functions are documented on this site. Simply search or browse the menu to the left.

#### Example - collecting ALL user Registry hives

Now to extend your reach. The very same VQL artefact can be run as a hunt across multiple endpoints, to simultaneously collect all user hives across your network in one sweep.

All connected endpoints will immediately receive the query and carry out your request. Any endpoints not currently connected will receive the command as soon as they reconnect to the Velociraptor server. No need for repeating the hunt or scheduling multiple hunts - Velociraptor will take care of the job.

<!--
#### Example - tracking an attacker's activities through their Registry hives

Let's extend this simple example a little more. Say you're investigating an attacker on your network. You've identified they're using a compromised backup service account and you want to collect all Registry hives from every system on which they've made an interactive login, to examine evidence of folders accessed, search queries entered into Explorer and files they've opened - critical evidence when answering questions about whether the attacker accessed any confidential information.

Velociraptor and VQL makes this simple. Make a copy of the artefact (named for example **Custom.Windows.Registry.NTUser.Upload**), then edit the VQL to focus on the compromised account name, by changing this line:

```text
4 SELECT upload(file="\\\\.\\" + HomeDir + "\\ntuser.dat",
```

to this:

```text
4 SELECT upload(file="\\\\.\\nick\\ntuser.dat",
```

Your new artefact will look something like this:

```text
1 LET users = SELECT Name, Directory as HomeDir
2    FROM Artifact.Windows.Sys.Users()
3    WHERE Directory
4 SELECT upload(file="\\\\.\\nick\\ntuser.dat",
5              accessor="ntfs") as Upload
6 FROM users
7
```
-->

## Our design goals

The design goals of Velociraptor that we're working towards, are to be:

* **Useful** - each artefact and use case must return valuable information to the user
* **Simple** - the design and interface must be easy for a person to navigate and use
* **Guided** - users don't need to be DFIR experts, since all elements should provide informative descriptions and guidance
* **Powerful** - the user should not have to perform too much additional work to achieve their objectives
* **Quick** - performance should be speedy and resource impact low, while allowing performance to be managed when needed
* **Reliable** - each feature and artefact should work as expected and be relatively free of bugs and issues

## We're still a work in progress

Although Velociraptor is already being used on real-life DFIR cases, it's still early days and is very much a work in progress.

Our roadmap includes many exciting features and developments, including:

* Expanding the artefact library, including individual artefacts and 'artefact packs' for even more powerful collection and analysis
* More artefact parsers to allow for analysis of artefacts and data reuse and cross-referencing directly on the server
* More monitoring artefacts, for real-time event detection and alerting
* Artefacts for OSX and Linux, since we already have clients for these
* Further documentation, especially within artefacts in the GUI, so users don't have to be DFIR experts
* A kernel driver for Windows, providing tighter integration with operating system event monitoring
* Improving the user interface, including richer features and more automated reporting

## Send us your feedback

We welcome all ideas and suggestions on how Velociraptor could be used and improved and encourage our users to get in touch.

<!-- Insert contact details
You can connect with us via:
-->
