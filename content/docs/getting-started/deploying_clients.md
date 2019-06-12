---
title: Deploying Clients
linktitle: Client Deployment
description: Velociraptor endpoint clients must be deployed on the endpoint. There are a number of way this can be done.
categories: [getting started]
keywords: [usage,docs]
menu:
  docs:
    parent: "getting-started"
    weight: 5
draft: false
aliases: [/getting-started/clients/]
toc: false
---

Velociraptor endpoint agents are called `clients`. Clients connect to
the server and wait for instructions (which mostly consist of VQL
statements), they then run any VQL queries and return the result to
the server.

There are a number of ways to run clients, depending on your
needs. This page summarizes the ways and discusses the pros and cons
of each approach.

Note that all Velociraptor binaries are the same - there is no
distinction between client binaries or server binaries. Therefore you
can run the server or the client on each supported platform. It is
simply command line options telling the binary to behave as a server
or client.

## Obtaining a client configuration file

Velociraptor clients know how to connect using the client's
configuration file. This file is generated from the server config file
and consists only of client specific options (like keys). The config
file is unique to your deployment - it is not possible to connect to
another deployment without obtaining that deployment's config file.

```
# velociraptor --config server.config.yaml config client > client.config.yaml
```

Will generate something like the following

```yaml
Client:
  server_urls:
  - https://velociraptor.example.com/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDITCCAgmgAwIBAgIRAI1oswXLBFqWVSYZx1VibMkwDQYJKoZIhvcNAQELBQAw
...
  writeback_windows: $ProgramFiles\Velociraptor\velociraptor.writeback.yaml
```

The file contains the server's location URL and a CA certificate to
verify the server's TLS certificate. If the deployment is self signed
the server's certificate must be issued by this CA.

The writeback file will be used to store client's state like crypto
keys.

## Running clients interactively

This method is most suitable for testing your deployment. In a shell
simply run the client using the client configuration.

```shell
$ velociraptor --config client.config.yaml client -v
```

The first time the client connects it will enrol. The server will
issue the interrogate flow on it automatically to collect various
information about it.

## Installing the client as a service

It is possible to tell the executable to install itself as a
service. This is preferable since it ensures the client runs as the
SYSTEM user and starts as soon as the machine boots.

```shell
# velociraptor.exe --config client.config.yaml service install
```

This will copy the binary to the location specified in the
configuration file under `Client.windows_installer`. You can change
the name of the binary and the service name.

## Installing using MSI package

While the previous method installs a service, it creates the service
by itself and just copies the file to their final detination. A proper
MSI package will be able to be uninstalled and upgraded and work
better with system wide package management tools like SCCM.

To create one of these follow the instructions
[here](https://github.com/Velocidex/velociraptor/tree/master/docs/wix).

## Agentless deplyment

There has been a lot of interest lately in "Agentless hunting"
especially using PowerShell. There are many reasons why Agentless
hunting is appealing - there are already a ton of endpoint agents and
yet another one may not be welcome. Somtimes we need to deploy
endpoint agents as part of a DFIR engagement and we may not want to
permanently install yet another agent on end points.

In the agentless deployment scenario we simply run the binary from a
network share using group policy settings. The downside to this
approach is that the endpoint needs to be on the domain network to
receive the group policy update (and have the network share
accessible) before it can run Velociraptor. When we run in Agentless
mode we are really after collecting a bunch of artifacts via hunts and
then exiting - the agent will not restart after a reboot. So this
method is suitable for quick hunts on corporate (non roaming) assets.

See this [blog
post](/blog/html/2019/03/02/agentless_hunting_with_velociraptor.html)
for the details of how to deploy Velociraptor in this mode.