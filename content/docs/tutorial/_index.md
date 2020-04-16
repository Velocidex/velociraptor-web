---
title: Tutorial
categories: [getting started]
keywords: [usage,docs]
weight: 100
hidden: true
---

In this tutorial we will deploy Velociraptor locally to our machine,
and connect a client to it. This is the bare minimum required to
demonstrate Velociraptor's capabilities and walk through the GUI.

Velociraptor can be used in a number of different ways, but in this
tutorial we will use it as an end point visibility tool, collect some
artifacts and set up endpoint monitoring.

### Overview

Before we start it is useful to see how a Velociraptor deployment
looks at a high level:

{{<mermaid align="center">}}
  graph TD;
   A(User) -->|Browser| B(Velociraptor GUI server)
   B --> C[Frontend]
   C --> D[fab:fa-apple]
   C --> E[fab:fa-linux]
   C --> F[fab:fa-windows]
{{< /mermaid >}}


#### Create a new deployment

Velociraptor clients connect back to the server using an encrypted
communication channel. Each deployment has its own unique
cryptographic keys ensuring the security and authenticity of the
server.

Therefore before we can start the server we will create a new server
configuration file:

```
$ velociraptor.exe config generate > server.config.yaml
```

This command generates a new configuration file and redirect it to the
file `server.config.yaml`. This file contains key material that
controls this specific deployment.
