---
title: Deploying in the cloud
linktitle: Cloud Deployment
description: Deploying Velociraptor servers in the cloud provides many advantages, including easy of use, fast bandwidth and flexibility to scale as needed.
categories: [getting started]
keywords: [usage,docs]
menu:
  docs:
    parent: "getting-started"
    weight: 5
draft: false
aliases: [/getting-started/cloud/]
toc: false
---

However one of the most important advantages of cloud deployment is
the possibility of minting a proper SSL certificate using the free
Letsencrypt CA. Velociraptor is able to use the Letsencrypt protocol
to obtain its own certificates (and automatically rotate them when
they expire).

## Step 1: Getting a domain name

An SSL certificate says that the DNS name is owned by the server which
presents it. Therefore SSL goes hand in hand with DNS. It is not
currently possible to get a Letsencrypt certificate for an IP address.

Therefore the first thing you need to do is to buy a DNS domain from
any provider. Once there you need to set up a DNS A Record to point at
your Velociraptor server's external IP.  You can use a dynamic DNS
client such as ddclient to update your DNS->IP mapping dynamically.

## Step 2: Tell Velociraptor to use autocert

Velociraptor can issue its own certificates. Simply configure the
following settings in the server's configuration file.

```yaml
autocert_domain: velociraptor.example.com
autocert_cert_cache: /etc/velociraptor_cache/
```

Enabling autocert mode has the following effects:

1. Velociraptor will listen on port 443 for both the GUI and Client
   connections.

2. Velociraptor will listen on port 80 for HTTP certificate
   authentication (This is part of the letsencrypt protocol).

You must have both these ports publically accessible by allowing any
inbound firewall rules! Letsencrypt uses both to issue certificates.

The first time you connect the GUI to the frontend, the server will
obtain its own certificates from letsencrypt (it might take a couple
of seconds to respond the first time).