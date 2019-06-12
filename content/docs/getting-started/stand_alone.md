---
title: Standalone Deployment
linktitle: Standalone Deployment
description: The simplest way to deploy a Velociraptor server is via a self signed, stand alone deployment.
categories: [getting started]
keywords: [usage,docs]
menu:
  docs:
    parent: "getting-started"
    weight: 1
draft: false
aliases: [/getting-started/standloane/]
toc: false
---

![Architecture Overview](../overview.png)

The Velociraptor server communicates with the clients over SSL
connection. The same binary also provides a GUI on a separate port.

## Step 1: Generating a new config file.

Velociraptor uses a configuration file to control the server and
client. Before making a new deployment, you need to generate a new
config file. The file also contains key material such that your
clients will only communicate with your servers.

Therefore our first step is to generate a new configuration
file. Velociraptor will generate new keys and fill in most fields with
reasonable defaults. However you will definitely need to edit the
file to adjust a few parameters.

```bash
$ velociraptor config generate > server.config.yaml
```

## Step 2: Edit the configuration

The configuration file generated contains fairly reasonable
defaults. The following parameters will probably need to be changed
though.

```yaml
Client:
  server_urls:
    - https://localhost:8000/

Datastore:
  implementation: FileBaseDataStore
  location: /tmp/velociraptor
  filestore_directory: /tmp/velociraptor

```

The `Client.server_urls` parameter is passed on to the client
configuration and indicates the public URL the client will attempt to
connect to. If you have a reverse proxy or gateway in front of the
server this value may be completely different from the server's
hostname and port.

By default Velociraptor will use self signed SSL so this URL should
begin with `https://`. Velociraptor is aware it is in self signed mode
and the Velociraptor client will only connect to a server presenting a
certificate signed by the CA certificate hard coded within the client
configuration. This means that although the deployment is using self
signed certificates, due to CA pinning it is even more secure than
using public PKIs (even if a public CA is compromised, it can not mint
a certificate the client will accept).


Finally you should probably update the location of the file store to
somewhere more permanent. This is where uploaded files and artifact
result CSV files are stored.

{{% notice note %}}

Velociraptor does not enforce any particular data retention
policies. At any time the data store can be wiped, and the server
restarted. If this happens, all the currently deployed clients will be
automatically re-enrolled with their existing client IDs (You might
want to archive any custom artifacts that you wrote however).

Since Velociraptor uses plain files, it is possible to archive the
entire deployment, or simply delete older files with a cron job.

{{% /notice %}}

## Step 3: Add a GUI User

In order to connect to the GUI using a web browser we require
authentication. In this simple mode, we use pre-determined
username/password combinations to authenticate users. Create a new GUI
user account:

```shell
$ velociraptor --config server.config.yaml user add mic
```

This will ask for a password and then create a user record in the data
store (it is just a file).

{{% notice note %}}

The GUI has no facility for the user to change their password. In a
larger deployment we do not expect that user accounts be manually
managed. Instead users should belong to a central SSO
mechanism. Currently Velociraptor supports Google OAuth2 and in future
AD integration might provide a suitable SSO mechanism.

{{% /notice %}}

## Step 4: Start the frontends

The frontend is the main Velociraptor server process. It performs all
the functions in the same binary.

We start the frontend using (The -v flag causes verbose output to be
shown in the terminal):

```text
# velociraptor --config server.config.yaml frontend -v
[INFO] 2019-04-01T14:44:40+10:00 Starting Frontend. {"build_time":"2019-04-01T00:25:49+10:00","commit":"503b1cf","version":"0.2.8"}
[INFO] 2019-04-01T14:44:40+10:00 Loaded 99 built in artifacts
[INFO] 2019-04-01T14:44:40+10:00 Loaded artifact_definitions/custom/Test.Yara.Scan.yaml
[INFO] 2019-04-01T14:44:40+10:00 Launched Prometheus monitoring server on 127.0.0.1:8003
[INFO] 2019-04-01T14:44:40+10:00 Frontend is ready to handle client TLS requests at 0.0.0.0:8000
[INFO] 2019-04-01T14:44:40+10:00 Starting hunt manager.
[INFO] 2019-04-01T14:44:40+10:00 Launched gRPC API server on 127.0.0.1:8001
[INFO] 2019-04-01T14:44:40+10:00 GUI is ready to handle TLS requests {"listenAddr":"127.0.0.1:8889"}
[INFO] 2019-04-01T14:44:40+10:00 Starting hunt dispatcher.
[INFO] 2019-04-01T14:44:40+10:00 Starting stats collector.
```

The frontend indicates which port the GUI will listen on
(i.e. `https://127.0.0.1:8889`).

{{% notice note %}}

Velociraptor currently does not support multiple frontends - all
clients connect to the same frontend which perfoms all roles (serving
client connections, serving the GUI and running the API server). While
we are working to address this limitation, we have tested Velociraptor
with 5-10k endpoints and it performs quite well already.

{{% /notice %}}

## Step 5: Verify the GUI works

Start a browser and point it at your GUI URL. In this mode, the GUI is
served over TSL with a self signed certificate. This shows up as an
untrusted certificate in browsers. You would need to log in as the
user you created earlier.

![Velociraptor GUI](../self_signed.png)

If you want to have an SSL certificate issued by Letsencrypt (so the
browser warning does not show up) see the next section (Deployment in
the cloud).

Thats it! you have a Velociraptor server up and running. Next you will
need to distribute and install your clients.