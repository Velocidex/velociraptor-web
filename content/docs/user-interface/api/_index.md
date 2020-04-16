---
date: 2019-02-09T04:10:06Z
title: "The Velociraptor API"
weight: 80
---


Velociraptor is very good at collecting artifacts from
endpoints. However, in modern DFIR work, the actual collection is only
the first step of a much more involved process. Typically we want to
post process data using more advanced data mining tools (such as data
stacking), or export the data to other systems. Velociraptor usually
is only a part of a wider solution which might include a SIEM and SOC
integration.

In order to facilitate interoperability with other tools, Velociraptor
offers an external API. The API is offered via gRPC so it can be used
in any language which gRPC supports (e.g. Java, C++, Python etc). In
this document we illustrate the Python API but any language should
work in a similar way (consult the gRPC documentation for your
language).


## The Velociraptor API Server

The API server exposes an endpoint ready to accept gRPC
connections. By default the API server listen only on the loopback
interface (127.0.0.1) but it is easy to change to be externally
accessible if you need by changing the `server.config.yaml` file:

```
  API:
    bind_address: 127.0.0.1
    bind_port: 8001
```

Client programs simply connect directly to this API and call gRPC
methods on it.

![Image](../api_diagram.png)

The connection is encrypted using TLS and authenticated using mutual
certificates. When we initially created the Velociraptor configuration
file, we created a CA certificate and embedded it in the
`server.config.yaml` file. It is this CA certificate which is used to
verify that the certificate each end presents was issued by the
Velociraptor CA.

{{% notice tip %}}
  If you need to have extra security in your environment you should
  keep the original `server.config.yaml` file generated in an offline
  location, then deploy a redacted file (without the CA.private_key
  value) on the server. This way api client certificates can only be
  issued offline.
{{% /notice %}}

Before the client may connect to the API server they must have a
certificate issued by the Velociraptor CA. This is easy to generate:

```
   $ velociraptor --config server.config.yaml \
        config api_client --name Fred > api_client.yaml
```

Will generate something like:

```
   ca_certificate: |
     -----BEGIN CERTIFICATE-----
     MIIDITCCAgmgAwIBAgIRAI1oswXLBFqWVSYZx1VibMkwDQYJKoZIhvcNAQELBQAw
     -----END CERTIFICATE-----
   client_cert: |
     -----BEGIN CERTIFICATE-----
     2e1ftQuzHGD2XPquqfuVzL1rtEIA1tiC82L6smYbeOe0p4pqpsHN1sEDkdfhBA==
     -----END CERTIFICATE-----
   client_private_key: |
     -----BEGIN RSA PRIVATE KEY-----
     sVr9HvR2kBzM/3yVwvb752h0qDOYDfzLRENjA7dySeOgLtBSvd2gRg==
     -----END RSA PRIVATE KEY-----
   api_connection_string: 127.0.0.1:8001
   name: Fred
```

The certificate generated has a common name as specified by the
`--name` flag. This name will be logged in the server's audit logs so
you can use this to keep track of which programs have access. This
file keeps both private key and certificate as well as the CA
certificate which must be used to authenticate the server in a single
file for convenience.

### Using the API from Python

Although the API exposes a bunch of functions used by the GUI, the
main function (which is not exposed through the GUI) is the `Query()`
method. This function simply executes one or more VQL queries, and
streams their results back to the caller.

The function requires an argument which is a protobuf of type
VQLCollectorArgs:

```
   VQLCollectorArgs:
        env:  list of VQLEnv(string key, string value)
        Query: list of VQLRequest(string Name, string VQL)
        max_row: int
        max_wait: int
        ops_per_second: float
```

This very simple structure allows the caller to specify one or more
VQL queries to run. The call can set up environment variables prior to
the query execution. The max_row and max_wait parameters indicate how
many rows to return in a single result set and how long to wait for
additional rows before returning a result set.

The call simply executes the VQL queries and returns result sets as
VQLResponse protobufs:

```
   VQLResponse:
      Response: json encoded string
      Columns: list of string
      total_rows: total number of rows in this packet
```

The VQL query may return many responses - each represents a set of
rows. These responses may be returned over a long time, the API call
will simply wait until new responses are available. For example, the
VQL may represent an event query - i.e. watch for the occurrence of
some event in the system - in this case it will never actually
terminate, but keep streaming response packets.

### How does this look like in code?

All the files needed for python integration can be found in the
`bindings/python` directory of the [source distribution](https://github.com/Velocidex/velociraptor/tree/master/bindings/python):

* The `requirements.txt` file can be used to install exactly the right
  version of dependencies (We recommend using a virtual env for
  python):

```
$ pip install -r requirements.txt
```

* The `api.proto` file specifies the exact protobufs required to
  connect to the API. There is no need to compile the file with the
  protobuf compiler - simply use the pre-compiled python files
  `api_pb2_grpc.py` and `api_pb2.py` by copying them into your
  project.

* The file `client_example.py` is a fully working client example. You
  can use this example to connect with the server and run any VQL
  queries.

### Code walk through

The following will cover an example implementation in python. The
first step is to prepare credentials for making the gRPC call. We
parse the `api_client.yaml` file and prepare a credential object:

```python
   config = yaml.load(open("api_client.yaml").read())
   creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"))

   options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)
```

Next we connect the channel to the API server:

```python
    with grpc.secure_channel(config["api_connection_string"],
                             creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)
```

The stub is the object we use to make calls with. We can then issue
our call:

```python
   request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(
                VQL=query,
            )])

   for response in stub.Query(request):
       rows = json.loads(response.Response)
       for row in rows:
           print(row)
```

We issue the query and then just wait for the call to generate
response packets. Each packet may contain several rows which will all
be encoded as JSON in the Response field. Each row is simply a dict
with keys being the column names, and the values being possibly nested
dicts or simple data depending on the query.


### What can we do with this?

The Velociraptor API is deliberately open ended - meaning we do not
pose any limitations on what can be done with it. It is conceptually a
very simple API - just issue the query and look at the results,
however this makes it extremely powerful.

We already have a number of very useful server side VQL plugins you
can use. We also plan to add a number of other plugins in future -
this means that the Velociraptor API can easily be extended in a
backwards compatible way by simply adding new VQL plugins. New queries
can do more, without breaking existing queries.
