---
title: Artifact Reference
weight: 50
---


Velociraptor uses VQL for many different purposes. Since Artifacts are
a nice way to package VQL queries, there are a number of different
types of artifacts. This page documents some of the more common
artifact types and where they are used.


## Client Artifacts

Client artifacts encapsulate VQL queries that run on the client. The
artifact contains a number of `Sources` - each extracting a single
table of data.

Client artifacts are collected from the each client at a time, or
using a hunt, collected from a number of clients at the same time.

## Server Artifacts

Velociraptor can also run VQL queries within the server process
itself. When running in the server, there are [a number of plugins
available](../../artifacts/server/) providing access to hunts, flows
and their results.

Therefore server artifacts are useful for post processing the raw data
collected from client artifacts.
