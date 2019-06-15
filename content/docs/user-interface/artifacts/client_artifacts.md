---
title: Client Artifacts
weight: 10
---

Now that we understand what artifacts actually are, we are ready to
collect artifacts from our endpoints. We will first discuss how to
collect an artifact from a single endpoint, and later discuss how to
hunt for the artifacts across the entire fleet.

Once we searched and selected the endpoint of interest, we can switch
to the "Collected Artifacts" view.

![The Collected Artifacts view](../collected_artifacts.png)

The screen shows the artifacts previously collected on this
endpoint. The screen is split into a top table showing a list of
collected artifacts, and a bottom overview pane showing details about
each selected artifact in the table above.

The artifacts list table shows an overview of previously collected
artifacts on this endpoint. Each artifact collection operation is
termed a `flow` in Velociraptor. It has the following columns:

1. The state of the flow. This can be a tick for completed flows, a
   clock for pending artifacts or a nuke for artifacts which were
   collected with critical errors (Artifacts may also have non
   critical errors so you need to check the logs as well).

2. The `FlowId` is a unique internal ID given to each flow
   Velociraptor runs. You will need this ID if you need to compose VQL
   quries for post processing the flow.

3. The `Artifacts Collected` column is a list of artifacts collected
   by this flow. It is possible to schedule multiple artifacts to be
   collected at the same time. This column shows each artifact by
   name.

4. The `Creation Date` is when the artifact was created. The endpoint
   may not have been online at the time, so it is possible that the
   endpoint did not receive the collection request immediately when it
   was created.

5. The `Last Active` date is when the last response arrived from the
   endpoint relating to this flow. The difference between this time
   and the creation time gives us an idea of how long the artifacts
   actually took to be collected on the endpoint.

6. Finally we learn the user that created the collection. If this
   column contains a hunt id (of the form `H.XXXX`) then this flow was
   automatically created by the hunt manager.

## The artifact details pane

The bottom pane allows us to inspect the flow and the collected
artifacts. It consists of several tabs, the first of which `Artifact
Collection` tab gives high level overview of the flow. We can see how
many files were uploaded, what artifacts were collected and any
specific artifact parameters that were issued.

In particular that tab also offers a `Download Results`
button. Clicking this button will create a zip file containing all
relevant information obtained from this artifact. Specifically it
contains a CSV file for each returned VQL query, as well as any file
uploaded by the artifact.

The `Uploaded Files` tab shows the files uploaded by the artifact's
VQL. Some artifact as simply file collectors - collecting a bunch of
files for later post processing analysis.

The `Results` tab shows a table of VQL results from each source. For
artifacts containing multiple sources (or if you collected multiple
artifacts) the selector allows switching between them to view the
result table from each. Since an artifact `source` is simply a VQL
query, it returns a table with columns specified by the query
itself. Therefore each artifact will procude a different table.

The `Logs` tab shows any messages logged by the endpoint while
collecting the artifact. Many issues encounted by the endpoint are not
considered fatal, but are nevertheless logged to the server (for
example, if the endpoint attempts to open a file which is locked). You
should look at the tab to assess if you are getting a complete result.

Finally the `Reports` tab shows the artifact's report. As described
above, the report is a human readable document explaining the results
of the artifact and performing some post processing.

## Collecting an artifact from an endpoint.

We have seen how to examine older artifacts collected from the
endpoint, how do we collect newer artifacts?

Clicking the plus button on the toolbar (`Collect More Artifacts`)
presents the artifacts collection UI.

![The collect new artifacts UI](../collect_artifacts_ui.png)

The UI element presents a search box for finding the desired
artifacts. Velociraptor will search for the keywords in the artifact's
description field. A list of matching artifact names is presented
below the search box. Clicking on each of these artifacts presents a
summary of the artifact on the right hand side. The summary includes
the description as well as the parameters the artifact takes and the
VQL queries that will be run. The artifact can now be added to the
selected artifacts box.

You can set the `Ops/Sec` value for collecting the artifacts. This
setting controls how aggressively the endpoint will collect the
artifact. For artifacts that collect a lot of files or otherwise
utilize heavy resources on the endpoint, it is advisable to lower this
to reduce endpoint load.
