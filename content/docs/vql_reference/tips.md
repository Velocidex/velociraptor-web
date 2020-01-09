---
title: Artifact Tips
weight: 160
---

When writing a new artifact it helps to use the following tips to make
it easier.

## Develop artifacts locally

Although the Velociraptor GUI allows to change the artifact, and
collect it from remote machines this is tedious in general. It is
easier to just develop and collect the artifact locally.

Simply create a directory where you store your custom artifact, and
run the artifact collector with that directory specified.

```
$ mkdir /tmp/my_artifacts/
$ vi /tmp/my_artifacts/my_new_artifact.yaml
....
$ velociraptor --definitions /tmp/my_artifacts artifacts collect -v My.New.Artifact.Name
```

Note the `-v` flag which emits verbose messages to the console. If you
have VQL syntax errors or any issues you will be able to see that
easily, edit the artifact source and re-collect it.

## Place complex filters as column specs.

In VQL you can put complex expressions in the WHERE clause in order to
filter the result set. The trouble is that you can not actually see
the results of the expression - the expression is simply evaluated for
a boolean true/false.

It is more productive to place the complex expression in the column
specification and then you can see what it evaluates to for each row.

```
SELECT encode(string=Data.value, type="hex") AS Value FROM .....
WHERE Value =~ "ffffff7f$"
```
