#!/usr/bin/python3

import argparse
import os
import yaml

parser = argparse.ArgumentParser(description='Generate artifact documentation.')
parser.add_argument('--config', help='config file.')

parser.add_argument('definition_path', metavar='N', type=str, nargs='+',
                    help='directories containing definitions.')



def load_artifacts(paths):
    result = dict()

    for path in paths:
        for root, dirs, files in os.walk(path):
            for name in files:
                if not name.endswith(".yaml"):
                    continue

                with open(os.path.join(root, name), "r") as fd:
                    raw_data = fd.read()
                    data = yaml.safe_load(raw_data)
                    data['raw'] = raw_data
                    result[data['name']] = data

    return result

def output_artifacts(fd, prefix):
    for name in sorted(artifacts):
        if not name.startswith(prefix):
            continue

        data = artifacts.pop(name)
        id = name.replace(".", "_")

        heading = name
        fd.write ("## " + heading + "\n\n")
        fd.write (data.get("description") + "\n")

        parameters = data.get("parameters",[])
        if len(parameters) > 0:
            fd.write("\nArg|Default|Description\n---|------|-----------\n")

            for parameter in parameters:
                fd.write("%s|%s|%s\n" % (
                    parameter["name"],
                    str(parameter.get("default", "")).encode("unicode_escape").decode("utf8"),
                    parameter.get("description", "").encode("unicode_escape").decode("utf8")))


        fd.write ("""
{{% expand  "View Artifact Source" %}}

""")
        fd.write ("\n```\n")

        for line in data['raw'].splitlines():
            fd.write (line + "\n")
        fd.write ("```\n   {{% /expand }}\n\n")


if __name__ == "__main__" :
    args = parser.parse_args()

    artifacts = load_artifacts(args.definition_path)

    config = yaml.safe_load(open(args.config).read())
    for filename, file_config in config.items():
        prefix = file_config.pop("prefix")
        if not isinstance(prefix, list):
            prefix = [prefix]

        with open(filename, "w") as fd:
            fd.write("---\n%s\n---\n" % yaml.dump(file_config))
            for prefix_item in prefix:
                output_artifacts(fd, prefix_item)


    if len(artifacts) > 0:
        print("Not all artifacts were classified!")
        for name in artifacts:
            print (name)
