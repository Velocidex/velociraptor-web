#!/usr/bin/python3

import argparse
import os
import re
import requests
import yaml

parser = argparse.ArgumentParser(description='Convert a medium post.')
parser.add_argument('markdown_file', type=str,
                    help='Obtained by mediumexporter .')

def download(match):
    url = match.group(1)

    if "medium" not in url or not (
            url.endswith("png")
            or url.endswith("jpeg")
            or url.endswith("jpg")):
        return "(" + url + ")"

    filename = os.path.basename(url).replace("*","")
    print("Downloading %s into %s" % (url, filename))

    myfile = requests.get(url)
    open("img/"+filename, 'wb').write(myfile.content)

    result = "../img/" + filename
    return "(" + result + ")"

def process(markdown_file):
    data = open(markdown_file).read()
    data = re.sub(r'\((https://[^\)]+)\)', download, data)
    with open(markdown_file, "w") as fd:
        fd.write(data)

if __name__ == "__main__" :
    args = parser.parse_args()
    process(args.markdown_file)
