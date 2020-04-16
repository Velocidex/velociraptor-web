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
    caption = match.group(1) or ""
    url = match.group(2)

    filename = os.path.basename(url).replace("*","")
    print("Downloading %s into %s" % (url, filename))

    myfile = requests.get(url)
    open("img/"+filename, 'wb').write(myfile.content)

    result = "../img/" + filename

    return "![%s](%s)" % (caption,  result)

def process(markdown_file):
    data = open(markdown_file).read()
    data = re.sub(r'^!\[(.*?)\]\((https://[^\)]+)\)$', download, data, flags=re.S | re.M)

    with open(markdown_file, "w") as fd:
        fd.write(data)

if __name__ == "__main__" :
    args = parser.parse_args()
    process(args.markdown_file)
