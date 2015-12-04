#! /usr/bin/env python

import sys
import re
import urlparse
import os.path
import urllib2
from StringIO import StringIO

import requests

def fetch_images(url, dest):

    print("Parsing image URLs from %s." % (url))
    urlparts = urlparse.urlparse(url)
    r = requests.get(url)
    for m in re.finditer(r"(/attachments/[^\s]+\.png)\"", r.text):
        filename = os.path.basename(m.group(1))
        image_url = "%s://%s%s" % (
            urlparts.scheme, urlparts.netloc, m.group(1))

        if not os.path.exists(dest):
            os.makedirs(dest)

        if os.path.exists("%s/%s" % (dest, filename)):
            print("Image %s already exists." % (filename))
            continue

        print("Fetching image %s." % (image_url))

        open(os.path.join(dest, filename), "w").write(
            urllib2.urlopen(image_url).read())

def main():

    url = sys.argv[1]
    output = sys.argv[2]

    fetch_images(url, output)

    print("Fetching %s." % (url))
    r = requests.get("%s.json" % url)
    text = r.json()["wiki_page"]["text"]
    text = text.replace("\r", "")

    inpre = False

    with open("%s.rst" % output, "w") as fileobj:
        for line in StringIO(text):

            if line.startswith("<pre>"):
                inpre = True
                line = line.replace("<pre>", "\n::\n\n  ")
                if line.find("</pre>") > -1:
                    print("Removing </pre> from end of line.")
                    line = line.replace("</pre>", "")
                    inpre = False

            if line.startswith("</pre>"):
                inpre = False
                line = ""

            if inpre and line:
                line = "  %s" % line

            # Images.
            line = re.sub(
                r"!([^\s]+)!", r"\n.. image:: %s/\1" % output, line)

            # h1.
            if line.startswith("h1."):
                line = re.sub("^h1\.\s+", "", line)
                line += "=" * (len(line) - 1) + "\n"

            # h2.
            if line.startswith("h2."):
                line = re.sub("^h2\.\s+", "", line)
                line += "-" * (len(line) - 1) + "\n"

            # h3.
            if line.startswith("h3."):
                line = re.sub("^h3\.\s+", "", line)
                line += "~" * (len(line) - 1) + "\n"

            # *bold* -> **bold**
            line = re.sub(r"(^|\s)\*([\w:]+)\*", r"\1**\2**", line)

            # _italic_ -> *italic*
            line = re.sub(r"\s_(\w+)_\s", r" *\1* ", line)

            fileobj.write(line.encode("utf-8"))

if __name__ == "__main__":
    sys.exit(main())
