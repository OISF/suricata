#! /usr/bin/env bash

repo=${repo:-"https://github.com/OISF/suricata-update"}
branch=${branch:-"master"}

url="${repo}/archive/${branch}.tar.gz"

echo "Bundling ${url}."

curl -o - -L "${repo}/archive/${branch}.tar.gz" | tar zxf - --strip-components=1
