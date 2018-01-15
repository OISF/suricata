#!/usr/bin/python
# Copyright (C) 2017-2018 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# author: Pierre Chifflier <chifflier@wzdftpd.net>

import sys

TABLE_NAME = "tls_ciphersuites"

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

def handle_line(line):
    #print line
    fields = line.split(':')
    print """
  - cipher: %s
    cs: 0x%s
    name: %s
    openssl-name: %s
    kx: %s
    au: %s
    enc: %s
    enc-mode: %s
    enc-size: %s
    mac: %s
    mac-size: %s
    prf: %s
    prf-size: %s
    rfc: %s
    export: %s
    minversion: 0x%s
    maxversion: 0x%s""" % (fields[1],
        fields[0], fields[1],
        fields[2] or "NULL",
        fields[3],
        fields[4], fields[5],
        fields[6] or "NULL",
        fields[7],
        fields[8], fields[9], fields[10], fields[11],
        fields[12], fields[13], fields[14], fields[15].rstrip(),
        )

# print header
print """
%YAML 1.1
---

tls-ciphersuites:"""

for line in sys.stdin:
    try:
        handle_line(line)
    except Exception,e:
        print e
        print line
        raise

print ""
