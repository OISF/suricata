#!/usr/bin/python
# Copyright (C) 2013-2014 ANSSI
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
# THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# author: Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>

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
    # fixes
    rfc = fields[12]
    if not is_number(rfc):
        rfc = 0
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
        rfc, fields[13], fields[14], fields[15].rstrip(),
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
