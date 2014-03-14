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

import urllib2
from BeautifulSoup import BeautifulSoup, ResultSet
file = urllib2.urlopen('http://www.iana.org/assignments/tls-parameters/tls-parameters.xml')
data = file.read()
with open('tls-parameters.xml', 'wb') as myFile:
    myFile.write(data)
file.close()

dom = BeautifulSoup(data)

#ciphersuites=dom.findAll ("registry")[4]
ciphersuites=dom.findAll (id="tls-parameters-4")
if isinstance(ciphersuites,ResultSet):
    ciphersuites = ciphersuites.pop()

openssl_names = {
  "0001" : "NULL-MD5",
  "0002" : "NULL-SHA",
  "0003" : "EXP-RC4-MD5",
  "0004" : "RC4-MD5",
  "0005" : "RC4-SHA",
  "0006" : "EXP-RC2-CBC-MD5",
  "0008" : "EXP-DES-CBC-SHA",
  "0009" : "DES-CBC-SHA",
  "000a" : "DES-CBC3-SHA",
  "0011" : "EXP-EDH-DSS-DES-CBC-SHA",
  "0012" : "EDH-DSS-DES-CBC-SHA",
  "0013" : "EDH-DSS-DES-CBC3-SHA",
  "0014" : "EXP-EDH-RSA-DES-CBC-SHA",
  "0015" : "EDH-RSA-DES-CBC-SHA",
  "0016" : "EDH-RSA-DES-CBC3-SHA",
  "0017" : "EXP-ADH-RC4-MD5",
  "0018" : "ADH-RC4-MD5",
  "0019" : "EXP-ADH-DES-CBC-SHA",
  "001a" : "ADH-DES-CBC-SHA",
  "001b" : "ADH-DES-CBC3-SHA",
  "002f" : "AES128-SHA",
  "0032" : "DHE-DSS-AES128-SHA",
  "0033" : "DHE-RSA-AES128-SHA",
  "0034" : "ADH-AES128-SHA",
  "0035" : "AES256-SHA",
  "0038" : "DHE-DSS-AES256-SHA",
  "0039" : "DHE-RSA-AES256-SHA",
  "003a" : "ADH-AES256-SHA",
  "003b" : "NULL-SHA256",
  "003c" : "AES128-SHA256",
  "003d" : "AES256-SHA256",
  "0040" : "DHE-DSS-AES128-SHA256",
  "0041" : "CAMELLIA128-SHA",
  "0044" : "DHE-DSS-CAMELLIA128-SHA",
  "0045" : "DHE-RSA-CAMELLIA128-SHA",
  "0046" : "ADH-CAMELLIA128-SHA",
  "0067" : "DHE-RSA-AES128-SHA256",
  "006a" : "DHE-DSS-AES256-SHA256",
  "006b" : "DHE-RSA-AES256-SHA256",
  "006c" : "ADH-AES128-SHA256",
  "006d" : "ADH-AES256-SHA256",
  "0084" : "CAMELLIA256-SHA",
  "0087" : "DHE-DSS-CAMELLIA256-SHA",
  "0088" : "DHE-RSA-CAMELLIA256-SHA",
  "0089" : "ADH-CAMELLIA256-SHA",
  "008a" : "PSK-RC4-SHA",
  "008b" : "PSK-3DES-EDE-CBC-SHA",
  "008c" : "PSK-AES128-CBC-SHA",
  "008d" : "PSK-AES256-CBC-SHA",
  "0096" : "SEED-SHA",
  "0099" : "DHE-DSS-SEED-SHA",
  "009a" : "DHE-RSA-SEED-SHA",
  "009b" : "ADH-SEED-SHA",
  "009c" : "AES128-GCM-SHA256",
  "009d" : "AES256-GCM-SHA384",
  "009e" : "DHE-RSA-AES128-GCM-SHA256",
  "009f" : "DHE-RSA-AES256-GCM-SHA384",
  "00a2" : "DHE-DSS-AES128-GCM-SHA256",
  "00a3" : "DHE-DSS-AES256-GCM-SHA384",
  "00a6" : "ADH-AES128-GCM-SHA256",
  "00a7" : "ADH-AES256-GCM-SHA384",
  "c001" : "ECDH-ECDSA-NULL-SHA",
  "c002" : "ECDH-ECDSA-RC4-SHA",
  "c003" : "ECDH-ECDSA-DES-CBC3-SHA",
  "c004" : "ECDH-ECDSA-AES128-SHA",
  "c005" : "ECDH-ECDSA-AES256-SHA",
  "c006" : "ECDHE-ECDSA-NULL-SHA",
  "c007" : "ECDHE-ECDSA-RC4-SHA",
  "c008" : "ECDHE-ECDSA-DES-CBC3-SHA",
  "c009" : "ECDHE-ECDSA-AES128-SHA",
  "c00a" : "ECDHE-ECDSA-AES256-SHA",
  "c00b" : "ECDH-RSA-NULL-SHA",
  "c00c" : "ECDH-RSA-RC4-SHA",
  "c00d" : "ECDH-RSA-DES-CBC3-SHA",
  "c00e" : "ECDH-RSA-AES128-SHA",
  "c00f" : "ECDH-RSA-AES256-SHA",
  "c010" : "ECDHE-RSA-NULL-SHA",
  "c011" : "ECDHE-RSA-RC4-SHA",
  "c012" : "ECDHE-RSA-DES-CBC3-SHA",
  "c013" : "ECDHE-RSA-AES128-SHA",
  "c014" : "ECDHE-RSA-AES256-SHA",
  "c015" : "AECDH-NULL-SHA",
  "c016" : "AECDH-RC4-SHA",
  "c017" : "AECDH-DES-CBC3-SHA",
  "c018" : "AECDH-AES128-SHA",
  "c019" : "AECDH-AES256-SHA",
  "c01a" : "SRP-3DES-EDE-CBC-SHA",
  "c01b" : "SRP-RSA-3DES-EDE-CBC-SHA",
  "c01c" : "SRP-DSS-3DES-EDE-CBC-SHA",
  "c01d" : "SRP-AES-128-CBC-SHA",
  "c01e" : "SRP-RSA-AES-128-CBC-SHA",
  "c01f" : "SRP-DSS-AES-128-CBC-SHA",
  "c020" : "SRP-AES-256-CBC-SHA",
  "c021" : "SRP-RSA-AES-256-CBC-SHA",
  "c022" : "SRP-DSS-AES-256-CBC-SHA",
  "c023" : "ECDHE-ECDSA-AES128-SHA256",
  "c024" : "ECDHE-ECDSA-AES256-SHA384",
  "c025" : "ECDH-ECDSA-AES128-SHA256",
  "c026" : "ECDH-ECDSA-AES256-SHA384",
  "c027" : "ECDHE-RSA-AES128-SHA256",
  "c028" : "ECDHE-RSA-AES256-SHA384",
  "c029" : "ECDH-RSA-AES128-SHA256",
  "c02a" : "ECDH-RSA-AES256-SHA384",
  "c02b" : "ECDHE-ECDSA-AES128-GCM-SHA256",
  "c02c" : "ECDHE-ECDSA-AES256-GCM-SHA384",
  "c02d" : "ECDH-ECDSA-AES128-GCM-SHA256",
  "c02e" : "ECDH-ECDSA-AES256-GCM-SHA384",
  "c02f" : "ECDHE-RSA-AES128-GCM-SHA256",
  "c030" : "ECDHE-RSA-AES256-GCM-SHA384",
  "c031" : "ECDH-RSA-AES128-GCM-SHA256",
  "c032" : "ECDH-RSA-AES256-GCM-SHA384"
}

def get_openssl_name (n):
  if n in openssl_names:
    return openssl_names[n]
  else:
    return ""

for i in ciphersuites.findAll ("record"):
  value = "".join(i.value.contents)
  desc = "".join (i.description.contents)
  
  ignore_keywords = [
          "Unassigned",
          "Reserved",
          ]
  f = filter(desc.startswith,ignore_keywords)
  
  if len(f) > 0:
    continue
  
  if desc == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV":
    continue
  
  rfc = "NONE"
  if i.xref:
    rfc_tmp = filter (lambda (var,val) : var == "data", i.xref.attrs)
    if len (rfc_tmp) > 0:
      rfc = rfc_tmp[0][1][3:7]

  real_value = "".join (map (lambda x : "%2.2x" % (int (x, 16)), value.split (",")))

  minver = 0x0300
  maxver = 0xffff
  
  (_kxau, encmac) = desc.split("_WITH_")
  kxau = _kxau.split ("_")[1:]
  export = 0
  if kxau[-1] == "EXPORT":
    export = 1
    maxver = 0x302
    kxau = kxau[:-1]
  if len (kxau) == 1:
    kx = kxau[0]
    au = kxau[0]
  elif kxau[0] == "SRP":
    kx = "_".join (kxau[0:1])
    au = kx
    if len (kxau) > 2:
      au += "+" + "_".join (kxau[2:])
  else:
    kx, au = kxau
  if au == "anon":
    au = "NULL"
  
  _encmac = encmac.split ("_")
  hashfun = _encmac [-1]
  _encstr = "_".join (_encmac [:-1])
  _enc = _encmac [:-1] 
 
  if _encstr == "DES40_CBC":
    enc = "DES"
    encmode = "CBC"
    encsize = 40
  elif len (_enc) == 3 and _enc[1] == "CBC" and _enc[2] == "40":
    enc = _enc[0]
    encmode = "CBC"
    encsize = 40
  elif _encstr == "DES_CBC":
    enc = "DES"
    encmode = "CBC"
    encsize = 56
  elif _encstr == "IDEA_CBC":
    enc = "IDEA"
    encmode = "CBC"
    encsize = 128
  elif _encstr == "3DES_EDE_CBC":
    enc = "3DES"
    encmode = "CBC"
    encsize = 168
  elif _encstr == "NULL":
    enc = "NULL"
    encmode = ""
    encsize = 0
  elif _encstr == "SEED_CBC":
    enc = "SEED"
    encmode = "CBC"
    encsize = 128
  elif len (_enc) == 2:
    enc = _enc[0]
    encmode = ""
    encsize = int (_enc[1])
  else:
    enc = _enc[0]
    encmode = _enc[2]
    encsize = int (_enc[1])

  prf = "DEFAULT"
  prfsize = 0

  # fix crap from recent changes
  if hashfun == "8":
    hashfun = "_".join([encmode,hashfun])
    encmode = ""
  
  if hashfun == "NULL":
    mac = "NULL"
    macsize = 0
  elif hashfun == "MD5":
    mac = "HMAC-MD5"
    macsize = 128
  elif hashfun == "SHA":
    mac = "HMAC-SHA1"
    macsize = 160
  elif hashfun == "SHA256":
    mac = "HMAC-SHA256"
    macsize = 256
    prf = "SHA256"
    prfsize = 256
    minver = 0x303
  elif hashfun == "SHA384":
    mac = "HMAC-SHA384"
    macsize = 384
    prf = "SHA384"
    prfsize = 384
    minver = 0x303
  elif hashfun == "CCM":
    #print encmode
    #mac = "CCM"
    #macsize = 0
    minver = 0x303
    encmode = "CCM"
  elif hashfun == "CCM_8":
    #print encmode
    #mac = "CCM_8"
    #macsize = 0
    minver = 0x303
    encmode = "CCM"
  else:
    print desc
    print encmac
    print hashfun
    raise "Unsupported."
  
  if encmode == "GCM":
    mac = "AEAD"
    macsize = encsize
    minver = 0x303
    
  print "%s:%s:%s:%s:%s:%s:%s:%d:%s:%d:%s:%d:%s:%d:%4.4x:%4.4x" % (real_value, desc, get_openssl_name (real_value), kx, au, enc, encmode, encsize, mac, macsize, prf, prfsize, rfc, export, minver, maxver)
