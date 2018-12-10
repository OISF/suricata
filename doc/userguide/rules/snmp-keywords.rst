SNMP keywords
=============

snmp_version
------------

SNMP protocol version (integer). Expected values are 1, 2 (for version 2c) or 3.

Syntax::

 snmp_version:[op]<number>

The version can be matched exactly, or compared using the _op_ setting::

 snmp_version:3    # exactly 3
 snmp_version:<3   # smaller than 3
 snmp_version:>=2  # greater or equal than 2

Signature example::

 alert snmp any any -> any any (msg:"old SNMP version (<3)"; snmp_version:<3; sid:1; rev:1;)

